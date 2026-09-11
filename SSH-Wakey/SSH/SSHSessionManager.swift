import Foundation
import Observation

/// Owns every live SSH session and the state the window displays.
///
/// A "session" here is one `ssh -M -N` master process. It authenticates once
/// and then holds the connection open. Terminal windows attach to it through
/// the control socket, so the password is needed exactly once and is destroyed
/// immediately afterwards.
@MainActor
@Observable
final class SSHSessionManager {

    enum State: Equatable {
        case idle
        case connecting(stage: String)
        case connected(Connected)
        case failed(SSHFailure)

        var isConnecting: Bool { if case .connecting = self { return true }; return false }
        var isConnected: Bool { if case .connected = self { return true }; return false }
    }

    struct Connected: Equatable {
        var since: Date
        /// False when ssh authenticated with a key or agent and never asked
        /// for the password that was typed.
        var usedPassword: Bool
    }

    enum SessionError: LocalizedError {
        case notConnected
        case terminalLaunchFailed(String)

        var errorDescription: String? {
            switch self {
            case .notConnected:
                return "That session is no longer open."
            case .terminalLaunchFailed(let reason):
                return "Terminal could not be opened: \(reason)"
            }
        }
    }

    /// ssh's own TCP connect timeout, in seconds.
    static let connectTimeout = 10
    /// How long the whole attempt, including authentication, may take.
    static let overallTimeout: TimeInterval = 45
    /// A session shorter than this is probably a Mac finishing its FileVault
    /// unlock rather than a session that failed.
    static let unlockHandoffWindow: TimeInterval = 30

    private(set) var states: [UUID: State] = [:]
    /// Set when opening Terminal fails, so the window can show it.
    var lastActionError: String?

    private var sessions: [UUID: Session] = [:]
    private var attempts: [UUID: Task<Void, Never>] = [:]

    private struct Session {
        let process: Process
        let controlPath: String
        let directoryURL: URL
        let connection: SSHConnection
    }

    var activeSessionCount: Int { sessions.count }

    func state(for id: UUID?) -> State {
        guard let id else { return .idle }
        return states[id] ?? .idle
    }

    // MARK: - Connecting

    /// Takes ownership of `password` and wipes it when the attempt ends,
    /// whether it succeeded, failed or was cancelled.
    func connect(_ connection: SSHConnection, password: SecureBuffer) {
        let id = connection.id
        guard attempts[id] == nil, sessions[id] == nil else {
            password.wipe()
            return
        }
        states[id] = .connecting(stage: "Starting ssh…")
        attempts[id] = Task { [weak self] in
            await self?.runAttempt(connection, password: password)
        }
    }

    func cancelConnect(_ id: UUID) {
        attempts[id]?.cancel()
    }

    private func runAttempt(_ connection: SSHConnection, password: SecureBuffer) async {
        let id = connection.id
        defer {
            password.wipe()
            attempts[id] = nil
        }

        let issues = ConnectionValidator.issues(in: connection)
        guard issues.isEmpty else {
            states[id] = .failed(SSHFailure(
                kind: .invalidConnection,
                headline: "This connection is not valid.",
                guidance: issues.map(\.message).joined(separator: " "),
                detail: nil))
            return
        }

        let directory: URL
        let controlPath: String
        do {
            directory = try Self.makeSessionDirectory()
            controlPath = directory.appendingPathComponent("ctl", isDirectory: false).path
        } catch {
            states[id] = .failed(SSHFailure(
                kind: .launchFailed,
                headline: "Could not create a private folder for the session.",
                guidance: error.localizedDescription, detail: nil))
            return
        }

        let channel: AskpassChannel
        let arguments: [String]
        do {
            channel = try AskpassChannel(password: password, helperPath: Self.askpassHelperPath)
            arguments = try SSHCommandBuilder.masterArguments(
                for: connection, controlPath: controlPath, connectTimeout: Self.connectTimeout)
        } catch {
            try? FileManager.default.removeItem(at: directory)
            states[id] = .failed(SSHFailure(
                kind: .launchFailed,
                headline: "ssh could not be started.",
                guidance: error.localizedDescription, detail: nil))
            return
        }
        defer { channel.invalidate() }

        var environment = ProcessRunner.minimalEnvironment()
        environment.merge(channel.environmentAdditions()) { _, new in new }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: SSHCommandBuilder.sshExecutable)
        process.arguments = arguments
        process.environment = environment
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice

        let errorPipe = Pipe()
        process.standardError = errorPipe
        let diagnostics = OutputCollector()
        errorPipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty {
                handle.readabilityHandler = nil
            } else {
                diagnostics.append(data)
            }
        }

        do {
            try process.run()
        } catch {
            errorPipe.fileHandleForReading.readabilityHandler = nil
            try? FileManager.default.removeItem(at: directory)
            states[id] = .failed(SSHFailure(
                kind: .launchFailed,
                headline: "/usr/bin/ssh could not be launched.",
                guidance: error.localizedDescription, detail: nil))
            return
        }

        states[id] = .connecting(stage: "Authenticating…")
        let deadline = Date().addingTimeInterval(Self.overallTimeout)
        var outcome: AttemptOutcome = .stillWaiting

        while outcome == .stillWaiting {
            if Task.isCancelled {
                outcome = .cancelled
                break
            }
            // ssh creates the control socket only once the connection is
            // authenticated, so its appearance is the success signal.
            if FileManager.default.fileExists(atPath: controlPath) {
                outcome = .authenticated
                break
            }
            if !process.isRunning {
                outcome = .exited
                break
            }
            if Date() >= deadline {
                outcome = .timedOut
                break
            }
            try? await Task.sleep(nanoseconds: 150_000_000)
        }

        switch outcome {
        case .stillWaiting, .authenticated:
            break
        case .cancelled:
            terminate(process)
            errorPipe.fileHandleForReading.readabilityHandler = nil
            try? FileManager.default.removeItem(at: directory)
            states[id] = .failed(SSHFailure(
                kind: .cancelled,
                headline: "Connection cancelled.",
                guidance: "Nothing was left running and the password was discarded.", detail: nil))
            return
        case .timedOut:
            terminate(process)
            errorPipe.fileHandleForReading.readabilityHandler = nil
            try? FileManager.default.removeItem(at: directory)
            var failure = SSHOutputClassifier.classify(exitCode: -1, standardError: diagnostics.text)
            if failure.kind == .unknown {
                failure = SSHFailure(
                    kind: .timeout,
                    headline: "The connection timed out.",
                    guidance: "ssh did not finish authenticating within \(Int(Self.overallTimeout)) seconds.",
                    detail: diagnostics.text.isEmpty ? nil : diagnostics.text)
            }
            states[id] = .failed(Self.annotated(failure, with: channel.outcome, host: connection.host))
            return
        case .exited:
            // Give the reader a moment to drain the last of stderr.
            try? await Task.sleep(nanoseconds: 200_000_000)
            errorPipe.fileHandleForReading.readabilityHandler = nil
            try? FileManager.default.removeItem(at: directory)

            let outcome = channel.outcome
            var failure = SSHOutputClassifier.classify(
                exitCode: process.terminationStatus, standardError: diagnostics.text)
            if !outcome.served, !outcome.refusedPrompts.isEmpty, failure.kind == .unknown {
                failure.kind = .askpassRefused
                failure.headline = "ssh asked for something other than a password."
            }
            states[id] = .failed(Self.annotated(failure, with: outcome, host: connection.host))
            return
        }

        // Authenticated. Confirm the master really is answering before
        // promising the user a usable session.
        states[id] = .connecting(stage: "Verifying session…")
        let check = try? await ProcessRunner.run(
            executable: SSHCommandBuilder.sshExecutable,
            arguments: SSHCommandBuilder.controlArguments(
                for: connection, controlPath: controlPath, command: "check"),
            timeout: 10)

        guard let check, check.exitCode == 0 else {
            terminate(process)
            errorPipe.fileHandleForReading.readabilityHandler = nil
            try? FileManager.default.removeItem(at: directory)
            states[id] = .failed(SSHFailure(
                kind: .unknown,
                headline: "The session could not be verified.",
                guidance: "ssh authenticated but the control socket did not answer.",
                detail: [diagnostics.text, check?.standardError]
                    .compactMap { $0 }
                    .filter { !$0.isEmpty }
                    .joined(separator: "\n")))
            return
        }

        errorPipe.fileHandleForReading.readabilityHandler = nil
        let usedPassword = channel.outcome.served
        sessions[id] = Session(
            process: process, controlPath: controlPath, directoryURL: directory, connection: connection)
        states[id] = .connected(Connected(since: Date(), usedPassword: usedPassword))

        process.terminationHandler = { [weak self] _ in
            Task { @MainActor [weak self] in self?.masterExited(id) }
        }
        if !process.isRunning { masterExited(id) }
    }

    private enum AttemptOutcome: Equatable {
        case stillWaiting, authenticated, exited, timedOut, cancelled
    }

    // MARK: - Live sessions

    func disconnect(_ id: UUID) {
        guard let session = sessions.removeValue(forKey: id) else { return }
        states[id] = .idle
        terminate(session.process)
        try? FileManager.default.removeItem(at: session.directoryURL)
    }

    func disconnectAll() {
        for id in sessions.keys { disconnect(id) }
    }

    /// Hands the already-authenticated session to Terminal. No password is
    /// involved: the new ssh client attaches to the existing master.
    func openInTerminal(_ id: UUID) {
        guard let session = sessions[id],
              FileManager.default.fileExists(atPath: session.controlPath) else {
            lastActionError = SessionError.notConnected.localizedDescription
            return
        }
        do {
            try TerminalHandoff.open(
                connection: session.connection,
                controlPath: session.controlPath,
                in: session.directoryURL)
            lastActionError = nil
        } catch {
            lastActionError = error.localizedDescription
        }
    }

    /// A session that ends on its own, rather than because Disconnect was
    /// pressed. Worth distinguishing, because a very short one is what a Mac
    /// unlocking its data volume looks like.
    private func masterExited(_ id: UUID) {
        guard let session = sessions[id] else { return }
        sessions.removeValue(forKey: id)
        try? FileManager.default.removeItem(at: session.directoryURL)
        guard case .connected(let info) = states[id] else { return }

        let lifetime = Date().timeIntervalSince(info.since)
        var guidance = "The connection closed on its own, rather than from Disconnect."
        if lifetime < Self.unlockHandoffWindow {
            guidance = "The connection closed after \(Int(lifetime.rounded())) seconds."
                + "\n\nIf that Mac was waiting at the FileVault "
                + "unlock screen, this is what success looks like: macOS closes the connection "
                + "while it mounts the data volume and starts the rest of the system. Give it a "
                + "few seconds and connect again for a normal session."
        }
        states[id] = .failed(SSHFailure(
            kind: .closedByRemote, headline: "The session ended.", guidance: guidance, detail: nil))
    }

    private func terminate(_ process: Process) {
        guard process.isRunning else { return }
        process.terminationHandler = nil
        process.terminate()
        let identifier = process.processIdentifier
        Task.detached {
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            if identifier > 0 { kill(identifier, SIGKILL) }
        }
    }

    // MARK: - Helpers

    /// Adds what the password channel saw to a failure message.
    ///
    /// Most of the time there is nothing to add. When there is, it explains
    /// something the ssh diagnostics alone do not: that a password was asked
    /// for twice, or that a prompt went deliberately unanswered.
    static func annotated(
        _ failure: SSHFailure,
        with outcome: AskpassChannel.Outcome,
        host: String? = nil
    ) -> SSHFailure {
        var failure = failure
        var notes: [String] = []

        // A machine on the local network that cannot be reached at all is the
        // signature of a missing Local Network permission, which looks exactly
        // like the machine being switched off.
        if let host, NetworkScope.isLocal(host),
           SSHFailure.localNetworkSuspects.contains(failure.kind) {
            failure.suggestsLocalNetworkPermission = true
            notes.append("This address is on your own network, and macOS has to give SSH-Wakey "
                + "permission to reach devices there. Without that permission every attempt fails "
                + "exactly like this, whether or not the other machine is running. If the prompt "
                + "was dismissed or refused, open Local Network settings below. If you have just "
                + "allowed it, connect again.")
        }

        if outcome.askedAgainAfterServing > 0 {
            notes.append("ssh asked for the password a second time, for another authentication "
                + "method. One typed password is used once, so that went unanswered rather than "
                + "becoming a silent retry. If the password was right, press Connect and try again.")
        }
        for prompt in outcome.refusedPrompts where !prompt.isEmpty {
            notes.append("This prompt went unanswered because it is not a password prompt: \(prompt)")
        }
        if outcome.wrongNonceAttempts > 0 || outcome.wrongUserAttempts > 0
            || outcome.wrongProgramAttempts > 0 {
            notes.append("Something other than ssh's password helper tried to read the password "
                + "channel, and was refused. That is worth looking into.")
        }
        guard !notes.isEmpty else { return failure }

        var annotated = failure
        annotated.guidance = ([failure.guidance] + notes)
            .compactMap { $0 }
            .filter { !$0.isEmpty }
            .joined(separator: "\n\n")
        return annotated
    }

    /// The executable ssh will run as its askpass helper: this very binary.
    static var askpassHelperPath: String {
        Bundle.main.executablePath ?? CommandLine.arguments.first ?? "/usr/bin/false"
    }

    private static func makeSessionDirectory() throws -> URL {
        let parent = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("SSH-Wakey", isDirectory: true)
        let directory = parent.appendingPathComponent("s-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(
            at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return directory
    }
}

/// Thread-safe accumulator for a pipe that is read on a background queue.
final class OutputCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()

    func append(_ chunk: Data) {
        lock.lock(); data.append(chunk); lock.unlock()
    }

    var text: String {
        lock.lock(); defer { lock.unlock() }
        return String(decoding: data, as: UTF8.self)
    }
}
