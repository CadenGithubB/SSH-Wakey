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
        /// Logged in and then closed, either because that is all that was
        /// asked for or because the far end hung up straight afterwards.
        case unlocked(Unlocked)
        case failed(SSHFailure)

        var isConnecting: Bool { if case .connecting = self { return true }; return false }
        var isConnected: Bool { if case .connected = self { return true }; return false }
    }

    struct Unlocked: Equatable {
        var at: Date
        /// False when a key was accepted and the typed password never used.
        var usedPassword: Bool
        /// True when the machine closed the connection rather than the app.
        var closedByServer: Bool
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

    /// ssh's own TCP connect timeout, in seconds. Long enough that a machine
    /// which has just taken a wake packet can finish bringing sshd up.
    static let connectTimeout = 15
    /// How long the whole attempt, including authentication, may take.
    static let overallTimeout: TimeInterval = 45
    /// A session shorter than this is probably a Mac finishing its FileVault
    /// unlock rather than a session that failed.
    static let unlockHandoffWindow: TimeInterval = 30

    private(set) var states: [UUID: State] = [:]
    /// Set when opening Terminal fails, so the window can show it.
    var lastActionError: String?
    /// Recent attempts, kept so they can be written out when something needs
    /// explaining. Bounded, and gone when the app quits.
    private(set) var diagnostics: [DiagnosticEntry] = []
    /// Called after a successful login with a MAC taken from the ARP table.
    var onLearnedLinkAddress: ((UUID, String) -> Void)?
    /// Shown in the status panel while a wake packet is on the network.
    static let wakingHeadline = "Waking the machine..."
    /// Managed builds never hold a session, even if a caller asks.
    var forcesUnlock: Bool = AppDistribution.isManagedBuild

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
    func connect(_ connection: SSHConnection, password: SecureBuffer, mode: ConnectMode) {
        let resolvedMode = forcesUnlock ? ConnectMode.unlock : mode
        let id = connection.id
        guard attempts[id] == nil, sessions[id] == nil else {
            password.wipe()
            return
        }
        states[id] = .connecting(
            stage: NetworkWake.shouldPoke(
                host: connection.host, hardwareAddress: connection.hardwareAddress)
            ? Self.wakingHeadline
            : "Starting ssh…")
        attempts[id] = Task { [weak self] in
            await self?.runAttempt(connection, password: password, mode: resolvedMode)
        }
    }

    func cancelConnect(_ id: UUID) {
        attempts[id]?.cancel()
    }

    private func runAttempt(
        _ connection: SSHConnection,
        password: SecureBuffer,
        mode: ConnectMode
    ) async {
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

        if NetworkWake.shouldPoke(host: connection.host, hardwareAddress: connection.hardwareAddress) {
            states[id] = .connecting(stage: Self.wakingHeadline)
            await NetworkWake.poke(host: connection.host, hardwareAddress: connection.hardwareAddress)
            if Task.isCancelled {
                try? FileManager.default.removeItem(at: directory)
                states[id] = .failed(Self.cancelledFailure)
                return
            }
            try? await Task.sleep(nanoseconds: NetworkWake.settleNanoseconds)
            if Task.isCancelled {
                try? FileManager.default.removeItem(at: directory)
                states[id] = .failed(Self.cancelledFailure)
                return
            }
        }

        let channel: AskpassChannel
        let arguments: [String]
        do {
            channel = try AskpassChannel(password: password, helperPath: Self.askpassHelperPath)
            switch mode {
            case .unlock:
                arguments = try SSHCommandBuilder.unlockArguments(
                    for: connection, connectTimeout: Self.connectTimeout)
            case .session:
                arguments = try SSHCommandBuilder.masterArguments(
                    for: connection, controlPath: controlPath, connectTimeout: Self.connectTimeout)
            }
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

        var launchesRemaining = NetworkWake.shouldPoke(
            host: connection.host, hardwareAddress: connection.hardwareAddress) ? 2 : 1
        var process = Process()
        var errorPipe = Pipe()
        var diagnostics = OutputCollector()
        var outcome: AttemptOutcome = .stillWaiting

        launch: while true {
            states[id] = .connecting(stage: "Starting ssh…")
            process = Process()
            process.executableURL = URL(fileURLWithPath: SSHCommandBuilder.sshExecutable)
            process.arguments = arguments
            process.environment = environment
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = FileHandle.nullDevice

            errorPipe = Pipe()
            process.standardError = errorPipe
            diagnostics = OutputCollector()
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
            outcome = .stillWaiting

            while outcome == .stillWaiting {
                if Task.isCancelled {
                    outcome = .cancelled
                    break
                }
                if mode == .unlock,
                   SSHOutputClassifier.indicatesAuthenticationSucceeded(diagnostics.text) {
                    outcome = .authenticated
                    break
                }
                if mode == .session, FileManager.default.fileExists(atPath: controlPath) {
                    outcome = .authenticated
                    break
                }
                if !process.isRunning {
                    outcome = SSHOutputClassifier.indicatesAuthenticationSucceeded(diagnostics.text)
                        ? .authenticated : .exited
                    break
                }
                if Date() >= deadline {
                    outcome = .timedOut
                    break
                }
                try? await Task.sleep(nanoseconds: 150_000_000)
            }

            let canRetry = launchesRemaining > 1
                && !channel.outcome.served
                && Self.shouldRetryAfterWake(outcome, output: diagnostics.text)
            launchesRemaining -= 1
            if canRetry {
                terminate(process)
                errorPipe.fileHandleForReading.readabilityHandler = nil
                states[id] = .connecting(stage: Self.wakingHeadline)
                await NetworkWake.poke(
                    host: connection.host, hardwareAddress: connection.hardwareAddress)
                if Task.isCancelled {
                    try? FileManager.default.removeItem(at: directory)
                    record(connection, mode: mode, result: "Cancelled",
                           channel: channel.outcome, output: diagnostics.text)
                    states[id] = .failed(Self.cancelledFailure)
                    return
                }
                try? await Task.sleep(nanoseconds: NetworkWake.settleNanoseconds)
                if Task.isCancelled {
                    try? FileManager.default.removeItem(at: directory)
                    record(connection, mode: mode, result: "Cancelled",
                           channel: channel.outcome, output: diagnostics.text)
                    states[id] = .failed(Self.cancelledFailure)
                    return
                }
                continue launch
            }
            break launch
        }

        switch outcome {
        case .stillWaiting, .authenticated:
            break
        case .cancelled:
            terminate(process)
            errorPipe.fileHandleForReading.readabilityHandler = nil
            try? FileManager.default.removeItem(at: directory)
            record(connection, mode: mode, result: "Cancelled",
                   channel: channel.outcome, output: diagnostics.text)
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
            record(connection, mode: mode, result: failure.headline,
                   channel: channel.outcome, output: diagnostics.text)
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
            record(connection, mode: mode, result: failure.headline,
                   channel: outcome, output: diagnostics.text)
            states[id] = .failed(Self.annotated(failure, with: outcome, host: connection.host))
            return
        }

        // Authenticated.
        let usedPassword = channel.outcome.served

        if mode == .unlock {
            terminate(process)
            errorPipe.fileHandleForReading.readabilityHandler = nil
            try? FileManager.default.removeItem(at: directory)
            record(connection, mode: mode, result: "Logged in, then closed as asked",
                   channel: channel.outcome, output: diagnostics.text)
            rememberLinkAddress(of: connection)
            states[id] = .unlocked(
                Unlocked(at: Date(), usedPassword: usedPassword, closedByServer: false))
            return
        }

        if !process.isRunning {
            // A session was asked for, but the far end hung up right after
            // accepting the password. That is what unlocking a disk looks like,
            // so it is reported as a success rather than a failure.
            errorPipe.fileHandleForReading.readabilityHandler = nil
            try? FileManager.default.removeItem(at: directory)
            record(connection, mode: mode, result: "Logged in, then the machine closed it",
                   channel: channel.outcome, output: diagnostics.text)
            rememberLinkAddress(of: connection)
            states[id] = .unlocked(
                Unlocked(at: Date(), usedPassword: usedPassword, closedByServer: true))
            return
        }

        // Confirm the master really is answering before promising a session.
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

        record(connection, mode: mode, result: "Connected",
               channel: channel.outcome, output: diagnostics.text)
        rememberLinkAddress(of: connection)
        errorPipe.fileHandleForReading.readabilityHandler = nil
        sessions[id] = Session(
            process: process, controlPath: controlPath, directoryURL: directory, connection: connection)
        states[id] = .connected(Connected(since: Date(), usedPassword: usedPassword))

        process.terminationHandler = { [weak self] _ in
            Task { @MainActor [weak self] in self?.masterExited(id) }
        }
        if !process.isRunning { masterExited(id) }
    }

    /// Attempts recorded for one saved connection, newest first.
    func diagnostics(for connectionID: UUID) -> [DiagnosticEntry] {
        DiagnosticsReport.entries(diagnostics, for: connectionID)
    }

    /// Records what happened, for Activity and the diagnostics file.
    private func record(
        _ connection: SSHConnection,
        mode: ConnectMode,
        result: String,
        channel: AskpassChannel.Outcome,
        output: String
    ) {
        diagnostics.append(DiagnosticEntry(
            at: Date(),
            connectionID: connection.id,
            connection: connection.name,
            destination: connection.displayDestination,
            mode: mode.title,
            result: result,
            channel: channel.summary,
            output: output))

        // Drop the oldest attempts for this machine first, then the oldest
        // overall, so one busy host cannot erase every other machine's history.
        let perConnection = DiagnosticsReport.maximumEntriesPerConnection
        while diagnostics.filter({ $0.connectionID == connection.id }).count > perConnection,
              let oldest = diagnostics.firstIndex(where: { $0.connectionID == connection.id }) {
            diagnostics.remove(at: oldest)
        }
        if diagnostics.count > DiagnosticsReport.maximumEntries {
            diagnostics.removeFirst(diagnostics.count - DiagnosticsReport.maximumEntries)
        }
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
        guard !forcesUnlock else {
            lastActionError = "This copy of SSH-Wakey cannot open a session."
            return
        }
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

    static let cancelledFailure = SSHFailure(
        kind: .cancelled,
        headline: "Connection cancelled.",
        guidance: "Nothing was left running and the password was discarded.", detail: nil)

    /// TCP never completed, so a wake poke and a second ssh are worth trying.
    /// Connection refused is not: the machine already answered.
    private static func shouldRetryAfterWake(_ outcome: AttemptOutcome, output: String) -> Bool {
        switch outcome {
        case .timedOut:
            return true
        case .exited:
            let kind = SSHOutputClassifier.classify(exitCode: 255, standardError: output).kind
            return kind == .timeout || kind == .hostUnreachable
        default:
            return false
        }
    }

    private func rememberLinkAddress(of connection: SSHConnection) {
        let id = connection.id
        let host = connection.host
        Task {
            guard let mac = await NetworkWake.learnedAddress(for: host) else { return }
            await MainActor.run { self.onLearnedLinkAddress?(id, mac) }
        }
    }

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

        if outcome.repeatedPrompts > 0 {
            notes.append("ssh asked the same question it had already been answered. That goes "
                + "unanswered, because repeating a password that has just been rejected only "
                + "produces more failed logins.")
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

    static let ownerFileName = "owner"

    /// Shuts down sessions left behind by an app that was killed rather than
    /// quit.
    ///
    /// Quitting disconnects everything. A crash or a Force Quit does not: the
    /// `ssh` master is reparented and carries on holding an authenticated
    /// connection that nothing can see, reach or close, with a control socket
    /// any process running as this user could still have attached to. This
    /// clears those on the next launch.
    ///
    /// A directory whose owning process is still alive belongs to another
    /// running copy of the app and is left alone.
    static func sweepAbandonedSessions() async {
        let parent = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("SSH-Wakey", isDirectory: true)
        guard let entries = try? FileManager.default.contentsOfDirectory(
            at: parent, includingPropertiesForKeys: [.contentModificationDateKey]) else { return }

        for entry in entries where isAbandoned(entry) {
            let control = entry.appendingPathComponent("ctl")
            if FileManager.default.fileExists(atPath: control.path) {
                // ssh looks at the control socket before the destination, so
                // the name here is only a placeholder.
                _ = try? await ProcessRunner.run(
                    executable: SSHCommandBuilder.sshExecutable,
                    arguments: ["-o", "ControlPath=\(control.path)", "-O", "exit",
                                "abandoned-session"],
                    timeout: 5)
            }
            try? FileManager.default.removeItem(at: entry)
        }
    }

    static func isAbandoned(_ directory: URL) -> Bool {
        let owner = directory.appendingPathComponent(ownerFileName)
        guard let text = try? String(contentsOf: owner, encoding: .utf8),
              let pid = pid_t(text.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            // No owner recorded: a password-channel folder, or one from an
            // older build. Only cleared once it is old enough that it cannot
            // belong to an attempt happening right now.
            let age = (try? directory.resourceValues(forKeys: [.contentModificationDateKey]))?
                .contentModificationDate.map { Date().timeIntervalSince($0) }
            return (age ?? 0) > 3600
        }
        if pid == getpid() { return false }
        // Alive means another copy of the app owns it. EPERM also means alive.
        return kill(pid, 0) != 0 && errno == ESRCH
    }

    private static func makeSessionDirectory() throws -> URL {
        let parent = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("SSH-Wakey", isDirectory: true)
        let directory = parent.appendingPathComponent("s-\(UUID().uuidString.prefix(8))", isDirectory: true)
        try FileManager.default.createDirectory(
            at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])

        // Records which app process owns this, so a later launch can tell a
        // session abandoned by a crash from one belonging to a running copy.
        try? Data(String(getpid()).utf8)
            .write(to: directory.appendingPathComponent(ownerFileName))
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
