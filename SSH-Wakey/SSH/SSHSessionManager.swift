import Darwin
import Foundation
import Observation

/// Owns every live SSH session and the state the window displays.
///
/// A "session" here is one `ssh -M -N` master process. It authenticates once
/// and then holds the connection open. Terminal windows attach to it through
/// the control socket. Password entry, when needed, belongs to the short-lived
/// native helper, never to this model.
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
        case wakeResult(WakeResult)
        case failed(SSHFailure)

        var isConnecting: Bool { if case .connecting = self { return true }; return false }
        var isConnected: Bool { if case .connected = self { return true }; return false }
    }

    struct Unlocked: Equatable {
        var at: Date
        /// Whether the native helper submitted a password during this attempt.
        var usedPassword: Bool
        /// True when the machine closed the connection rather than the app.
        var closedByServer: Bool
    }

    /// Reachability is deliberately separate from authentication and disk unlock.
    struct WakeResult: Equatable {
        var loginConfirmed: Bool
        var reachablePort: Int?
        var checkStopped = false
        var screenSharingRespondedBeforeSSH: Bool? = nil

        var desktopReady: Bool { reachablePort == 5900 }

        var headline: String {
            if desktopReady { return "Ready for Remote Desktop" }
            if checkStopped { return "Readiness check stopped." }
            return "Screen Sharing hasn’t responded yet."
        }

        var guidance: String {
            if desktopReady {
                return "Your Mac’s Screen Sharing service is responding. You can connect now."
            }
            if checkStopped { return "You can try Remote Desktop now, or select Wake to check again." }
            return "Your Mac may still be starting. Wait a moment, then try Remote Desktop. See Activity for connection details."
        }

        var activitySummary: String {
            let login = loginConfirmed ? "SSH login confirmed; connection closed." : "Password sent; SSH ended without confirming login."
            let readiness: String
            if desktopReady {
                readiness = "Screen Sharing protocol greeting verified on port 5900. "
                    + (screenSharingRespondedBeforeSSH == true ? "Screen Sharing responded before password submission. "
                       : screenSharingRespondedBeforeSSH == false ? "Screen Sharing was not observed in the initial check; responding afterwards. " : "")
                    + "FileVault unlock not verified; desktop login not attempted."
            } else if checkStopped {
                readiness = "Readiness check stopped."
            } else if let port = reachablePort {
                readiness = "TCP port \(port) answered, but no Screen Sharing greeting was verified within 45 seconds; unlock not confirmed."
            } else {
                readiness = "No service answered within 45 seconds; unlock not confirmed."
            }
            return login + " " + readiness
        }
    }

    struct Connected: Equatable {
        var since: Date
        /// Whether the native helper submitted a password during this attempt.
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
    static let passwordSentHeadline = "Password sent. Waiting for the Mac to finish starting…"
    static let readinessHeadline = "Still waiting for your Mac…"
    static let baselineHeadline = "Checking Screen Sharing before Wake…"
    /// Managed builds never hold a session, even if a caller asks.
    var forcesUnlock: Bool = AppDistribution.isManagedBuild
    /// The app-lock controller owns this gate. View visibility is not authority
    /// to connect, attach to a master, or publish an asynchronous result.
    private(set) var isAppLocked = false
    private var authorizationGeneration = UUID()

    struct WakeTrace {
        var connection: SSHConnection
        var mode: ConnectMode
        var baseline: Bool?
        var events: [DiagnosticEvent]
    }
    private var traces: [UUID: WakeTrace] = [:]
    private var pendingHostTrust: [UUID: WakeTrace] = [:]

    private var sessions: [UUID: Session] = [:]
    private var attempts: [UUID: Task<Void, Never>] = [:]
    private var attemptDirectories: [UUID: URL] = [:]
    private var addressLookups: [UUID: (token: UUID, task: Task<Void, Never>)] = [:]
    // Kept synchronously so normal app termination also closes attempts that
    // have authenticated but have not yet become an established Session.
    private var inFlight: [UUID: (process: Process, channel: AskpassChannel, log: SSHDiagnosticStream)] = [:]
    private let wake: (String, String?) async -> Void
    private let makeDirectory: () throws -> URL
    private let checkReadiness: (String, Int) async -> Int?
    private let checkScreenSharing: (String) async -> Bool

    init(wake: @escaping (String, String?) async -> Void = {
        await NetworkWake.poke(host: $0, hardwareAddress: $1)
    }, makeSessionDirectory: (() throws -> URL)? = nil,
       checkReadiness: @escaping (String, Int) async -> Int? = {
           await WakeReadiness.check(host: $0, sshPort: $1)
       }, checkScreenSharing: @escaping (String) async -> Bool = {
           await WakeReadiness.screenSharingAvailable(host: $0)
       }) {
        self.checkScreenSharing = checkScreenSharing
        self.checkReadiness = checkReadiness
        self.wake = wake
        self.makeDirectory = makeSessionDirectory ?? { try Self.makeSessionDirectory() }
    }

    private struct Session {
        let process: Process
        let controlPath: String
        let directoryURL: URL
        let connection: SSHConnection
        let log: SSHDiagnosticStream
        let monitor: Task<Void, Never>
    }

    var activeSessionCount: Int { sessions.count }

    /// Call with true before hiding/releasing the unlocked vault; call with
    /// false only after the app-lock controller has authenticated the user.
    /// Unlock permits fresh work. It never revives work from before the lock.
    func setAppLocked(_ locked: Bool) {
        guard locked != isAppLocked else { return }
        isAppLocked = locked
        guard locked else { return }
        authorizationGeneration = UUID()
        disconnectAll()
        for attempt in inFlight.values {
            attempt.log.collector.suppressStorage()
            attempt.log.close()
        }
        for directory in attemptDirectories.values {
            try? FileManager.default.removeItem(at: directory)
        }
        attempts.removeAll()
        inFlight.removeAll()
        attemptDirectories.removeAll()
        states.removeAll()
        diagnostics.removeAll()
        traces.removeAll()
        pendingHostTrust.removeAll()
        lastActionError = nil
        // Cancelling drops retained work as it unwinds. Swift/framework copies
        // of connection metadata are not claimed to be physically erased.
    }

    private func isAuthorized(_ generation: UUID) -> Bool {
        !isAppLocked && generation == authorizationGeneration
    }

    func state(for id: UUID?) -> State {
        guard let id else { return .idle }
        return states[id] ?? .idle
    }

    // MARK: - Connecting

    /// No password enters the main app. The verified SSH child opens the native helper.
    func connect(_ connection: SSHConnection, mode: ConnectMode, continuingTrust: Bool = false) {
        guard !isAppLocked else { return }
        let resolvedMode = forcesUnlock ? ConnectMode.unlock : mode
        let id = connection.id
        guard attempts[id] == nil, sessions[id] == nil else {
            return
        }
        beginAttemptTrace(connection, mode: resolvedMode, continuingTrust: continuingTrust)
        states[id] = .connecting(
            stage: NetworkWake.shouldPoke(
                host: connection.host, hardwareAddress: connection.hardwareAddress)
            ? Self.wakingHeadline
            : "Starting ssh…")
        let generation = authorizationGeneration
        attempts[id] = Task { [weak self] in
            await self?.runAttempt(connection, mode: resolvedMode, generation: generation)
        }
    }

    func cancelConnect(_ id: UUID) {
        discardHostTrustContinuation(id)
        attempts[id]?.cancel()
    }

    func discardHostTrustContinuation(_ id: UUID) {
        pendingHostTrust[id] = nil
    }

    /// Continuation is explicit and bound to the unchanged connection and mode.
    /// A normal Wake always starts a fresh timeline.
    func beginAttemptTrace(_ connection: SSHConnection, mode: ConnectMode, continuingTrust: Bool) {
        guard !isAppLocked else { return }
        let previous = pendingHostTrust.removeValue(forKey: connection.id)
        if continuingTrust, let previous, previous.connection == connection, previous.mode == mode {
            traces[connection.id] = previous
            observe(connection.id, "Host trusted; continuing the original attempt.")
        } else {
            traces[connection.id] = WakeTrace(connection: connection, mode: mode, events: [])
            observe(connection.id, mode == .unlock ? "Wake requested." : "Connection requested.")
        }
    }

    func observeBaseline(_ connectionID: UUID, responded: Bool, at: Date = Date()) {
        traces[connectionID]?.baseline = responded
        observe(connectionID, responded
            ? "Screen Sharing greeting received before password submission."
            : "No Screen Sharing greeting received during the initial check.", at: at)
    }

    func retainHostTrustContinuation(_ connectionID: UUID) {
        observe(connectionID, "Waiting for host trust approval.")
        if pendingHostTrust.count >= DiagnosticsReport.maximumEntries,
           let oldest = pendingHostTrust.min(by: {
               ($0.value.events.first?.at ?? .distantPast) < ($1.value.events.first?.at ?? .distantPast)
           })?.key { pendingHostTrust[oldest] = nil }
        pendingHostTrust[connectionID] = traces[connectionID]
    }

    func initialScreenSharingObservation(_ id: UUID) -> Bool? { traces[id]?.baseline }

    private func observe(_ id: UUID, _ message: String, at: Date = Date()) {
        guard traces[id] != nil, (traces[id]?.events.count ?? 0) < 24 else { return }
        traces[id]?.events.append(DiagnosticEvent(at: at, message: message))
    }

    private func runAttempt(
        _ connection: SSHConnection,
        mode: ConnectMode,
        generation: UUID
    ) async {
        let id = connection.id
        defer {
            if generation == authorizationGeneration {
                attempts[id] = nil
                inFlight[id] = nil
                attemptDirectories[id] = nil
                traces[id] = nil
            }
        }
        guard isAuthorized(generation) else { return }
        guard !Task.isCancelled else {
            states[id] = .failed(Self.cancelledFailure)
            return
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
            directory = try makeDirectory()
            attemptDirectories[id] = directory
            controlPath = directory.appendingPathComponent("ctl", isDirectory: false).path
        } catch {
            states[id] = .failed(SSHFailure(
                kind: .launchFailed,
                headline: "Could not create a private folder for the session.",
                guidance: error.localizedDescription, detail: nil))
            return
        }

        var screenSharingRespondedBeforeSSH = initialScreenSharingObservation(id)
        if mode == .unlock, screenSharingRespondedBeforeSSH == nil {
            states[id] = .connecting(stage: Self.baselineHeadline)
            screenSharingRespondedBeforeSSH = await checkScreenSharing(connection.host)
            guard isAuthorized(generation) else {
                try? FileManager.default.removeItem(at: directory)
                return
            }
            if Task.isCancelled {
                try? FileManager.default.removeItem(at: directory)
                states[id] = .failed(Self.cancelledFailure)
                return
            }
            observeBaseline(id, responded: screenSharingRespondedBeforeSSH == true)
        }

        if NetworkWake.shouldPoke(host: connection.host, hardwareAddress: connection.hardwareAddress) {
            states[id] = .connecting(stage: Self.wakingHeadline)
            await wake(connection.host, connection.hardwareAddress)
            guard isAuthorized(generation) else {
                try? FileManager.default.removeItem(at: directory)
                return
            }
            if Task.isCancelled {
                try? FileManager.default.removeItem(at: directory)
                states[id] = .failed(Self.cancelledFailure)
                return
            }
            try? await Task.sleep(nanoseconds: NetworkWake.settleNanoseconds)
            guard isAuthorized(generation) else {
                try? FileManager.default.removeItem(at: directory)
                return
            }
            if Task.isCancelled {
                try? FileManager.default.removeItem(at: directory)
                states[id] = .failed(Self.cancelledFailure)
                return
            }
        }

        let channel: AskpassChannel
        let arguments: [String]
        let log: SSHDiagnosticStream
        do {
            log = try SSHDiagnosticStream(in: directory)
            let trust = try HostKeyService.prepareTrustSnapshot(in: directory)
            switch mode {
            case .unlock:
                arguments = try SSHCommandBuilder.unlockArguments(
                    for: connection, connectTimeout: Self.connectTimeout,
                    diagnosticLogPath: log.url.path, knownHostsPath: trust.path,
                    authenticatedCallbackCommand: AskpassHelper.authenticationCommand(helperPath: Self.askpassHelperPath))
            case .session:
                arguments = try SSHCommandBuilder.masterArguments(
                    for: connection, controlPath: controlPath, connectTimeout: Self.connectTimeout,
                    diagnosticLogPath: log.url.path, knownHostsPath: trust.path,
                    authenticatedCallbackCommand: AskpassHelper.authenticationCommand(helperPath: Self.askpassHelperPath))
            }
            channel = try AskpassChannel(context: .init(destination: connection.displayDestination,
                action: mode.buttonTitle), directory: directory, helperPath: Self.askpassHelperPath,
                beforePasswordEntry: { log.collector.suppressStorage() })
        } catch {
            try? FileManager.default.removeItem(at: directory)
            states[id] = .failed(SSHFailure(kind: .launchFailed,
                headline: "The secure connection could not be prepared.",
                guidance: error.localizedDescription, detail: nil))
            return
        }
        var keepLog = false
        defer { channel.invalidate(); if !keepLog { log.close() } }

        var environment = ProcessRunner.minimalEnvironment()
        environment.merge(channel.environmentAdditions()) { _, new in new }

        var launchesRemaining = NetworkWake.shouldPoke(
            host: connection.host, hardwareAddress: connection.hardwareAddress) ? 2 : 1
        var process = Process()
        let diagnostics = log.collector
        var outcome: AttemptOutcome = .stillWaiting

        launch: while true {
            guard isAuthorized(generation) else {
                terminate(process)
                try? FileManager.default.removeItem(at: directory)
                return
            }
            if Task.isCancelled {
                try? FileManager.default.removeItem(at: directory)
                states[id] = .failed(Self.cancelledFailure)
                return
            }
            states[id] = .connecting(stage: "Starting ssh…")
            observe(id, "SSH attempt started.")
            process = Process()
            process.executableURL = URL(fileURLWithPath: SSHCommandBuilder.sshExecutable)
            process.arguments = arguments
            process.environment = environment
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = FileHandle.nullDevice

            // -E writes only OpenSSH's internal log into a bounded private FIFO.
            // Server banners and prompts on stderr are discarded, not recorded.
            process.standardError = FileHandle.nullDevice
            diagnostics.reset()

            do {
                try process.run()
                inFlight[id] = (process, channel, log)
                if process.isRunning { try channel.registerSSHProcess(process) }
            } catch {
                terminate(process)
                try? FileManager.default.removeItem(at: directory)
                states[id] = .failed(SSHFailure(
                    kind: .launchFailed,
                    headline: "/usr/bin/ssh could not be launched securely.",
                    guidance: error.localizedDescription, detail: nil))
                return
            }

            states[id] = .connecting(stage: "Authenticating…")
            let started = ProcessInfo.processInfo.systemUptime
            outcome = .stillWaiting

            while outcome == .stillWaiting {
                if !isAuthorized(generation) || Task.isCancelled || channel.outcome.cancelled {
                    outcome = .cancelled
                    break
                }
                if channel.outcome.helperFailed {
                    outcome = .helperFailed
                    break
                }
                if channel.outcome.authenticated {
                    outcome = .authenticated
                    break
                }
                if !process.isRunning {
                    try? await Task.sleep(nanoseconds: 50_000_000)
                    outcome = channel.outcome.authenticated
                        ? .authenticated : .exited
                    break
                }
                if channel.outcome.served {
                    states[id] = .connecting(stage: Self.passwordSentHeadline)
                }
                let promptDeadline = channel.outcome.promptedAt.map { $0 + AskpassProtocol.promptLifetime } ?? 0
                let deadline = max(started + Self.overallTimeout, promptDeadline)
                if ProcessInfo.processInfo.systemUptime >= deadline || diagnostics.exceededLimit {
                    outcome = .timedOut
                    break
                }
                try? await Task.sleep(nanoseconds: 150_000_000)
            }

            guard isAuthorized(generation) else {
                terminate(process)
                try? FileManager.default.removeItem(at: directory)
                return
            }

            let canRetry = launchesRemaining > 1
                && channel.outcome.promptedAt == nil
                && Self.shouldRetryAfterWake(outcome, output: diagnostics.text)
            launchesRemaining -= 1
            if canRetry {
                terminate(process)
                states[id] = .connecting(stage: Self.wakingHeadline)
                await wake(connection.host, connection.hardwareAddress)
                guard isAuthorized(generation) else {
                    try? FileManager.default.removeItem(at: directory)
                    return
                }
                if Task.isCancelled || channel.outcome.cancelled {
                    try? FileManager.default.removeItem(at: directory)
                    record(connection, mode: mode, result: "Cancelled",
                           channel: channel.outcome, output: diagnostics.text)
                    states[id] = .failed(Self.cancelledFailure)
                    return
                }
                try? await Task.sleep(nanoseconds: NetworkWake.settleNanoseconds)
                guard isAuthorized(generation) else {
                    try? FileManager.default.removeItem(at: directory)
                    return
                }
                if Task.isCancelled || channel.outcome.cancelled {
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
            try? FileManager.default.removeItem(at: directory)
            record(connection, mode: mode, result: "Cancelled",
                   channel: channel.outcome, output: diagnostics.text)
            states[id] = .failed(SSHFailure(
                kind: .cancelled,
                headline: "Connection cancelled.",
                guidance: "The SSH attempt was stopped and its password helper was closed.", detail: nil))
            return
        case .helperFailed:
            terminate(process)
            try? FileManager.default.removeItem(at: directory)
            record(connection, mode: mode, result: Self.helperFailure.headline,
                   channel: channel.outcome, output: diagnostics.text)
            states[id] = .failed(Self.helperFailure)
            return
        case .timedOut:
            terminate(process)
            try? FileManager.default.removeItem(at: directory)
            var failure = SSHOutputClassifier.classify(exitCode: -1, standardError: diagnostics.text)
            if failure.kind == .unknown {
                failure = SSHFailure(
                    kind: .timeout,
                    headline: "The connection timed out.",
                    guidance: "ssh did not finish authenticating within the allowed time or exceeded the diagnostic output limit.",
                    detail: nil)
            }
            record(connection, mode: mode, result: failure.headline,
                   channel: channel.outcome, output: diagnostics.text)
            states[id] = .failed(Self.annotated(failure, with: channel.outcome, host: connection.host))
            return
        case .exited:
            // Give the reader a moment to drain the last of stderr.
            try? await Task.sleep(nanoseconds: 200_000_000)
            try? FileManager.default.removeItem(at: directory)
            guard isAuthorized(generation) else { return }

            let outcome = channel.outcome
            var failure = SSHOutputClassifier.classify(
                exitCode: process.terminationStatus, standardError: diagnostics.text)
            if !outcome.served, !outcome.refusedPrompts.isEmpty, failure.kind == .unknown {
                failure.kind = .askpassRefused
                failure.headline = "ssh asked for something other than a password."
            }
            if Self.mayHaveUnlocked(failure: failure, outcome: outcome) {
                channel.invalidate()
                log.close()
                await finishWake(connection, mode: mode, loginConfirmed: false,
                                 channel: outcome, screenSharingRespondedBeforeSSH: screenSharingRespondedBeforeSSH, generation: generation)
                return
            }
            if failure.kind == .hostKeyUnknown { retainHostTrustContinuation(id) }
            record(connection, mode: mode, result: failure.headline,
                   channel: outcome, output: diagnostics.text)
            states[id] = .failed(Self.annotated(failure, with: outcome, host: connection.host))
            return
        }

        // Authenticated.
        let usedPassword = channel.outcome.served

        if mode == .unlock {
            terminate(process)
            try? FileManager.default.removeItem(at: directory)
            let delivered = channel.outcome
            channel.invalidate()
            log.close()
            rememberLinkAddress(of: connection, generation: generation)
            await finishWake(connection, mode: mode, loginConfirmed: true,
                             channel: delivered, screenSharingRespondedBeforeSSH: screenSharingRespondedBeforeSSH, generation: generation)
            return
        }

        if !process.isRunning {
            // A session was asked for, but the far end hung up right after
            // accepting the password. That is what unlocking a disk looks like,
            // so it is reported as a success rather than a failure.
            try? FileManager.default.removeItem(at: directory)
            record(connection, mode: mode, result: "Logged in, then the machine closed it",
                   channel: channel.outcome, output: diagnostics.text)
            rememberLinkAddress(of: connection, generation: generation)
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

        guard isAuthorized(generation) else {
            terminate(process)
            try? FileManager.default.removeItem(at: directory)
            return
        }
        if Task.isCancelled {
            terminate(process)
            try? FileManager.default.removeItem(at: directory)
            states[id] = .failed(Self.cancelledFailure)
            return
        }
        guard let check, check.exitCode == 0, !check.outputLimitExceeded else {
            terminate(process)
            try? FileManager.default.removeItem(at: directory)
            states[id] = .failed(SSHFailure(
                kind: .unknown,
                headline: "The session could not be verified.",
                guidance: "ssh authenticated but the control socket did not answer.",
                detail: nil))
            return
        }

        record(connection, mode: mode, result: "Connected",
               channel: channel.outcome, output: diagnostics.text)
        rememberLinkAddress(of: connection, generation: generation)
        keepLog = true
        let master = process
        let monitor = Task { [weak self] in
            while !Task.isCancelled && master.isRunning {
                guard self?.isAuthorized(generation) == true,
                      self?.sessions[id]?.process === master else { return }
                if diagnostics.exceededLimit { self?.disconnect(id); break }
                try? await Task.sleep(nanoseconds: 250_000_000)
            }
        }
        sessions[id] = Session(process: process, controlPath: controlPath, directoryURL: directory,
            connection: connection, log: log, monitor: monitor)
        states[id] = .connected(Connected(since: Date(), usedPassword: usedPassword))

        process.terminationHandler = { [weak self] process in
            Task { @MainActor [weak self] in
                self?.masterExited(id, process: process, generation: generation)
            }
        }
        if !process.isRunning { masterExited(id, process: process, generation: generation) }
    }

    /// A submitted password is not proof of login. Explicit failures retain their
    /// original meaning; only an otherwise unexplained exit can be a handoff.
    static func mayHaveUnlocked(failure: SSHFailure, outcome: AskpassChannel.Outcome) -> Bool {
        outcome.served && !outcome.authenticated && !outcome.cancelled && !outcome.helperFailed
            && outcome.wrongNonceAttempts == 0 && outcome.wrongUserAttempts == 0
            && outcome.wrongProgramAttempts == 0
            && (failure.kind == .unknown || failure.kind == .closedByRemote)
    }

    /// Reads only the Screen Sharing greeting; no password or login exchange.
    /// Internal visibility permits synthetic lifecycle tests without real hosts.
    func finishWake(_ connection: SSHConnection, mode: ConnectMode, loginConfirmed: Bool,
                    channel: AskpassChannel.Outcome, screenSharingRespondedBeforeSSH: Bool? = nil,
                    generation: UUID? = nil) async {
        let generation = generation ?? authorizationGeneration
        guard isAuthorized(generation) else { return }
        observe(connection.id, loginConfirmed ? "SSH login confirmed; connection closed." : "SSH ended without confirming login.")
        observe(connection.id, "Waiting for Screen Sharing to respond.")
        states[connection.id] = .connecting(stage: Self.readinessHeadline)
        let port = Task.isCancelled ? nil : await checkReadiness(connection.host, connection.port)
        guard isAuthorized(generation) else { return }
        let result = WakeResult(loginConfirmed: loginConfirmed,
                                reachablePort: Task.isCancelled ? nil : port,
                                checkStopped: Task.isCancelled, screenSharingRespondedBeforeSSH: screenSharingRespondedBeforeSSH)
        observe(connection.id, result.desktopReady ? "Screen Sharing greeting verified; ready for Remote Desktop."
            : result.checkStopped ? "Readiness check stopped." : "Screen Sharing check ended without a verified greeting.")
        record(connection, mode: mode, result: result.activitySummary, channel: channel, output: "")
        states[connection.id] = .wakeResult(result)
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
        var events = traces[connection.id]?.events ?? []
        if let at = channel.servedAt { events.append(DiagnosticEvent(at: at, message: "Password submitted by the native helper.")) }
        if let at = channel.authenticatedAt { events.append(DiagnosticEvent(at: at, message: "SSH authentication confirmed by the verified callback.")) }
        diagnostics.append(DiagnosticEntry(
            at: Date(),
            connectionID: connection.id,
            connection: connection.name,
            destination: connection.displayDestination,
            mode: mode.title,
            result: result,
            channel: channel.summary,
            output: output,
            events: events.sorted { $0.at < $1.at }))

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
        case stillWaiting, authenticated, exited, timedOut, cancelled, helperFailed
    }

    // MARK: - Live sessions

    func disconnect(_ id: UUID) {
        guard let session = sessions.removeValue(forKey: id) else { return }
        states[id] = .idle
        session.monitor.cancel()
        session.log.collector.suppressStorage()
        session.log.close()
        terminate(session.process)
        try? FileManager.default.removeItem(at: session.directoryURL)
    }

    func disconnectAll() {
        for task in attempts.values { task.cancel() }
        for lookup in addressLookups.values { lookup.task.cancel() }
        addressLookups.removeAll()
        for attempt in inFlight.values {
            attempt.channel.invalidate()
            terminate(attempt.process)
        }
        for id in Array(sessions.keys) { disconnect(id) }
    }

    /// Quitting ends this process before cancelled attempts unwind, so their
    /// folders (socket, diagnostic FIFO, owner file; no secrets) go now rather
    /// than waiting for the next launch's sweep, as locking already does.
    func shutDownForTermination() {
        disconnectAll()
        for directory in attemptDirectories.values {
            try? FileManager.default.removeItem(at: directory)
        }
        attemptDirectories.removeAll()
    }

    /// Hands the already-authenticated session to Terminal. No password is
    /// involved: the new ssh client attaches to the existing master.
    func openInTerminal(_ id: UUID) {
        guard !isAppLocked else { return }
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
    private func masterExited(_ id: UUID, process: Process, generation: UUID) {
        guard isAuthorized(generation), let session = sessions[id],
              session.process === process else { return }
        sessions.removeValue(forKey: id)
        session.monitor.cancel()
        session.log.close()
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
        // Only the known Apple SSH process is used here. Do not schedule a
        // later raw-PID kill after Foundation may have reaped/reused its PID.
    }

    // MARK: - Helpers

    /// Distinct from Cancel: the person did not stop this.
    static let helperFailure = SSHFailure(
        kind: .helperFailed,
        headline: "Password entry could not complete.",
        guidance: "No password was sent. SSH-Wakey's password entry failed one of its own checks "
            + "or quit unexpectedly. Try again. If it keeps happening, use Help > Save Diagnostics… to report it.",
        detail: nil)

    static let cancelledFailure = SSHFailure(
        kind: .cancelled,
        headline: "Connection cancelled.",
        guidance: "The SSH attempt was stopped and its password helper was closed.", detail: nil)

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

    private func rememberLinkAddress(of connection: SSHConnection, generation: UUID) {
        guard isAuthorized(generation) else { return }
        let id = connection.id
        let host = connection.host
        let token = UUID()
        addressLookups[id]?.task.cancel()
        let task = Task { [weak self] in
            defer {
                if self?.addressLookups[id]?.token == token { self?.addressLookups[id] = nil }
            }
            guard !Task.isCancelled, self?.isAuthorized(generation) == true else { return }
            guard let mac = await NetworkWake.learnedAddress(for: host) else { return }
            guard !Task.isCancelled, self?.isAuthorized(generation) == true else { return }
            self?.onLearnedLinkAddress?(id, mac)
        }
        addressLookups[id] = (token, task)
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
        failure.detail = nil
        var notes: [String] = []

        // A machine on the local network that cannot be reached at all is the
        // signature of a missing Local Network permission, which looks exactly
        // like the machine being switched off.
        if let host, NetworkScope.isLocal(host),
           SSHFailure.localNetworkSuspects.contains(failure.kind) {
            failure.suggestsLocalNetworkPermission = true
            notes.append("If other devices on this network are also unreachable, check that macOS "
                + "has given SSH-Wakey Local Network permission. This error alone does not show "
                + "whether permission is missing.")
        }

        if outcome.repeatedPrompts > 0 {
            notes.append("ssh asked for the password again after it had already been given once. "
                + "SSH-Wakey answers a single password prompt per attempt and left the rest "
                + "unanswered. A repeated prompt alone does not prove the password was rejected; "
                + "FileVault can close SSH while the Mac finishes starting. The password was not resent.")
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

    /// Only the embedded signed adapter can launch the sandboxed password UI.
    static var askpassHelperPath: String {
        HelperLayout.adapterPath
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
    static func sweepAbandonedSessions(in parent: URL) async {
        // An explicit root is required; tests must never sweep real sessions.
        guard (try? ProtectedFile.createPrivateDirectory(at: parent)) != nil else { return }
        guard let entries = try? FileManager.default.contentsOfDirectory(
            at: parent, includingPropertiesForKeys: [.contentModificationDateKey]) else { return }

        for entry in entries where isAbandoned(entry) {
            let control = entry.appendingPathComponent("ctl")
            var controlInfo = stat()
            if lstat(control.path, &controlInfo) == 0,
               controlInfo.st_mode & S_IFMT == S_IFSOCK,
               controlInfo.st_uid == getuid(), controlInfo.st_mode & 0o077 == 0 {
                // ssh looks at the control socket before the destination, so
                // the name here is only a placeholder.
                _ = try? await ProcessRunner.run(
                    executable: SSHCommandBuilder.sshExecutable,
                    arguments: SSHCommandBuilder.abandonedControlArguments(
                        controlPath: control.path),
                    timeout: 5)
            }
            try? FileManager.default.removeItem(at: entry)
        }
    }

    static func isAbandoned(_ directory: URL) -> Bool {
        var info = stat()
        guard lstat(directory.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == getuid(), info.st_mode & 0o077 == 0 else { return false }
        let owner = directory.appendingPathComponent(ownerFileName)
        let data: Data?
        do { data = try ProtectedFile.read(from: owner, maximumBytes: 4096) }
        catch { return false }
        if let data {
            if let identity = try? JSONDecoder().decode(ProcessIdentity.self, from: data) {
                return !identity.isCurrent
            }
            // Older versions stored just the PID. Treat an existing/reused PID
            // conservatively; only its verified absence permits cleanup.
            guard let text = String(data: data, encoding: .utf8),
                  let pid = pid_t(text.trimmingCharacters(in: .whitespacesAndNewlines)), pid > 0 else {
                return false
            }
            return kill(pid, 0) != 0 && errno == ESRCH
        }
        return Date().timeIntervalSince1970 - TimeInterval(info.st_mtimespec.tv_sec) > 3600
    }

    static let temporaryRoot = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        .resolvingSymlinksInPath().appendingPathComponent("SSH-Wakey", isDirectory: true)

    private static func makeSessionDirectory() throws -> URL {
        try ProtectedFile.createPrivateDirectory(at: temporaryRoot)
        let directory = temporaryRoot.appendingPathComponent("s-\(UUID().uuidString.prefix(12))", isDirectory: true)
        try ProtectedFile.createPrivateDirectory(at: directory)
        guard let identity = ProcessIdentity.read(getpid()) else { throw AskpassError.invalidProcess }
        try ProtectedFile.write(JSONEncoder().encode(identity), to: directory.appendingPathComponent(ownerFileName))
        return directory
    }

}

/// Bounded transient internal SSH log. No raw output is retained in history.
final class OutputCollector: @unchecked Sendable {
    static let maximumBytes = 65_536
    private let lock = NSLock()
    private var data = Data()
    private var overflow = false
    private var discarding = false
    private var total = 0

    func append(_ chunk: Data) { chunk.withUnsafeBytes { append($0) } }
    func append(_ chunk: UnsafeRawBufferPointer) {
        lock.lock(); defer { lock.unlock() }
        let available = Self.maximumBytes - total
        if !discarding { data.append(contentsOf: chunk.prefix(available)) }
        total += min(chunk.count, available)
        if chunk.count > available { overflow = true }
    }
    func reset() {
        lock.lock(); defer { lock.unlock() }
        VaultCrypto.erase(&data)
        overflow = false; total = 0; discarding = false
    }
    func suppressStorage() {
        lock.lock(); defer { lock.unlock() }
        discarding = true
        VaultCrypto.erase(&data)
    }
    var exceededLimit: Bool { lock.lock(); defer { lock.unlock() }; return overflow }
    var text: String { lock.lock(); defer { lock.unlock() }; return String(decoding: data, as: UTF8.self) }
}

/// A private FIFO separates OpenSSH's internal log from remote banners on stderr.
/// It never writes log text to a regular file. The reader remains active for a
/// live master; overflow terminates that session instead of growing memory/disk.
final class SSHDiagnosticStream: @unchecked Sendable {
    let url: URL
    let collector = OutputCollector()
    private let reader: DispatchSourceRead
    private let lock = NSLock()
    private var closed = false

    init(in directory: URL) throws {
        url = directory.appendingPathComponent("log")
        guard mkfifo(url.path, 0o600) == 0 else { throw AskpassError.socketCreationFailed }
        let fd = open(url.path, O_RDWR | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { unlink(url.path); throw AskpassError.socketCreationFailed }
        reader = DispatchSource.makeReadSource(fileDescriptor: fd,
            queue: DispatchQueue(label: "com.CadenGithubB.sshwakey.internal-log"))
        let output = collector
        reader.setEventHandler {
            var buffer = [UInt8](repeating: 0, count: 4096)
            for _ in 0..<16 {
                let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
                if count > 0 {
                    buffer.withUnsafeMutableBytes { bytes in
                        output.append(UnsafeRawBufferPointer(rebasing: bytes[..<count]))
                        _ = memset_s(bytes.baseAddress, bytes.count, 0, bytes.count)
                    }
                }
                else if count < 0 && errno == EINTR { continue }
                else { break }
            }
        }
        reader.setCancelHandler { Darwin.close(fd) }
        reader.resume()
    }
    func close() {
        lock.lock(); defer { lock.unlock() }
        guard !closed else { return }
        closed = true
        reader.cancel()
        unlink(url.path)
    }
    deinit { collector.suppressStorage(); close() }
}
