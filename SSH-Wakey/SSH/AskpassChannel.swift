import Darwin
import Foundation
import Security

/// Authorizes one native password popup for one actual SSH child. This class
/// never receives, retains or transmits a password. Environment values identify
/// the attempt but are not accepted as proof of caller identity.
final class AskpassChannel: @unchecked Sendable {
    struct Outcome: Equatable {
        var served = false
        var authenticated = false
        var repeatedPrompts = 0
        var refusedPrompts: [String] = [] // fixed categories, never server text
        var wrongNonceAttempts = 0
        var wrongUserAttempts = 0
        var wrongProgramAttempts = 0
        var promptedAt: TimeInterval?
        var cancelled = false
        mutating func reservePrompt(at time: TimeInterval) -> Bool {
            guard promptedAt == nil else { repeatedPrompts += 1; return false }
            guard !cancelled else { return false }
            promptedAt = time
            return true
        }
        var summary: String {
            var parts = [served ? "password submitted by the native helper" : "no password submitted"]
            if repeatedPrompts > 0 { parts.append("repeated prompt refused") }
            if !refusedPrompts.isEmpty { parts.append("unsupported authentication prompt refused") }
            if wrongNonceAttempts + wrongUserAttempts + wrongProgramAttempts > 0 {
                parts.append("unauthorized helper request refused")
            }
            if cancelled { parts.append("password entry cancelled") }
            return parts.joined(separator: ", ")
        }
    }

    let nonce: String
    private let context: AskpassProtocol.Context
    private let helperPath: String
    private let helperRequirement: String
    private let inputRequirement: String
    private let inputPath: String
    private let beforePasswordEntry: @Sendable () -> Void
    private let socketPath: String
    private let listener: Int32
    private let condition = NSCondition()
    private var expectedSSH: ProcessIdentity?
    private var stopped = false
    private var activeClient: Int32 = -1
    private var outcomeValue = Outcome()
    private let queue = DispatchQueue(label: "com.CadenGithubB.sshwakey.askpass-authorization")

    var outcome: Outcome { condition.lock(); defer { condition.unlock() }; return outcomeValue }

    init(context: AskpassProtocol.Context, directory: URL,
         helperPath: String = HelperLayout.adapterPath,
         beforePasswordEntry: @escaping @Sendable () -> Void = {}) throws {
        let adapter = URL(fileURLWithPath: helperPath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let input = HelperLayout.service(in: adapter)
        guard !helperPath.isEmpty,
              let requirement = HelperIdentity.requirement(at: adapter),
              let inputRequirement = HelperIdentity.requirement(at: input) else { throw AskpassError.invalidProcess }
        self.helperRequirement = requirement
        self.inputRequirement = inputRequirement
        self.inputPath = HelperLayout.executable(in: input, name: HelperLayout.serviceName).resolvingSymlinksInPath().path
        self.context = context
        self.beforePasswordEntry = beforePasswordEntry
        self.helperPath = URL(fileURLWithPath: helperPath).resolvingSymlinksInPath().path
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess
        else { throw AskpassError.randomFailed }
        self.nonce = bytes.map { String(format: "%02x", $0) }.joined()
        try ProtectedFile.createPrivateDirectory(at: directory)
        self.socketPath = directory.appendingPathComponent("ask").path
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw AskpassError.socketCreationFailed }
        do {
            guard AskpassProtocol.configure(fd),
                  fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else { throw AskpassError.socketCreationFailed }
            let status = try AskpassProtocol.withSocketAddress(path: socketPath) { bind(fd, $0, $1) }
            guard status == 0, chmod(socketPath, 0o600) == 0, listen(fd, 4) == 0
            else { throw AskpassError.socketCreationFailed }
        } catch {
            close(fd)
            unlink(socketPath)
            throw error
        }
        listener = fd
        // Explicit invalidation ends the worker's ownership. SessionManager
        // installs its defer immediately after construction.
        queue.async { self.acceptLoop() }
    }

    func environmentAdditions() -> [String: String] {
        ["SSH_ASKPASS": helperPath, "SSH_ASKPASS_REQUIRE": "force",
         AskpassProtocol.socketEnvironmentKey: socketPath, AskpassProtocol.nonceEnvironmentKey: nonce]
    }

    func registerSSHProcess(_ process: Process) throws {
        guard process.isRunning, let identity = ProcessIdentity.read(process.processIdentifier),
              identity.parent == getpid(), identity.isAppleSSH else { throw AskpassError.invalidProcess }
        condition.lock(); defer { condition.unlock() }
        guard !stopped, outcomeValue.promptedAt == nil else { throw AskpassError.invalidProcess }
        expectedSSH = identity
        condition.broadcast()
    }

    func invalidate() {
        condition.lock(); defer { condition.unlock() }
        guard !stopped else { return }
        stopped = true
        if activeClient >= 0 { shutdown(activeClient, SHUT_RDWR) }
        condition.broadcast()
        // The worker alone closes descriptors, avoiding close/reuse races.
    }

    private func acceptLoop() {
        defer { close(listener); unlink(socketPath) }
        while true {
            condition.lock(); let done = stopped; condition.unlock()
            if done { return }
            var state = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
            let ready = poll(&state, 1, 100)
            if ready < 0 && errno == EINTR { continue }
            if ready < 0 { return }
            if ready == 0 { continue }
            let client = accept(listener, nil, nil)
            if client < 0 { continue }
            condition.lock()
            activeClient = client
            let cancelled = stopped
            condition.unlock()
            if !cancelled { handle(client) }
            condition.lock()
            activeClient = -1
            close(client)
            condition.unlock()
        }
    }

    /// Pure relationship check is tested separately from kernel/signature reads.
    static func isExpectedHelper(_ peer: ProcessIdentity, ssh: ProcessIdentity,
                                 appPID: pid_t, helperPath: String) -> Bool {
        peer.uid == getuid() && ssh.uid == getuid() && peer.path == helperPath
            && peer.parent == ssh.pid && ssh.parent == appPID && ssh.path == "/usr/bin/ssh"
    }

    private func handle(_ client: Int32) {
        guard AskpassProtocol.configure(client), let peer = ProcessIdentity.peer(on: client) else {
            record { $0.wrongUserAttempts += 1 }; return
        }
        guard HelperIdentity.peer(on: client, matches: helperRequirement) else {
            record { $0.wrongProgramAttempts += 1 }; return
        }
        condition.lock()
        let until = Date().addingTimeInterval(2)
        while expectedSSH == nil && !stopped {
            if !condition.wait(until: until) { break }
        }
        let ssh = expectedSSH
        let cancelled = stopped
        condition.unlock()
        guard !cancelled, let ssh, ssh.isCurrent, peer.isCurrent,
              Self.isExpectedHelper(peer, ssh: ssh, appPID: getpid(), helperPath: helperPath) else {
            record { $0.wrongProgramAttempts += 1 }; return
        }
        guard let line = AskpassProtocol.readLine(from: client),
              let request = AskpassProtocol.decode(AskpassProtocol.Message.self, line) else { return }
        guard AskpassProtocol.constantTimeEquals(request.nonce, nonce) else {
            record { $0.wrongNonceAttempts += 1 }; return
        }
        if request.event == "authenticated" {
            // The builder installs a two-argument LocalCommand callback, run
            // after authentication. A server's single askpass prompt argument
            // cannot select this mode in the signed helper.
            guard request.prompt.isEmpty, ssh.isCurrent, peer.isCurrent else { return }
            record { $0.authenticated = true }
            _ = AskpassProtocol.sendLine("accepted", to: client)
            return
        }
        guard request.event == "password" else { return }
        guard request.prompt == "Password:" else {
            record { if $0.refusedPrompts.isEmpty { $0.refusedPrompts = ["Unsupported authentication prompt"] } }
            return
        }
        condition.lock()
        let start = ProcessInfo.processInfo.systemUptime
        let granted = !stopped && outcomeValue.reservePrompt(at: start)
        let denied = stopped
        condition.unlock()
        guard !denied else { return }
        guard granted else { return }
        beforePasswordEntry()
        let grant = AskpassProtocol.Grant(context: context, ssh: ssh,
            expiresAt: start + AskpassProtocol.promptLifetime)
        guard let encoded = AskpassProtocol.encode(grant), AskpassProtocol.sendLine(encoded, to: client),
              let result = AskpassProtocol.readLine(from: client, timeout: AskpassProtocol.promptLifetime + 2)
        else { record { $0.cancelled = true }; return }
        guard result == "ready" else { record { $0.cancelled = true }; return }
        condition.lock(); let invalid = stopped; condition.unlock()
        // Darwin reports the current writer after XPC transfers the connected
        // descriptor. The ready message must now come from our sandboxed input
        // service, while the original authorized adapter and SSH are still alive.
        guard !invalid, ssh.isCurrent, peer.isCurrent,
              ProcessInfo.processInfo.systemUptime < grant.expiresAt,
              let input = ProcessIdentity.peer(on: client), input.path == inputPath, input.isCurrent,
              HelperIdentity.peer(on: client, matches: inputRequirement) else {
            record { $0.cancelled = true }; return
        }
        guard AskpassProtocol.sendLine("send", to: client) else { return }
        if AskpassProtocol.readLine(from: client) == "sent" { record { $0.served = true } }
    }

    private func record(_ change: (inout Outcome) -> Void) {
        condition.lock(); change(&outcomeValue); condition.unlock()
    }
}
