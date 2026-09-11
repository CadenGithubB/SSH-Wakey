import Darwin
import Foundation
import Security

/// A single-use local channel that hands one password to one `ssh` askpass
/// invocation, then destroys itself.
///
/// What this buys us, compared with the usual askpass-script approach:
///
///  * The password is never an argument, never an environment value and never
///    a file. It crosses an `AF_UNIX` stream socket inside a `0700` directory.
///  * The caller must present a random nonce that only the spawned `ssh`
///    process was given, and must be running as the same user.
///  * Exactly one password is ever served. Afterwards the listener is closed,
///    the socket is unlinked, the directory is removed and the plaintext is
///    overwritten, so the helper cannot be replayed.
final class AskpassChannel: @unchecked Sendable {

    /// What the channel saw during one connection attempt. Recorded so the
    /// window can explain an odd failure instead of guessing.
    struct Outcome: Equatable {
        /// False when ssh authenticated without ever asking, usually because a
        /// key or an agent was accepted first.
        var served = false
        /// ssh came back for a password after being given one. That happens
        /// when the first authentication method rejected it and ssh moves on to
        /// the next one. One typed password is used once, so this goes
        /// unanswered.
        var askedAgainAfterServing = 0
        /// Prompts that were not password prompts, so they went unanswered.
        var refusedPrompts: [String] = []
        var wrongNonceAttempts = 0
        var wrongUserAttempts = 0
        /// Something connected that was not the helper this app started.
        var wrongProgramAttempts = 0
    }

    let nonce: String

    /// The only executable that should ever ask. Empty disables the check.
    private let helperPath: String
    private let password: SecureBuffer
    private let directoryURL: URL
    private let socketPath: String
    private let queue = DispatchQueue(label: "com.CadenGithubB.sshwakey.askpass")
    private let lock = NSLock()

    private var listenDescriptor: Int32 = -1
    private var served = false
    private var invalidated = false
    private var outcomeValue = Outcome()

    /// What happened on the channel. Read after the connection attempt ends.
    var outcome: Outcome {
        lock.lock(); defer { lock.unlock() }
        return outcomeValue
    }

    /// Creates the private directory, binds the socket and starts listening.
    init(password: SecureBuffer, helperPath: String = Bundle.main.executablePath ?? "") throws {
        self.password = password
        self.helperPath = Self.resolved(helperPath)
        self.nonce = Self.makeNonce()

        let parent = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("SSH-Wakey", isDirectory: true)
        let directory = parent.appendingPathComponent("ap-\(UUID().uuidString.prefix(8))", isDirectory: true)
        do {
            try FileManager.default.createDirectory(
                at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        } catch {
            throw AskpassError.temporaryDirectoryUnavailable(error.localizedDescription)
        }
        self.directoryURL = directory
        self.socketPath = directory.appendingPathComponent("s", isDirectory: false).path

        try openSocket()
        queue.async { [weak self] in self?.acceptLoop() }
    }

    deinit {
        invalidate()
    }

    /// The environment additions the spawned `ssh` needs. The password is not
    /// in here; only where to ask and how to prove it is the right asker.
    func environmentAdditions() -> [String: String] {
        [
            "SSH_ASKPASS": helperPath,
            "SSH_ASKPASS_REQUIRE": "force",
            AskpassProtocol.socketEnvironmentKey: socketPath,
            AskpassProtocol.nonceEnvironmentKey: nonce,
        ]
    }

    /// Closes the channel and wipes the password. Idempotent.
    func invalidate() {
        lock.lock()
        if invalidated {
            lock.unlock()
            return
        }
        invalidated = true
        let descriptor = listenDescriptor
        listenDescriptor = -1
        lock.unlock()

        if descriptor >= 0 {
            shutdown(descriptor, SHUT_RDWR)
            close(descriptor)
        }
        password.wipe()
        unlink(socketPath)
        try? FileManager.default.removeItem(at: directoryURL)
    }

    // MARK: - Socket plumbing

    private func openSocket() throws {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw AskpassError.socketCreationFailed(Self.describeErrno())
        }

        // Non-blocking, so the accept loop can notice invalidation promptly.
        let flags = fcntl(descriptor, F_GETFL, 0)
        _ = fcntl(descriptor, F_SETFL, flags | O_NONBLOCK)

        unlink(socketPath)
        do {
            let bound = try AskpassProtocol.withSocketAddress(path: socketPath) { address, length in
                bind(descriptor, address, length)
            }
            guard bound == 0 else {
                let reason = Self.describeErrno()
                close(descriptor)
                throw AskpassError.socketCreationFailed(reason)
            }
        } catch {
            close(descriptor)
            throw error
        }

        chmod(socketPath, 0o600)
        guard listen(descriptor, 1) == 0 else {
            let reason = Self.describeErrno()
            close(descriptor)
            unlink(socketPath)
            throw AskpassError.socketCreationFailed(reason)
        }

        lock.lock()
        listenDescriptor = descriptor
        lock.unlock()
    }

    private var isInvalidated: Bool {
        lock.lock(); defer { lock.unlock() }
        return invalidated
    }

    private func acceptLoop() {
        while true {
            lock.lock()
            let descriptor = listenDescriptor
            let stopped = invalidated
            lock.unlock()
            guard !stopped, descriptor >= 0 else { return }

            var poller = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            let ready = withUnsafeMutablePointer(to: &poller) { poll($0, 1, 100) }
            if ready < 0 {
                if errno == EINTR { continue }
                return
            }
            if ready == 0 { continue }

            let client = accept(descriptor, nil, nil)
            if client < 0 {
                if errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { continue }
                return
            }
            handle(client: client)
            close(client)
        }
    }

    private func handle(client: Int32) {
        // Writing to a peer that has already gone raises SIGPIPE, and the
        // default disposition for that is to kill the process. The app must not
        // die because an askpass helper gave up early, so the error is turned
        // into an ordinary EPIPE on this socket.
        var noSignal: Int32 = 1
        setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))

        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        // The peer must be this same user. The 0700 directory already enforces
        // that; this is the belt to that pair of braces.
        var peerUID = uid_t(0)
        var peerGID = gid_t(0)
        if getpeereid(client, &peerUID, &peerGID) != 0 || peerUID != getuid() {
            record { $0.wrongUserAttempts += 1 }
            return
        }

        guard peerIsTheHelper(client) else {
            record { $0.wrongProgramAttempts += 1 }
            return
        }

        guard let request = readRequest(from: client) else { return }
        let parts = request.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false)
        let presentedNonce = parts.first.map(String.init) ?? ""
        let prompt = parts.count > 1 ? String(parts[1]) : ""

        guard AskpassProtocol.constantTimeEquals(presentedNonce, nonce) else {
            record { $0.wrongNonceAttempts += 1 }
            return
        }
        guard AskpassProtocol.looksLikePasswordPrompt(prompt) else {
            record { $0.refusedPrompts.append(prompt.trimmingCharacters(in: .whitespacesAndNewlines)) }
            return
        }

        lock.lock()
        let alreadyServed = served
        if !served { served = true }
        lock.unlock()

        // One typed password, one use. ssh asks again when the first
        // authentication method rejects it; answering that would be a silent
        // retry, so it is recorded and left unanswered.
        guard !alreadyServed else {
            record { $0.askedAgainAfterServing += 1 }
            return
        }

        send(to: client)
        record { $0.served = true }

        // The plaintext is not needed again. The listener stays up only so a
        // further ask can be noticed, and `invalidate()` closes it when the
        // connection attempt ends.
        password.wipe()
    }

    /// The socket path and the nonce travel in the environment of the `ssh`
    /// process, and on macOS anything running as this user can read another of
    /// its own processes' environment. So the nonce alone is not proof: check
    /// that the program on the other end really is the copy of this executable
    /// that ssh started as its askpass helper.
    private func peerIsTheHelper(_ client: Int32) -> Bool {
        guard !helperPath.isEmpty else { return true }

        var peerPID = pid_t(0)
        var size = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(client, SOL_LOCAL, LOCAL_PEERPID, &peerPID, &size) == 0, peerPID > 0 else {
            // Cannot tell who it is. The uid check and the nonce still apply.
            return true
        }

        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let length = proc_pidpath(peerPID, &buffer, UInt32(buffer.count))
        guard length > 0 else { return true }
        return Self.resolved(String(cString: buffer)) == helperPath
    }

    /// Both sides are compared with symlinks resolved, so that /var against
    /// /private/var, or an app reached through a linked folder, is not mistaken
    /// for a different program.
    private static func resolved(_ path: String) -> String {
        guard !path.isEmpty else { return path }
        return URL(fileURLWithPath: path).resolvingSymlinksInPath().path
    }

    private func readRequest(from client: Int32) -> String? {
        var collected = [UInt8]()
        var chunk = [UInt8](repeating: 0, count: 512)
        while collected.count < AskpassProtocol.maxRequestBytes {
            let count = chunk.withUnsafeMutableBytes { read(client, $0.baseAddress, $0.count) }
            if count > 0 {
                collected.append(contentsOf: chunk[0..<count])
                continue
            }
            if count == 0 { break }
            if errno == EINTR { continue }
            return nil
        }
        return String(decoding: collected, as: UTF8.self)
    }

    /// Writes the password followed by a newline, which is what `ssh` expects
    /// from an askpass program on stdout.
    private func send(to client: Int32) {
        password.withBytes { bytes in
            var payload = [UInt8](bytes)
            payload.append(0x0A)
            payload.withUnsafeBytes { raw in
                var offset = 0
                while offset < raw.count {
                    let written = write(client, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                    if written > 0 {
                        offset += written
                        continue
                    }
                    if written < 0 && errno == EINTR { continue }
                    break
                }
            }
            payload.withUnsafeMutableBytes { buffer in
                if let address = buffer.baseAddress {
                    memset_s(address, buffer.count, 0, buffer.count)
                }
            }
        }
    }

    private func record(_ change: (inout Outcome) -> Void) {
        lock.lock()
        change(&outcomeValue)
        lock.unlock()
    }

    private static func makeNonce() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        if SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) != errSecSuccess {
            for index in bytes.indices { bytes[index] = UInt8.random(in: 0...255) }
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    private static func describeErrno() -> String {
        String(cString: strerror(errno))
    }
}
