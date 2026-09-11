import Foundation

/// The other half of `AskpassChannel`: what this executable does when `ssh`
/// runs it as `SSH_ASKPASS`.
///
/// `ssh` execs the program named by `SSH_ASKPASS` with the prompt as its only
/// argument and reads the answer from stdout. There is no separate helper
/// binary and no generated script; SSH-Wakey points `SSH_ASKPASS` at its own
/// executable, so there is nothing left on disk to find or to reuse. Askpass
/// mode is selected purely by the environment of that one child process, and
/// it finishes before any UI framework is touched.
enum AskpassHelper {

    struct Request {
        let socketPath: String
        let nonce: String
        let prompt: String
    }

    /// Non-nil only when this process was launched by ssh as the askpass helper.
    static func requestFromEnvironment(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        arguments: [String] = CommandLine.arguments
    ) -> Request? {
        guard let socketPath = environment[AskpassProtocol.socketEnvironmentKey],
              let nonce = environment[AskpassProtocol.nonceEnvironmentKey],
              !socketPath.isEmpty, !nonce.isEmpty
        else { return nil }
        return Request(socketPath: socketPath, nonce: nonce, prompt: arguments.dropFirst().joined(separator: " "))
    }

    /// Asks the app for the password and writes it to stdout. Never returns.
    ///
    /// Exiting non-zero tells `ssh` that no password is available, which ends
    /// the attempt instead of falling back to some other prompt.
    static func serve(_ request: Request) -> Never {
        // ssh can give up before reading the answer, and the default response to
        // writing into a pipe nobody is reading is for the process to be killed.
        // Exiting cleanly instead means the app sees "no password available"
        // rather than a mysterious signal.
        signal(SIGPIPE, SIG_IGN)

        guard let answer = fetch(request), !answer.isEmpty else { exit(1) }

        var failed = false
        answer.withBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let written = write(
                    STDOUT_FILENO, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if written > 0 {
                    offset += written
                    continue
                }
                if written < 0 && errno == EINTR { continue }
                failed = true
                break
            }
        }

        // exit() does not run deferred blocks, so this cannot be a defer. The
        // process is about to end either way, but the plaintext should not
        // outlive its last use even by that much.
        answer.wipe()
        exit(failed ? 1 : 0)
    }

    /// Internal rather than private so the unit tests can drive the client half
    /// of the protocol without launching a second process.
    static func fetch(_ request: Request) -> SecureBuffer? {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else { return nil }
        defer { close(descriptor) }

        var noSignal: Int32 = 1
        setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSignal,
                   socklen_t(MemoryLayout<Int32>.size))

        var timeout = timeval(tv_sec: 10, tv_usec: 0)
        setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        let connected = (try? AskpassProtocol.withSocketAddress(path: request.socketPath) { address, length in
            connect(descriptor, address, length)
        }) ?? -1
        guard connected == 0 else { return nil }

        let payload = Array("\(request.nonce)\n\(request.prompt)".utf8)
        var offset = 0
        payload.withUnsafeBufferPointer { buffer in
            while offset < buffer.count {
                let written = write(descriptor, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if written > 0 {
                    offset += written
                    continue
                }
                if written < 0 && errno == EINTR { continue }
                break
            }
        }
        guard offset == payload.count else { return nil }
        shutdown(descriptor, SHUT_WR)

        // Read straight into locked memory, sized once. The password never
        // touches a growing array and is never copied on the way.
        let answer = SecureBuffer(capacity: AskpassProtocol.maxResponseBytes)
        while true {
            let received = answer.withFreeSpace { space -> Int in
                read(descriptor, space.baseAddress, space.count)
            }
            guard let received else { break }   // full
            if received > 0 {
                answer.advance(by: received)
                continue
            }
            if received == 0 { break }          // the app closed the socket
            if errno == EINTR { continue }
            answer.wipe()
            return nil
        }
        return answer
    }
}
