import Darwin
import Foundation

struct ProcessResult: Sendable {
    var exitCode: Int32
    var standardOutput: String
    var standardError: String
    var timedOut: Bool
    var outputLimitExceeded = false
}

/// Runs a fixed executable without a shell. One worker owns spawning, signalling
/// and reaping: a PID cannot be reused before this worker has stopped signalling.
enum ProcessRunner {
    static let maximumOutputBytes = 64 * 1024

    static func run(
        executable: String,
        arguments: [String],
        environment: [String: String]? = nil,
        input: Data? = nil,
        timeout: TimeInterval = 15,
        outputLimit: Int = maximumOutputBytes
    ) async throws -> ProcessResult {
        guard timeout.isFinite, timeout > 0, outputLimit > 0,
              outputLimit <= maximumOutputBytes else {
            throw POSIXError(.EINVAL)
        }
        try Task.checkCancellation()
        let cancellation = RunnerCancellation()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                DispatchQueue.global(qos: .utility).async {
                    do {
                        continuation.resume(returning: try execute(
                            executable: executable, arguments: arguments,
                            environment: environment ?? minimalEnvironment(), input: input,
                            timeout: timeout, outputLimit: outputLimit, cancellation: cancellation))
                    } catch {
                        continuation.resume(throwing: error)
                    }
                }
            }
        } onCancel: {
            cancellation.cancel()
        }
    }

    private static func execute(
        executable: String, arguments: [String], environment: [String: String],
        input: Data?, timeout: TimeInterval, outputLimit: Int,
        cancellation: RunnerCancellation
    ) throws -> ProcessResult {
        guard !cancellation.isCancelled else { throw CancellationError() }
        let strings = [executable] + arguments + environment.map { "\($0.key)=\($0.value)" }
        guard executable.hasPrefix("/"), strings.allSatisfy({ !$0.utf8.contains(0) }) else {
            throw POSIXError(.EINVAL)
        }

        var output = [-1, -1] as [Int32]
        var errors = [-1, -1] as [Int32]
        var incoming = [-1, -1] as [Int32]
        defer {
            for fd in output + errors + incoming where fd >= 0 { close(fd) }
        }
        guard pipe(&output) == 0, pipe(&errors) == 0, pipe(&incoming) == 0 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        for fd in output + errors + incoming {
            guard fcntl(fd, F_SETFD, FD_CLOEXEC) != -1 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        }
        // Nonblocking I/O keeps output draining and cancellation alive even when
        // a child ignores its input or a descendant inherits a pipe.
        for fd in [output[0], errors[0], incoming[1]] {
            guard fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) != -1 else {
                throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
            }
        }
        guard fcntl(incoming[1], F_SETNOSIGPIPE, 1) != -1 else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }

        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        func require(_ status: Int32) throws {
            guard status == 0 else { throw POSIXError(POSIXErrorCode(rawValue: status) ?? .EIO) }
        }
        try require(posix_spawn_file_actions_init(&actions))
        defer { posix_spawn_file_actions_destroy(&actions) }
        try require(posix_spawnattr_init(&attributes))
        defer { posix_spawnattr_destroy(&attributes) }
        try require(posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)))
        for (source, target) in [(incoming[0], STDIN_FILENO), (output[1], STDOUT_FILENO),
                                 (errors[1], STDERR_FILENO)] {
            try require(posix_spawn_file_actions_adddup2(&actions, source, target))
        }
        for fd in output + errors + incoming {
            try require(posix_spawn_file_actions_addclose(&actions, fd))
        }

        var argv = ([executable] + arguments).map { strdup($0) } + [nil]
        var envp = environment.map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer {
            argv.compactMap { $0 }.forEach { free($0) }
            envp.compactMap { $0 }.forEach { free($0) }
        }
        guard argv.dropLast().allSatisfy({ $0 != nil }), envp.dropLast().allSatisfy({ $0 != nil }) else {
            throw POSIXError(.ENOMEM)
        }
        var pid: pid_t = 0
        try require(posix_spawn(&pid, executable, &actions, &attributes, &argv, &envp))
        close(output[1]); output[1] = -1
        close(errors[1]); errors[1] = -1
        close(incoming[0]); incoming[0] = -1

        var outputData = Data()
        var errorData = Data()
        var inputOffset = 0
        var status: Int32?
        var timedOut = false
        var exceeded = false
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        var terminationAt: TimeInterval?
        var drainDeadline: TimeInterval?
        var sentKill = false

        func drain(_ fd: inout Int32, into data: inout Data) {
            guard fd >= 0 else { return }
            var chunk = [UInt8](repeating: 0, count: 4096)
            // Limit work per turn even if a child writes forever.
            for _ in 0..<16 {
                let count = read(fd, &chunk, chunk.count)
                if count > 0 {
                    let accepted = min(count, max(0, outputLimit - data.count))
                    data.append(contentsOf: chunk.prefix(accepted))
                    if accepted < count { exceeded = true }
                } else if count == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    close(fd); fd = -1
                    return
                } else {
                    return
                }
            }
        }

        while true {
            let now = ProcessInfo.processInfo.systemUptime
            // waitpid is only called here. Once reaped, never signal this PID.
            if status == nil {
                var raw: Int32 = 0
                let waited = waitpid(pid, &raw, WNOHANG)
                if waited == pid {
                    status = (raw & 0x7f) == 0 ? (raw >> 8) & 0xff : 128 + (raw & 0x7f)
                    drainDeadline = now + 0.25
                } else if waited == -1 && errno != EINTR {
                    // ECHILD means someone else reaped it; never signal then.
                    status = -1
                    drainDeadline = now + 0.25
                }
            }
            drain(&output[0], into: &outputData)
            drain(&errors[0], into: &errorData)
            if incoming[1] >= 0 {
                if status != nil || input == nil || inputOffset == input?.count {
                    close(incoming[1]); incoming[1] = -1
                } else if let input {
                    let written = input.withUnsafeBytes { bytes in
                        write(incoming[1], bytes.baseAddress!.advanced(by: inputOffset),
                              min(4096, bytes.count - inputOffset))
                    }
                    if written > 0 { inputOffset += written }
                    else if written < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR {
                        close(incoming[1]); incoming[1] = -1
                    }
                }
            }
            if status == nil {
                if terminationAt == nil && (now >= deadline || cancellation.isCancelled || exceeded) {
                    timedOut = now >= deadline
                    terminationAt = now
                    kill(pid, SIGTERM)
                }
                if let at = terminationAt, now - at >= 0.25, !sentKill {
                    kill(pid, SIGKILL)
                    sentKill = true
                }
            } else if (output[0] < 0 && errors[0] < 0) || now >= (drainDeadline ?? now) {
                break
            }
            // This GCD worker does not block a Swift cooperative executor.
            usleep(10_000)
        }
        if cancellation.isCancelled { throw CancellationError() }
        return ProcessResult(exitCode: status ?? -1,
                             standardOutput: String(decoding: outputData, as: UTF8.self),
                             standardError: String(decoding: errorData, as: UTF8.self),
                             timedOut: timedOut, outputLimitExceeded: exceeded)
    }

    static func minimalEnvironment() -> [String: String] {
        var environment: [String: String] = [
            "HOME": NSHomeDirectory(), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "USER": NSUserName(), "LOGNAME": NSUserName(),
            "TMPDIR": NSTemporaryDirectory(), "LANG": "en_US.UTF-8",
        ]
        if let agent = ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"] {
            environment["SSH_AUTH_SOCK"] = agent
        }
        return environment
    }
}

private final class RunnerCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    var isCancelled: Bool {
        lock.lock(); defer { lock.unlock() }
        return cancelled
    }
    func cancel() {
        lock.lock(); cancelled = true; lock.unlock()
    }
}
