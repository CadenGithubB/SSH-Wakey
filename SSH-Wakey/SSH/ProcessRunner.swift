import Foundation

struct ProcessResult: Sendable {
    var exitCode: Int32
    var standardOutput: String
    var standardError: String
    var timedOut: Bool
}

/// Runs a short-lived tool and collects its output.
///
/// Used for `ssh -O check`, `ssh-keyscan` and `ssh-keygen -l`. None of those
/// ever receive a secret in their arguments, and nothing here goes through a
/// shell.
enum ProcessRunner {

    static func run(
        executable: String,
        arguments: [String],
        environment: [String: String]? = nil,
        input: Data? = nil,
        timeout: TimeInterval = 15
    ) async throws -> ProcessResult {

        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = environment ?? minimalEnvironment()

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe

        let inputPipe = Pipe()
        process.standardInput = input == nil ? FileHandle.nullDevice : inputPipe

        let exit = ExitWaiter()
        process.terminationHandler = { finished in exit.complete(finished.terminationStatus) }

        try process.run()

        if let input {
            inputPipe.fileHandleForWriting.write(input)
            try? inputPipe.fileHandleForWriting.close()
        }

        // Read both pipes while the process runs so a chatty tool cannot fill a
        // pipe buffer and deadlock.
        let outputTask = Task.detached { outputPipe.fileHandleForReading.readDataToEndOfFile() }
        let errorTask = Task.detached { errorPipe.fileHandleForReading.readDataToEndOfFile() }

        let timeoutTask = Task {
            try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
            guard !Task.isCancelled else { return }
            if process.isRunning {
                exit.markTimedOut()
                process.terminate()
            }
        }

        let status = await exit.wait()
        timeoutTask.cancel()

        let outputData = await outputTask.value
        let errorData = await errorTask.value

        return ProcessResult(
            exitCode: status,
            standardOutput: String(decoding: outputData, as: UTF8.self),
            standardError: String(decoding: errorData, as: UTF8.self),
            timedOut: exit.timedOut)
    }

    /// A deliberately small environment. Inheriting the app's own environment
    /// would be a way for something unexpected to influence a child process.
    static func minimalEnvironment() -> [String: String] {
        var environment: [String: String] = [
            "HOME": NSHomeDirectory(),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "USER": NSUserName(),
            "LOGNAME": NSUserName(),
            "TMPDIR": NSTemporaryDirectory(),
            "LANG": "en_US.UTF-8",
        ]
        // Passed through so an already-unlocked SSH agent can authenticate and
        // the typed password is never needed at all.
        if let agent = ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"] {
            environment["SSH_AUTH_SOCK"] = agent
        }
        return environment
    }
}

/// Bridges `Process.terminationHandler` to async/await without losing an exit
/// that happens before anyone starts waiting.
private final class ExitWaiter: @unchecked Sendable {
    private let lock = NSLock()
    private var status: Int32?
    private var continuation: CheckedContinuation<Int32, Never>?
    private var didTimeOut = false

    var timedOut: Bool {
        lock.lock(); defer { lock.unlock() }
        return didTimeOut
    }

    func markTimedOut() {
        lock.lock(); didTimeOut = true; lock.unlock()
    }

    func complete(_ value: Int32) {
        lock.lock()
        if let waiting = continuation {
            continuation = nil
            lock.unlock()
            waiting.resume(returning: value)
        } else {
            status = value
            lock.unlock()
        }
    }

    func wait() async -> Int32 {
        await withCheckedContinuation { continuation in
            lock.lock()
            if let value = status {
                lock.unlock()
                continuation.resume(returning: value)
            } else {
                self.continuation = continuation
                lock.unlock()
            }
        }
    }
}
