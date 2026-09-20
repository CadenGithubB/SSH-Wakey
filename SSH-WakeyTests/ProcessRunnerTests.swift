import XCTest
@testable import SSH_Wakey

final class ProcessRunnerTests: XCTestCase {

    func testOutputAndExitCodeAreCaptured() async throws {
        let result = try await ProcessRunner.run(
            executable: "/bin/echo", arguments: ["hello", "world"])
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertEqual(result.standardOutput.trimmingCharacters(in: .whitespacesAndNewlines), "hello world")
        XCTAssertFalse(result.timedOut)
    }

    func testAFailingToolReportsItsStatus() async throws {
        let result = try await ProcessRunner.run(executable: "/usr/bin/false", arguments: [])
        XCTAssertNotEqual(result.exitCode, 0)
    }

    func testStandardInputIsDelivered() async throws {
        let result = try await ProcessRunner.run(
            executable: "/bin/cat", arguments: [], input: Data("piped".utf8))
        XCTAssertEqual(result.standardOutput, "piped")
    }

    func testInputAndOutputArePumpedTogetherBeyondAPipeBuffer() async throws {
        let input = Data(repeating: 65, count: 32_000)
        let result = try await ProcessRunner.run(executable: "/bin/cat", arguments: [], input: input)
        XCTAssertEqual(Data(result.standardOutput.utf8), input)
        XCTAssertFalse(result.outputLimitExceeded)
    }

    func testAChildClosingItsInputDoesNotRaiseSIGPIPEInTheApp() async throws {
        let result = try await ProcessRunner.run(executable: "/usr/bin/true", arguments: [],
                                                input: Data(repeating: 65, count: 1_000_000))
        XCTAssertEqual(result.exitCode, 0)
    }

    func testEmbeddedNULArgumentsAreRefusedInsteadOfTruncated() async {
        do {
            _ = try await ProcessRunner.run(executable: "/bin/echo", arguments: ["safe\0hidden"])
            XCTFail("an argument with a NUL byte was accepted")
        } catch {
            XCTAssertEqual((error as? POSIXError)?.code, .EINVAL)
        }
    }

    func testAHangingToolIsStoppedAtTheTimeout() async throws {
        let result = try await ProcessRunner.run(
            executable: "/bin/sleep", arguments: ["30"], timeout: 1)
        XCTAssertTrue(result.timedOut)
    }

    func testAChildIgnoringTerminationIsKilledWithinABoundedTime() async throws {
        let began = Date()
        let result = try await ProcessRunner.run(
            executable: "/bin/sh", arguments: ["-c", "trap '' TERM; exec /bin/sleep 30"],
            timeout: 0.1)
        XCTAssertTrue(result.timedOut)
        XCTAssertEqual(result.exitCode, 128 + SIGKILL)
        XCTAssertLessThan(Date().timeIntervalSince(began), 2)
    }

    func testCancellationStopsTheChildAndThrows() async throws {
        let began = Date()
        let task = Task {
            try await ProcessRunner.run(executable: "/bin/sleep", arguments: ["30"])
        }
        try await Task.sleep(nanoseconds: 50_000_000)
        task.cancel()
        do {
            _ = try await task.value
            XCTFail("cancellation must not return an ordinary successful result")
        } catch is CancellationError {
            XCTAssertLessThan(Date().timeIntervalSince(began), 2)
        }
    }

    func testUnendingOutputIsCappedAndStopsTheChild() async throws {
        let result = try await ProcessRunner.run(
            executable: "/usr/bin/yes", arguments: ["bounded"], outputLimit: 1024)
        XCTAssertTrue(result.outputLimitExceeded)
        XCTAssertLessThanOrEqual(result.standardOutput.utf8.count, 1024)
        XCTAssertNotEqual(result.exitCode, 0)
    }

    func testStderrHasItsOwnOutputLimit() async throws {
        let result = try await ProcessRunner.run(
            executable: "/bin/sh", arguments: ["-c", "exec /usr/bin/yes bounded >&2"],
            outputLimit: 1024)
        XCTAssertTrue(result.outputLimitExceeded)
        XCTAssertLessThanOrEqual(result.standardError.utf8.count, 1024)
        XCTAssertTrue(result.standardOutput.isEmpty)
    }

    func testAnInheritedPipeDoesNotKeepTheRunnerWaitingAfterTheChildExits() async throws {
        let began = Date()
        let result = try await ProcessRunner.run(
            executable: "/bin/sh", arguments: ["-c", "/bin/sleep 2 & exit 0"])
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertLessThan(Date().timeIntervalSince(began), 1.5)
    }

    func testAChildIgnoringInputCannotBlockItsTimeout() async throws {
        let began = Date()
        let result = try await ProcessRunner.run(
            executable: "/bin/sleep", arguments: ["30"],
            input: Data(repeating: 65, count: 1_000_000), timeout: 0.1)
        XCTAssertTrue(result.timedOut)
        XCTAssertLessThan(Date().timeIntervalSince(began), 2)
    }

    func testInvalidTimeoutsAreRejectedBeforeLaunching() async {
        for timeout in [0, -1, .nan, .infinity] as [TimeInterval] {
            do {
                _ = try await ProcessRunner.run(executable: "/usr/bin/true", arguments: [], timeout: timeout)
                XCTFail("invalid timeout was accepted")
            } catch {
                XCTAssertEqual((error as? POSIXError)?.code, .EINVAL)
            }
        }
    }

    /// Arguments are an array all the way down, so a value that looks like
    /// shell syntax stays a single argument.
    func testArgumentsAreNeverInterpretedByAShell() async throws {
        let result = try await ProcessRunner.run(
            executable: "/bin/echo", arguments: ["a; touch /tmp/ssh-wakey-should-not-exist"])
        XCTAssertTrue(result.standardOutput.contains("; touch"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: "/tmp/ssh-wakey-should-not-exist"))
    }

    func testTheChildEnvironmentIsSmallAndCarriesNoAppState() {
        let environment = ProcessRunner.minimalEnvironment()
        XCTAssertNotNil(environment["HOME"])
        XCTAssertNotNil(environment["PATH"])
        XCTAssertNil(environment[AskpassProtocol.socketEnvironmentKey])
        XCTAssertNil(environment[AskpassProtocol.nonceEnvironmentKey])
        XCTAssertNil(environment["SSH_ASKPASS"])
    }
}
