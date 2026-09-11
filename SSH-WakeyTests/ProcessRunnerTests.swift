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

    func testAHangingToolIsStoppedAtTheTimeout() async throws {
        let result = try await ProcessRunner.run(
            executable: "/bin/sleep", arguments: ["30"], timeout: 1)
        XCTAssertTrue(result.timedOut)
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
