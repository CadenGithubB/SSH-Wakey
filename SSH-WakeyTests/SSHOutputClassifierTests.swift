import XCTest
@testable import SSH_Wakey

/// The strings here are the diagnostics OpenSSH actually prints. The point of
/// the classifier is that the window explains what happened instead of showing
/// an exit code.
final class SSHOutputClassifierTests: XCTestCase {

    private func kind(_ stderr: String, exitCode: Int32 = 255) -> SSHFailure.Kind {
        SSHOutputClassifier.classify(exitCode: exitCode, standardError: stderr).kind
    }

    func testAuthenticationFailure() {
        XCTAssertEqual(kind("morgan@10.0.0.4: Permission denied (publickey,password)."), .authentication)
        XCTAssertEqual(kind("Received disconnect from 10.0.0.4 port 22:2: Too many authentication failures"), .authentication)
    }

    func testAServerThatOnlyAcceptsKeys() {
        XCTAssertEqual(kind("morgan@10.0.0.4: Permission denied (publickey)."), .passwordNotOffered)
    }

    func testConnectionRefused() {
        XCTAssertEqual(kind("ssh: connect to host 10.0.0.4 port 22: Connection refused"), .connectionRefused)
    }

    func testTimeout() {
        XCTAssertEqual(kind("ssh: connect to host 10.0.0.4 port 22: Operation timed out"), .timeout)
    }

    func testUnreachableHost() {
        XCTAssertEqual(kind("ssh: connect to host 10.0.0.4 port 22: No route to host"), .hostUnreachable)
    }

    func testNameResolution() {
        XCTAssertEqual(kind("ssh: Could not resolve hostname studio.lan: nodename nor servname provided"), .nameResolution)
    }

    func testUnknownHostKey() {
        let stderr = """
        No ED25519 host key is known for 10.0.0.4 and you have requested strict checking.
        Host key verification failed.
        """
        XCTAssertEqual(kind(stderr), .hostKeyUnknown)
    }

    func testChangedHostKeyIsNeverTreatedAsMerelyUnknown() {
        let stderr = """
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        Host key verification failed.
        """
        XCTAssertEqual(kind(stderr), .hostKeyChanged)
    }

    func testABadExtraArgument() {
        XCTAssertEqual(kind("command-line: line 0: Bad configuration option: nonsense"), .badOption)
    }

    func testUnrecognisedOutputStillProducesSomethingUseful() {
        let failure = SSHOutputClassifier.classify(exitCode: 255, standardError: "something odd happened")
        XCTAssertEqual(failure.kind, .unknown)
        XCTAssertTrue(failure.headline.contains("255"))
        XCTAssertEqual(failure.detail, "something odd happened")
    }

    func testOnlyTheRightFailuresOfferFollowUpActions() {
        let unknownKey = SSHOutputClassifier.classify(
            exitCode: 255, standardError: "Host key verification failed.")
        XCTAssertTrue(unknownKey.offersHostKeyReview)

        let refused = SSHOutputClassifier.classify(
            exitCode: 255, standardError: "ssh: connect to host x port 22: Connection refused")
        XCTAssertTrue(refused.offersBootHelp)
        XCTAssertFalse(refused.offersHostKeyReview)

        let auth = SSHOutputClassifier.classify(
            exitCode: 255, standardError: "Permission denied (password).")
        XCTAssertFalse(auth.offersBootHelp)
        XCTAssertFalse(auth.offersHostKeyReview)
    }

    func testEveryClassificationExplainsWhatToDoNext() {
        let samples = [
            "Permission denied (publickey,password).",
            "ssh: connect to host x port 22: Connection refused",
            "ssh: connect to host x port 22: Operation timed out",
            "Host key verification failed.",
            "REMOTE HOST IDENTIFICATION HAS CHANGED!",
            "Could not resolve hostname x: nodename nor servname provided",
        ]
        for sample in samples {
            let failure = SSHOutputClassifier.classify(exitCode: 255, standardError: sample)
            XCTAssertFalse(failure.headline.isEmpty, sample)
            XCTAssertFalse(failure.guidance?.isEmpty ?? true, sample)
        }
    }
}
