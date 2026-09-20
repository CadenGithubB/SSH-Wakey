import XCTest
@testable import SSH_Wakey

final class ValidationTests: XCTestCase {

    private func connection(
        name: String = "Studio Mac",
        username: String = "admin",
        host: String = "10.0.0.4",
        port: Int = 22,
        extra: String = ""
    ) -> SSHConnection {
        SSHConnection(name: name, username: username, host: host, port: port, extraArguments: extra)
    }

    func testAValidConnectionHasNoIssues() {
        XCTAssertTrue(ConnectionValidator.isValid(connection()))
    }

    func testDisplayNameIsRequired() {
        XCTAssertEqual(ConnectionValidator.issues(in: connection(name: "")), [.emptyName])
        XCTAssertEqual(ConnectionValidator.issues(in: connection(name: "   ")), [.emptyName])
    }

    func testUsernameIsRequired() {
        XCTAssertEqual(ConnectionValidator.issues(in: connection(username: "")), [.emptyUsername])
        XCTAssertEqual(ConnectionValidator.issues(in: connection(username: "  ")), [.emptyUsername])
    }

    func testHostIsRequired() {
        XCTAssertEqual(ConnectionValidator.issues(in: connection(host: "")), [.emptyHost])
    }

    func testPortMustBeInRange() {
        XCTAssertEqual(ConnectionValidator.issues(in: connection(port: 0)), [.portOutOfRange(0)])
        XCTAssertEqual(ConnectionValidator.issues(in: connection(port: -1)), [.portOutOfRange(-1)])
        XCTAssertEqual(ConnectionValidator.issues(in: connection(port: 65536)), [.portOutOfRange(65536)])
        XCTAssertTrue(ConnectionValidator.isValid(connection(port: 1)))
        XCTAssertTrue(ConnectionValidator.isValid(connection(port: 65535)))
    }

    func testUsernamesThatCouldBeMisreadAreRejected() {
        for candidate in ["-oProxyCommand=x", "mor gan", "admin@host", "user:name", "a/b", "tab\there", "user;id", "user$(id)", "user`id`", "user%h"] {
            XCTAssertFalse(ConnectionValidator.isValidUsername(candidate), candidate)
        }
    }

    func testOrdinaryUsernamesAreAccepted() {
        for candidate in ["admin", "ci-runner", "user_1", "root", "admin.local"] {
            XCTAssertTrue(ConnectionValidator.isValidUsername(candidate), candidate)
        }
    }

    func testHostsThatCouldBeMisreadAreRejected() {
        for candidate in ["-oProxyCommand=touch /tmp/x", "host name", "user@host", "a/b", "host\nname", "host,*", "*.example.com", "host;id", "host$(id)", "host?", "host%h", "[::1]:2222", "host..local"] {
            XCTAssertFalse(ConnectionValidator.isValidHost(candidate), candidate)
        }
    }

    func testOrdinaryHostsAreAccepted() {
        for candidate in ["10.0.0.4", "mac.local", "build-01.example.internal", "fe80::1", "::1", "[::1]", "fe80::1%en0"] {
            XCTAssertTrue(ConnectionValidator.isValidHost(candidate), candidate)
        }
    }

    func testEveryProblemIsReportedAtOnce() {
        let issues = ConnectionValidator.issues(
            in: connection(name: "", username: "", host: "", port: 0))
        XCTAssertEqual(issues.count, 4)
    }

    func testBadExtraArgumentsSurfaceAsAValidationIssue() {
        let issues = ConnectionValidator.issues(in: connection(extra: "-o ProxyCommand=nc %h %p"))
        XCTAssertEqual(issues.count, 1)
        guard case .badArguments(let message) = issues.first else {
            return XCTFail("Expected .badArguments, got \(String(describing: issues.first))")
        }
        XCTAssertTrue(message.contains("run another program"), message)
    }

    func testValidationIgnoresSurroundingWhitespace() {
        XCTAssertTrue(ConnectionValidator.isValid(
            connection(name: " Studio ", username: " admin ", host: " 10.0.0.4 ")))
    }
}
