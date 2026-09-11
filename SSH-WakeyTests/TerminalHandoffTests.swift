import XCTest
@testable import SSH_Wakey

final class TerminalHandoffTests: XCTestCase {

    private let connection = SSHConnection(
        name: "Studio Mac", username: "admin", host: "10.0.0.4", port: 2222)

    func testTheScriptAttachesToTheExistingSession() {
        let script = TerminalHandoff.scriptContents(for: connection, controlPath: "/tmp/ctl")
        XCTAssertTrue(script.contains("ControlPath=/tmp/ctl"))
        XCTAssertTrue(script.contains("ControlMaster=no"))
        XCTAssertTrue(script.contains("/usr/bin/ssh"))
    }

    func testTheScriptDeletesItselfBeforeConnecting() {
        let script = TerminalHandoff.scriptContents(for: connection, controlPath: "/tmp/ctl")
        let removeLine = try? XCTUnwrap(script.split(separator: "\n").firstIndex { $0.contains("rm -f") })
        let execLine = try? XCTUnwrap(script.split(separator: "\n").firstIndex { $0.hasPrefix("exec ") })
        XCTAssertNotNil(removeLine)
        XCTAssertNotNil(execLine)
        if let removeLine, let execLine { XCTAssertLessThan(removeLine, execLine) }
    }

    /// The comment lines mention the word "password" on purpose, so the check
    /// is against the part that actually runs, plus the protocol values that
    /// would let anything reuse the password channel.
    func testTheScriptNeverCarriesACredential() {
        let script = TerminalHandoff.scriptContents(for: connection, controlPath: "/tmp/ctl")

        let executable = script
            .split(separator: "\n")
            .filter { !$0.hasPrefix("#") }
            .joined(separator: "\n")
            .lowercased()
        XCTAssertFalse(executable.contains("password"), executable)
        XCTAssertFalse(executable.contains("askpass"), executable)

        XCTAssertFalse(script.contains(AskpassProtocol.socketEnvironmentKey))
        XCTAssertFalse(script.contains(AskpassProtocol.nonceEnvironmentKey))
        XCTAssertFalse(script.contains("SSH_ASKPASS"))
    }

    func testEveryValueInTheScriptIsQuoted() {
        let awkward = SSHConnection(
            name: "Odd", username: "admin", host: "10.0.0.4", port: 22)
        let script = TerminalHandoff.scriptContents(for: awkward, controlPath: "/tmp/a b/ctl")
        XCTAssertTrue(script.contains("'ControlPath=/tmp/a b/ctl'"))
        XCTAssertTrue(script.contains("'10.0.0.4'"))
    }

    func testSingleQuotesAreEscapedRatherThanEndingTheQuoting() {
        XCTAssertEqual(TerminalHandoff.shellQuote("plain"), "'plain'")
        XCTAssertEqual(TerminalHandoff.shellQuote("it's"), "'it'\\''s'")
        XCTAssertEqual(TerminalHandoff.shellQuote("a b"), "'a b'")
        XCTAssertEqual(TerminalHandoff.shellQuote("$(whoami)"), "'$(whoami)'")
    }
}
