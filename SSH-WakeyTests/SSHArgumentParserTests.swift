import XCTest
@testable import SSH_Wakey

final class SSHArgumentParserTests: XCTestCase {

    // MARK: - Tokenising

    func testEmptyTextProducesNoArguments() throws {
        XCTAssertEqual(try SSHArgumentParser.tokenize(""), [])
        XCTAssertEqual(try SSHArgumentParser.tokenize("    "), [])
    }

    func testWhitespaceSeparatesArguments() throws {
        XCTAssertEqual(try SSHArgumentParser.tokenize("-v  -4   -C"), ["-v", "-4", "-C"])
    }

    func testQuotedSectionsStayInOneArgument() throws {
        XCTAssertEqual(
            try SSHArgumentParser.tokenize("-o 'ServerAliveInterval 30'"),
            ["-o", "ServerAliveInterval 30"])
        XCTAssertEqual(
            try SSHArgumentParser.tokenize("-o \"SetEnv FOO=a b\""),
            ["-o", "SetEnv FOO=a b"])
    }

    func testBackslashEscapesTheNextCharacter() throws {
        XCTAssertEqual(try SSHArgumentParser.tokenize("-i my\\ key"), ["-i", "my key"])
    }

    func testUnterminatedQuoteIsRejected() {
        XCTAssertThrowsError(try SSHArgumentParser.tokenize("-o 'unclosed")) { error in
            XCTAssertEqual(error as? SSHArgumentParser.ParseError, .unterminatedQuote("'"))
        }
    }

    func testTrailingBackslashIsRejected() {
        XCTAssertThrowsError(try SSHArgumentParser.tokenize("-v \\")) { error in
            XCTAssertEqual(error as? SSHArgumentParser.ParseError, .trailingBackslash)
        }
    }

    /// Nothing here is expanded, so shell metacharacters are just text. This is
    /// the property that makes shell injection impossible.
    func testShellMetacharactersAreTreatedAsPlainText() throws {
        XCTAssertEqual(
            try SSHArgumentParser.tokenize("-o 'SetEnv X=$(whoami)'"),
            ["-o", "SetEnv X=$(whoami)"])
        XCTAssertEqual(try SSHArgumentParser.tokenize("-4;-C"), ["-4;-C"])
    }

    // MARK: - Validating

    func testHarmlessOptionsAreAccepted() throws {
        XCTAssertEqual(try SSHArgumentParser.parse("-v"), ["-v"])
        XCTAssertEqual(try SSHArgumentParser.parse("-vvv"), ["-vvv"])
        XCTAssertEqual(try SSHArgumentParser.parse("-4 -C"), ["-4", "-C"])
        XCTAssertEqual(
            try SSHArgumentParser.parse("-o ServerAliveInterval=30"),
            ["-o", "ServerAliveInterval=30"])
        XCTAssertEqual(try SSHArgumentParser.parse("-J jump.example.com"), ["-J", "jump.example.com"])
        XCTAssertEqual(try SSHArgumentParser.parse("-L 8080:localhost:80"), ["-L", "8080:localhost:80"])
        XCTAssertEqual(try SSHArgumentParser.parse("-i ~/.ssh/id_ed25519"), ["-i", "~/.ssh/id_ed25519"])
    }

    func testOptionsThatRunLocalProgramsAreRefused() {
        for text in [
            "-o ProxyCommand=nc %h %p",
            "-o proxycommand=/bin/sh",
            "-o PermitLocalCommand=yes",
            "-o LocalCommand=/bin/sh",
            "-o KnownHostsCommand=/bin/echo",
            "-o PKCS11Provider=/tmp/evil.dylib",
            "-o Match=exec",
            "-o Include=/tmp/other-config",
        ] {
            XCTAssertThrowsError(try SSHArgumentParser.parse(text), text) { error in
                guard case .dangerousOption = error as? SSHArgumentParser.ParseError else {
                    return XCTFail("Expected .dangerousOption for \(text), got \(error)")
                }
            }
        }
    }

    func testTrustRedirectionIsRefused() {
        XCTAssertThrowsError(try SSHArgumentParser.parse("-o UserKnownHostsFile=/dev/null"))
    }

    func testOptionsTheAppSetsItselfAreRefused() {
        for text in [
            "-o StrictHostKeyChecking=no",
            "-o ControlPath=/tmp/x",
            "-o NumberOfPasswordPrompts=5",
            "-o BatchMode=yes",
            "-p 2222",
            "-l root",
            "-M",
            "-S /tmp/sock",
            "-N",
            "-f",
        ] {
            XCTAssertThrowsError(try SSHArgumentParser.parse(text), text) { error in
                guard case .reservedOption = error as? SSHArgumentParser.ParseError else {
                    return XCTFail("Expected .reservedOption for \(text), got \(error)")
                }
            }
        }
    }

    func testAttachedValuesAreCheckedToo() {
        XCTAssertThrowsError(try SSHArgumentParser.parse("-oProxyCommand=nc")) { error in
            guard case .dangerousOption = error as? SSHArgumentParser.ParseError else {
                return XCTFail("Expected .dangerousOption, got \(error)")
            }
        }
    }

    func testAnOperandIsRefusedBecauseTheDestinationComesFromTheFields() {
        XCTAssertThrowsError(try SSHArgumentParser.parse("other.example.com")) { error in
            guard case .unexpectedOperand = error as? SSHArgumentParser.ParseError else {
                return XCTFail("Expected .unexpectedOperand, got \(error)")
            }
        }
        XCTAssertThrowsError(try SSHArgumentParser.parse("-v rm -rf /"))
    }

    func testUnknownOptionsAreRefused() {
        XCTAssertThrowsError(try SSHArgumentParser.parse("-Z")) { error in
            XCTAssertEqual(error as? SSHArgumentParser.ParseError, .unknownOption("-Z"))
        }
        XCTAssertThrowsError(try SSHArgumentParser.parse("--config=/tmp/x"))
    }

    func testAnOptionMissingItsValueIsRefused() {
        XCTAssertThrowsError(try SSHArgumentParser.parse("-o")) { error in
            XCTAssertEqual(error as? SSHArgumentParser.ParseError, .missingValue("-o"))
        }
    }

    func testEveryParseErrorExplainsItself() {
        let errors: [SSHArgumentParser.ParseError] = [
            .unterminatedQuote("'"), .trailingBackslash, .controlCharacter,
            .unexpectedOperand("x"), .missingValue("-o"), .unknownOption("-Z"),
            .reservedOption("-p"), .dangerousOption("-o proxycommand"),
        ]
        for error in errors {
            XCTAssertFalse(error.errorDescription?.isEmpty ?? true, "\(error)")
        }
    }
}
