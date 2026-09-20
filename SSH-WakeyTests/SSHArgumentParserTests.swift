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
        XCTAssertEqual(try SSHArgumentParser.parse("-4 -6"), ["-4", "-6"])
        XCTAssertEqual(
            try SSHArgumentParser.parse("-o ServerAliveInterval=30"),
            ["-o", "ServerAliveInterval=30"])
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
            "-J jump.example.com",
            "-Jjump.example.com",
            "-vJ jump.example.com",
            "-F /tmp/evil-config",
            "-F/tmp/evil-config",
            "-F",
            "-vF /tmp/evil-config",
            "-I /tmp/evil.dylib",
            "-I/tmp/evil.dylib",
            "-vI /tmp/evil.dylib",
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

    /// The keyword check is an allow list. A perfectly real ssh option that is
    /// not on it is refused, so an option nobody has vetted cannot ride along.
    func testKeywordsOutsideTheAllowListAreRefused() {
        for text in ["-o SetEnv=X=1", "-o RemoteCommand=/bin/sh", "-o EscapeChar=none"] {
            XCTAssertThrowsError(try SSHArgumentParser.parse(text), text) { error in
                guard case .unsupportedKeyword = error as? SSHArgumentParser.ParseError else {
                    return XCTFail("Expected .unsupportedKeyword for \(text), got \(error)")
                }
            }
        }
    }

    /// A safe, useful option on the allow list still passes.
    func testAllowedKeywordsPass() throws {
        XCTAssertEqual(
            try SSHArgumentParser.parse("-o AddressFamily=inet6"),
            ["-o", "AddressFamily=inet6"])
        XCTAssertEqual(
            try SSHArgumentParser.parse("-o IdentitiesOnly=yes"),
            ["-o", "IdentitiesOnly=yes"])
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
            "-q",
            "-o LogLevel=QUIET",
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
            .unsupportedKeyword("-o setenv"), .invalidValue("-i"),
        ]
        for error in errors {
            XCTAssertFalse(error.errorDescription?.isEmpty ?? true, "\(error)")
        }
    }
    func testForwardingDelegationAgentMutationAndCryptoOverridesAreRefused() {
        for text in [
            "-A", "-Y", "-X", "-K", "-y", "-L 8080:localhost:80",
            "-R 9000:localhost:22", "-D 1080", "-g", "-w 1:1",
            "-c aes128-cbc", "-m hmac-sha1", "-o AddKeysToAgent=yes",
            "-o PreferredAuthentications=hostbased", "-o GSSAPIAuthentication=yes",
            "-o IdentityFile=/tmp/key", "-o Ciphers=aes128-cbc", "-o KexAlgorithms=+diffie-hellman-group1-sha1",
            "-o HostKeyAlgorithms=+ssh-rsa", "-o ProxyJump=jump.invalid",
            "-o VerifyHostKeyDNS=yes", "-o UpdateHostKeys=yes",
        ] { XCTAssertThrowsError(try SSHArgumentParser.parse(text), text) }
    }

    func testAllowedValuesAreBoundedAndCannotCarryAnotherDirective() throws {
        for text in [
            "-o ServerAliveInterval=-1", "-o ServerAliveInterval=3601",
            "-o ServerAliveCountMax=0", "-o ServerAliveCountMax=11",
            "-o ConnectionAttempts=4", "-o TCPKeepAlive=maybe",
            "-o AddressFamily=unix", "-o 'ServerAliveInterval=1 ProxyCommand=/bin/sh'",
            "-o 'ServerAliveInterval=1\nProxyCommand=/bin/sh'", "-i '%h/key'", "-i '$HOME/key'",
        ] { XCTAssertThrowsError(try SSHArgumentParser.parse(text), text) }
        XCTAssertEqual(try SSHArgumentParser.parse("-o 'ServerAliveInterval 30'"), ["-o", "ServerAliveInterval 30"])
    }

}
