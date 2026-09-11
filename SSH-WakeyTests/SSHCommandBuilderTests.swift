import XCTest
@testable import SSH_Wakey

final class SSHCommandBuilderTests: XCTestCase {

    private let connection = SSHConnection(
        name: "Studio Mac", username: "morgan", host: "10.0.0.4", port: 2222,
        extraArguments: "-v -o ServerAliveInterval=30", strictHostKeyChecking: true)

    private func masterArguments(_ connection: SSHConnection) throws -> [String] {
        try SSHCommandBuilder.masterArguments(
            for: connection, controlPath: "/tmp/ctl", connectTimeout: 10)
    }

    func testTheExecutableIsTheSystemSSH() {
        XCTAssertEqual(SSHCommandBuilder.sshExecutable, "/usr/bin/ssh")
    }

    func testMasterRunsWithNoRemoteCommandAndItsOwnControlSocket() throws {
        let arguments = try masterArguments(connection)
        XCTAssertTrue(arguments.contains("-M"))
        XCTAssertTrue(arguments.contains("-N"))
        XCTAssertTrue(arguments.contains("ControlPath=/tmp/ctl"))
    }

    func testSecuritySensitiveOptionsArePresent() throws {
        let arguments = try masterArguments(connection)
        XCTAssertTrue(arguments.contains("StrictHostKeyChecking=yes"))
        XCTAssertTrue(arguments.contains("NumberOfPasswordPrompts=1"))
        XCTAssertTrue(arguments.contains("ConnectTimeout=10"))
    }

    func testTurningOffStrictCheckingStillRefusesAChangedKey() throws {
        var relaxed = connection
        relaxed.strictHostKeyChecking = false
        let arguments = try masterArguments(relaxed)
        XCTAssertTrue(arguments.contains("StrictHostKeyChecking=accept-new"))
        XCTAssertFalse(arguments.contains("StrictHostKeyChecking=no"))
    }

    func testUsernameAndPortArePassedAsSeparateArguments() throws {
        let arguments = try masterArguments(connection)
        let userIndex = try XCTUnwrap(arguments.firstIndex(of: "-l"))
        XCTAssertEqual(arguments[userIndex + 1], "morgan")
        let portIndex = try XCTUnwrap(arguments.firstIndex(of: "-p"))
        XCTAssertEqual(arguments[portIndex + 1], "2222")
    }

    func testTheHostIsTheFinalArgument() throws {
        XCTAssertEqual(try masterArguments(connection).last, "10.0.0.4")
    }

    func testExtraArgumentsAreInsertedBeforeTheHost() throws {
        let arguments = try masterArguments(connection)
        let verboseIndex = try XCTUnwrap(arguments.firstIndex(of: "-v"))
        XCTAssertLessThan(verboseIndex, arguments.count - 1)
        XCTAssertTrue(arguments.contains("ServerAliveInterval=30"))
    }

    func testDangerousExtraArgumentsStopTheCommandFromBeingBuilt() {
        var risky = connection
        risky.extraArguments = "-o ProxyCommand=/bin/sh"
        XCTAssertThrowsError(try masterArguments(risky))
    }

    func testNoArgumentIsAShellStringOrCarriesASecret() throws {
        let arguments = try masterArguments(connection)
        for argument in arguments {
            XCTAssertFalse(argument.contains(";"), argument)
            XCTAssertFalse(argument.contains("|"), argument)
            XCTAssertFalse(argument.lowercased().contains("password="), argument)
        }
    }

    func testControlCommandsTargetTheSameSocket() {
        let arguments = SSHCommandBuilder.controlArguments(
            for: connection, controlPath: "/tmp/ctl", command: "check")
        XCTAssertTrue(arguments.contains("ControlPath=/tmp/ctl"))
        let commandIndex = arguments.firstIndex(of: "-O")
        XCTAssertNotNil(commandIndex)
        XCTAssertEqual(arguments[commandIndex! + 1], "check")
    }

    func testTheTerminalSessionAttachesRatherThanBecomingASecondMaster() {
        let arguments = SSHCommandBuilder.attachArguments(for: connection, controlPath: "/tmp/ctl")
        XCTAssertTrue(arguments.contains("ControlMaster=no"))
        XCTAssertFalse(arguments.contains("-M"))
        XCTAssertFalse(arguments.contains("-N"))
        XCTAssertEqual(arguments.last, "10.0.0.4")
    }
}
