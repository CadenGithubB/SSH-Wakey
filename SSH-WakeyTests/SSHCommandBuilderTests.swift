import XCTest
@testable import SSH_Wakey

final class SSHCommandBuilderTests: XCTestCase {

    private let connection = SSHConnection(
        name: "Studio Mac", username: "admin", host: "10.0.0.4", port: 2222,
        extraArguments: "-v -o ServerAliveInterval=30", strictHostKeyChecking: true)

    private func masterArguments(_ connection: SSHConnection) throws -> [String] {
        try SSHCommandBuilder.masterArguments(
            for: connection, controlPath: "/tmp/ctl", connectTimeout: 10,
            diagnosticLogPath: "/tmp/ssh.log", knownHostsPath: "/tmp/Application Support/known_hosts.snapshot",
            authenticatedCallbackCommand: "exec /usr/bin/true")
    }

    func testTheExecutableIsTheSystemSSH() {
        XCTAssertEqual(SSHCommandBuilder.sshExecutable, "/usr/bin/ssh")
    }

    func testMasterRunsWithNoRemoteCommandAndItsOwnControlSocket() throws {
        let arguments = try masterArguments(connection)
        XCTAssertTrue(arguments.contains("-M"))
        XCTAssertTrue(arguments.contains("-N"))
        XCTAssertTrue(arguments.contains("ControlPath=\"/tmp/ctl\""))
    }

    func testSecuritySensitiveOptionsArePresent() throws {
        let arguments = try masterArguments(connection)
        XCTAssertTrue(arguments.contains("StrictHostKeyChecking=yes"))
        XCTAssertTrue(arguments.contains("NumberOfPasswordPrompts=1"))
        XCTAssertTrue(arguments.contains("ConnectTimeout=10"))
    }

    func testMasterAndUnlockIgnoreSSHConfigAndUseOnlyTheAppKnownHostsFile() throws {
        let expectedKnownHosts = "UserKnownHostsFile=\"/tmp/Application Support/known_hosts.snapshot\""

        for arguments in [try masterArguments(connection), try unlockArguments(connection)] {
            let configIndex = try XCTUnwrap(arguments.firstIndex(of: "-F"))
            XCTAssertEqual(arguments[configIndex + 1], "/dev/null")
            XCTAssertTrue(arguments.contains("GlobalKnownHostsFile=/dev/null"))
            XCTAssertTrue(arguments.contains(expectedKnownHosts))
        }
    }

    func testLegacyTrustOnFirstUseSettingStillRequiresAnApprovedKey() throws {
        var relaxed = connection
        relaxed.strictHostKeyChecking = false
        let arguments = try masterArguments(relaxed)
        XCTAssertTrue(arguments.contains("StrictHostKeyChecking=yes"))
        XCTAssertFalse(arguments.contains("StrictHostKeyChecking=accept-new"))
        XCTAssertFalse(arguments.contains("StrictHostKeyChecking=no"))
    }

    func testUsernameAndPortArePassedAsSeparateArguments() throws {
        let arguments = try masterArguments(connection)
        let userIndex = try XCTUnwrap(arguments.firstIndex(of: "-l"))
        XCTAssertEqual(arguments[userIndex + 1], "admin")
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

    // MARK: - Unlock mode

    private func unlockArguments(_ connection: SSHConnection) throws -> [String] {
        try SSHCommandBuilder.unlockArguments(for: connection, connectTimeout: 10,
            diagnosticLogPath: "/tmp/ssh.log", knownHostsPath: "/tmp/Application Support/known_hosts.snapshot",
            authenticatedCallbackCommand: "exec /usr/bin/true")
    }

    func testUnlockingRunsNoRemoteCommandAndLeavesNothingBehind() throws {
        let arguments = try unlockArguments(connection)
        XCTAssertTrue(arguments.contains("-N"))
        XCTAssertFalse(arguments.contains("-M"), "nothing is going to attach, so no master")
        XCTAssertFalse(arguments.contains { $0.hasPrefix("ControlPath=") })
    }

    func testBothModesUseFixedAuthenticatedCallbackBeforeDefaultProhibition() throws {
        for arguments in [try unlockArguments(connection), try masterArguments(connection)] {
            let firstPermit = try XCTUnwrap(arguments.first { $0.hasPrefix("PermitLocalCommand=") })
            XCTAssertEqual(firstPermit, "PermitLocalCommand=yes")
            XCTAssertTrue(arguments.contains("LocalCommand=exec /usr/bin/true"))
            XCTAssertTrue(arguments.contains("LogLevel=VERBOSE"))
        }
        let attach = SSHCommandBuilder.attachArguments(for: connection, controlPath: "/tmp/ctl")
        XCTAssertEqual(attach.first { $0.hasPrefix("PermitLocalCommand=") }, "PermitLocalCommand=no")
        XCTAssertFalse(attach.contains { $0.hasPrefix("LocalCommand=") })
    }

    func testUnlockingKeepsTheSameSecurityOptions() throws {
        let arguments = try unlockArguments(connection)
        XCTAssertTrue(arguments.contains("StrictHostKeyChecking=yes"))
        XCTAssertTrue(arguments.contains("NumberOfPasswordPrompts=1"))
        XCTAssertEqual(arguments.last, "10.0.0.4")

        let userIndex = try XCTUnwrap(arguments.firstIndex(of: "-l"))
        XCTAssertEqual(arguments[userIndex + 1], "admin")
    }

    func testUnlockingStillRefusesDangerousExtraArguments() {
        var risky = connection
        risky.extraArguments = "-o ProxyCommand=/bin/sh"
        XCTAssertThrowsError(try unlockArguments(risky))
    }

    func testTheModesAreDescribedAndStableOnDisk() {
        XCTAssertEqual(ConnectMode.allCases.count, 2)
        // The raw values are saved on each connection, so they must not drift.
        XCTAssertEqual(ConnectMode.unlock.rawValue, "unlock")
        XCTAssertEqual(ConnectMode.session.rawValue, "session")
        for mode in ConnectMode.allCases {
            XCTAssertFalse(mode.title.isEmpty)
            XCTAssertFalse(mode.explanation.isEmpty)
            XCTAssertFalse(mode.buttonTitle.isEmpty)
        }
        XCTAssertEqual(ConnectMode.unlock.title, "Connect, wake, then disconnect")
        XCTAssertEqual(ConnectMode.unlock.buttonTitle, "Wake")
        XCTAssertEqual(ConnectMode.session.buttonTitle, "Connect")
        XCTAssertEqual(SSHConnection().connectMode, .unlock)
        XCTAssertEqual(
            ConnectMode.unlock.idleHeadline(destination: "admin@mac.local"),
            "Ready to wake admin@mac.local via SSH.")
        XCTAssertTrue(ConnectMode.unlock.idleGuidance.contains("then disconnects"))
    }

    func testControlCommandsTargetTheSameSocket() {
        let arguments = SSHCommandBuilder.controlArguments(
            for: connection, controlPath: "/tmp/ctl", command: "check")
        XCTAssertTrue(arguments.contains("ControlPath=\"/tmp/ctl\""))
        XCTAssertTrue(arguments.contains("-F"))
        XCTAssertTrue(arguments.contains("GlobalKnownHostsFile=/dev/null"))
        let commandIndex = arguments.firstIndex(of: "-O")
        XCTAssertNotNil(commandIndex)
        XCTAssertEqual(arguments[commandIndex! + 1], "check")
    }

    func testAbandonedControlCleanupUsesTheSameIsolation() {
        let arguments = SSHCommandBuilder.abandonedControlArguments(controlPath: "/tmp/ctl")
        XCTAssertTrue(arguments.contains("-F"))
        XCTAssertTrue(arguments.contains("GlobalKnownHostsFile=/dev/null"))
        XCTAssertTrue(arguments.contains("ControlPath=\"/tmp/ctl\""))
        XCTAssertTrue(arguments.contains("abandoned-session"))
    }

    func testTheTerminalSessionAttachesRatherThanBecomingASecondMaster() {
        let arguments = SSHCommandBuilder.attachArguments(for: connection, controlPath: "/tmp/ctl")
        XCTAssertTrue(arguments.contains("ControlMaster=no"))
        XCTAssertTrue(arguments.contains("BatchMode=yes"))
        XCTAssertTrue(arguments.contains("ProxyCommand=/usr/bin/false"))
        XCTAssertTrue(arguments.contains("-F"))
        XCTAssertTrue(arguments.contains("GlobalKnownHostsFile=/dev/null"))
        XCTAssertFalse(arguments.contains("-M"))
        XCTAssertFalse(arguments.contains("-N"))
        XCTAssertEqual(arguments.last, "10.0.0.4")
    }
    func testAuthenticationPolicyIsFixedAndInternalLogsAreSeparate() throws {
        for arguments in [try masterArguments(connection), try unlockArguments(connection)] {
            for required in ["HostKeyAlgorithms=ssh-ed25519", "VerifyHostKeyDNS=no",
                             "UpdateHostKeys=no", "ForwardAgent=no", "ForwardX11=no",
                             "ClearAllForwardings=yes", "GSSAPIDelegateCredentials=no", "AddKeysToAgent=no"] {
                XCTAssertTrue(arguments.contains(required), required)
            }
            let logFlag = try XCTUnwrap(arguments.firstIndex(of: "-E"))
            XCTAssertEqual(arguments[logFlag + 1], "/tmp/ssh.log")
        }
    }

    func testSSHParsesSnapshotPathWithSpacesAsOneTrustFile() throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        let snapshot = "/private/tmp/Application Support/audit-known-hosts"
        process.arguments = ["-G"] + (try SSHCommandBuilder.unlockArguments(
            for: connection, connectTimeout: 10, diagnosticLogPath: "/dev/null", knownHostsPath: snapshot,
            authenticatedCallbackCommand: "exec /usr/bin/true"))
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        let text = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
        XCTAssertTrue(text.split(separator: "\n").contains("userknownhostsfile \(snapshot)"), text)
    }

}
