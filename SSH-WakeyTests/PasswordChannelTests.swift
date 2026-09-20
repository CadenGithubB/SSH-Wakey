import Darwin
import XCTest
@testable import SSH_Wakey

/// The app channel carries authorization metadata only. Ordinary runs display no
/// password popup. The explicit manual UI audit also uses only synthetic data;
/// no test uses real credentials or connects to a network destination.
final class PasswordChannelTests: XCTestCase {
    private var directory: URL!
    private var channels: [AskpassChannel] = []
    private let context = AskpassProtocol.Context(destination: "test-user@audit.invalid", action: "Wake")

    override func setUpWithError() throws {
        directory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .resolvingSymlinksInPath().appendingPathComponent("apT-\(UUID().uuidString.prefix(8))")
        try ProtectedFile.createPrivateDirectory(at: directory)
    }
    override func tearDownWithError() throws {
        channels.forEach { $0.invalidate() }
        channels = []
        try? FileManager.default.removeItem(at: directory)
    }
    private func makeChannel() throws -> AskpassChannel {
        let child = directory.appendingPathComponent(String(channels.count))
        let channel = try AskpassChannel(context: context, directory: child)
        channels.append(channel)
        return channel
    }
    private func identity(pid: pid_t, parent: pid_t, path: String, uid: uid_t = getuid(),
                          started: UInt64 = 1) -> ProcessIdentity {
        ProcessIdentity(pid: pid, parent: parent, uid: uid,
                        startedSeconds: started, startedMicroseconds: 0, path: path)
    }

    func testOnlyTheExpectedSSHChildAndItsDirectHelperSatisfyTheRelationship() {
        let ssh = identity(pid: 20, parent: 10, path: "/usr/bin/ssh")
        let helper = identity(pid: 30, parent: 20, path: "/app/SSH-Wakey")
        XCTAssertTrue(AskpassChannel.isExpectedHelper(helper, ssh: ssh, appPID: 10, helperPath: helper.path))
        let attacker = identity(pid: 31, parent: 99, path: helper.path)
        XCTAssertFalse(AskpassChannel.isExpectedHelper(attacker, ssh: ssh, appPID: 10, helperPath: helper.path))
    }
    func testTheRightExecutableWithAReplayedEnvironmentIsNotEnough() {
        let ssh = identity(pid: 20, parent: 10, path: "/usr/bin/ssh")
        let replay = identity(pid: 30, parent: 10, path: "/app/SSH-Wakey")
        XCTAssertFalse(AskpassChannel.isExpectedHelper(replay, ssh: ssh, appPID: 10, helperPath: replay.path))
    }
    func testWrongUserOrSSHOwnerIsRejected() {
        let helper = identity(pid: 30, parent: 20, path: "/app/SSH-Wakey")
        let wrongUser = identity(pid: 20, parent: 10, path: "/usr/bin/ssh", uid: getuid() + 1)
        let wrongParent = identity(pid: 20, parent: 99, path: "/usr/bin/ssh")
        for ssh in [wrongUser, wrongParent] {
            XCTAssertFalse(AskpassChannel.isExpectedHelper(helper, ssh: ssh, appPID: 10, helperPath: helper.path))
        }
    }
    func testAnotherExecutableCannotStandInForAppleSSH() {
        let ssh = identity(pid: 20, parent: 10, path: "/tmp/ssh")
        let helper = identity(pid: 30, parent: 20, path: "/app/SSH-Wakey")
        XCTAssertFalse(AskpassChannel.isExpectedHelper(helper, ssh: ssh, appPID: 10, helperPath: helper.path))
        XCTAssertFalse(ssh.isAppleSSH)
    }
    func testKernelIdentityIncludesStartTimeAndCorrectParent() throws {
        let current = try XCTUnwrap(ProcessIdentity.read(getpid()))
        XCTAssertEqual(current.parent, getppid())
        XCTAssertEqual(current.uid, getuid())
        XCTAssertTrue(current.isCurrent)
        let stale = identity(pid: current.pid, parent: current.parent, path: current.path,
                             started: current.startedSeconds + 1)
        XCTAssertFalse(stale.isCurrent)
        XCTAssertNil(ProcessIdentity.read(0))
        XCTAssertNil(ProcessIdentity.read(-1))
    }
    func testNonSSHChildCannotBeRegistered() throws {
        let channel = try makeChannel()
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/bin/sleep")
        child.arguments = ["5"]
        try child.run()
        defer { child.terminate(); child.waitUntilExit() }
        XCTAssertThrowsError(try channel.registerSSHProcess(child))
        XCTAssertFalse(channel.outcome.served)
    }
    func testARealHelperLaunchedByTheAppRefusesReplayedAuthorizationBeforeUI() async throws {
        let channel = try makeChannel()
        var environment = ProcessRunner.minimalEnvironment()
        environment.merge(channel.environmentAdditions()) { _, new in new }
        let result = try await ProcessRunner.run(
            executable: HelperLayout.adapterPath,
            arguments: ["test-user@audit.invalid's password: "], environment: environment, timeout: 3)
        XCTAssertNotEqual(result.exitCode, 0)
        XCTAssertFalse(result.timedOut, "replay must fail before it can display a popup")
        XCTAssertTrue(result.standardOutput.isEmpty)
        XCTAssertFalse(channel.outcome.served)
        XCTAssertNil(channel.outcome.promptedAt)
    }
    func testMainExecutableCannotFallBackToUnsandboxedPasswordEntry() async throws {
        let channel = try makeChannel()
        var environment = ProcessRunner.minimalEnvironment()
        environment.merge(channel.environmentAdditions()) { _, new in new }
        let result = try await ProcessRunner.run(executable: try XCTUnwrap(Bundle.main.executablePath),
            arguments: ["Password:"], environment: environment, timeout: 3)
        XCTAssertEqual(result.exitCode, 1)
        XCTAssertFalse(result.timedOut)
        XCTAssertTrue(result.standardOutput.isEmpty)
        XCTAssertNil(channel.outcome.promptedAt)
    }
    func testCodeDescriptorMustNameTheExpectedExecutableAndBeReadOnly() throws {
        let executable = try XCTUnwrap(Bundle.main.executableURL).resolvingSymlinksInPath()
        let handle = try FileHandle(forReadingFrom: executable)
        defer { try? handle.close() }
        XCTAssertEqual(HelperIdentity.requirement(from: handle, expectedExecutable: executable),
                       HelperIdentity.requirement(at: Bundle.main.bundleURL))
        XCTAssertNil(HelperIdentity.requirement(from: handle, expectedExecutable: URL(fileURLWithPath: "/bin/false")))
        let copy = directory.appendingPathComponent("executable")
        try FileManager.default.copyItem(at: executable, to: copy)
        let writable = try FileHandle(forUpdating: copy)
        defer { try? writable.close() }
        XCTAssertNil(HelperIdentity.requirement(from: writable, expectedExecutable: copy))
        let pipe = Pipe()
        XCTAssertNil(HelperIdentity.requirement(from: pipe.fileHandleForReading, expectedExecutable: executable))
    }
    func testMissingOrUnsignedHelperCannotCreateAnAuthorizationChannel() throws {
        for helper in [directory.appendingPathComponent("Missing.app/Contents/MacOS/helper"),
                       directory.appendingPathComponent("Unsigned.app/Contents/MacOS/helper")] {
            try FileManager.default.createDirectory(at: helper.deletingLastPathComponent(), withIntermediateDirectories: true)
            if helper.path.contains("Unsigned") { try Data("unsigned".utf8).write(to: helper) }
            XCTAssertThrowsError(try AskpassChannel(context: context,
                directory: directory.appendingPathComponent("bad"), helperPath: helper.path))
        }
    }
    func testTheSocketAndItsFolderArePrivate() throws {
        let channel = try makeChannel()
        let path = try XCTUnwrap(channel.environmentAdditions()[AskpassProtocol.socketEnvironmentKey])
        let socket = try FileManager.default.attributesOfItem(atPath: path)
        let folder = try FileManager.default.attributesOfItem(atPath: URL(fileURLWithPath: path).deletingLastPathComponent().path)
        XCTAssertEqual((socket[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        XCTAssertEqual((folder[.posixPermissions] as? NSNumber)?.intValue, 0o700)
    }
    func testInvalidatingEventuallyRemovesTheSocketAndIsIdempotent() throws {
        let channel = try makeChannel()
        let path = try XCTUnwrap(channel.environmentAdditions()[AskpassProtocol.socketEnvironmentKey])
        channel.invalidate(); channel.invalidate()
        let removed = expectation(for: NSPredicate { _, _ in !FileManager.default.fileExists(atPath: path) }, evaluatedWith: nil)
        wait(for: [removed], timeout: 2)
    }
    func testTheEnvironmentCarriesOnlyAuthorizationIdentifiers() throws {
        let channel = try makeChannel()
        let environment = channel.environmentAdditions()
        XCTAssertEqual(Set(environment.keys), ["SSH_ASKPASS", "SSH_ASKPASS_REQUIRE",
                        AskpassProtocol.socketEnvironmentKey, AskpassProtocol.nonceEnvironmentKey])
        XCTAssertEqual(environment["SSH_ASKPASS_REQUIRE"], "force")
        XCTAssertFalse(environment.values.contains(context.destination))
        XCTAssertFalse(Mirror(reflecting: channel).children.contains { $0.label == "password" })
    }
    func testEveryAttemptHasAnIndependent256BitNonce() throws {
        let first = try makeChannel(), second = try makeChannel()
        XCTAssertEqual(first.nonce.utf8.count, 64)
        XCTAssertNotEqual(first.nonce, second.nonce)
    }
    func testOnlyOnePromptCanBeReservedEvenWhenSubmissionFails() {
        var outcome = AskpassChannel.Outcome()
        XCTAssertTrue(outcome.reservePrompt(at: 10))
        XCTAssertFalse(outcome.served)
        for time in [11.0, 12, 13] { XCTAssertFalse(outcome.reservePrompt(at: time)) }
        XCTAssertEqual(outcome.promptedAt, 10)
        XCTAssertEqual(outcome.repeatedPrompts, 3)
    }
    func testCancellationPreventsAFirstPromptReservation() {
        var outcome = AskpassChannel.Outcome(); outcome.cancelled = true
        XCTAssertFalse(outcome.reservePrompt(at: 1))
        XCTAssertNil(outcome.promptedAt)
    }
    func testAStaticAskpassPromptCannotSelectAuthenticationCallbackMode() {
        XCTAssertTrue(AskpassHelper.isAuthenticationCallback(arguments:
            ["app", "--ssh-wakey-authenticated", "--post-authentication"]))
        for arguments in [["app", "--ssh-wakey-authenticated"],
                          ["app", "--ssh-wakey-authenticated --post-authentication"],
                          ["app", "--post-authentication", "--ssh-wakey-authenticated"],
                          ["app", "--ssh-wakey-authenticated", "--post-authentication", "extra"]] {
            XCTAssertFalse(AskpassHelper.isAuthenticationCallback(arguments: arguments))
        }
    }
    func testTheAuthenticationCallbackCannotBeReplayedByTheApp() async throws {
        let channel = try makeChannel()
        var environment = ProcessRunner.minimalEnvironment()
        environment.merge(channel.environmentAdditions()) { _, new in new }
        let result = try await ProcessRunner.run(executable: HelperLayout.adapterPath,
            arguments: ["--ssh-wakey-authenticated", "--post-authentication"], environment: environment, timeout: 3)
        XCTAssertNotEqual(result.exitCode, 0)
        XCTAssertFalse(result.timedOut)
        XCTAssertFalse(channel.outcome.authenticated)
    }
    func testRealSSHAuthenticatesTheSignedCallbackOverLocalPipesWithSyntheticKeys() async throws {
        try await exerciseRealSSH(manualPopup: ProcessInfo.processInfo.environment["SSHWAKEY_HELPER_UI_SMOKE"] == "1")
    }
    func testSandboxDeniesUnrelatedFilesAndNewNetworkConnectionsButAllowsPassedChannels() async throws {
        try await exerciseRealSSH(sandboxProbe: true)
    }
    private func exerciseRealSSH(manualPopup: Bool = false, sandboxProbe: Bool = false) async throws {
        // sshd inetd mode consumes stdin/stdout: no listening socket, service
        // configuration, actual saved key, password or remote host is involved.
        for name in ["host_key", "client_key"] {
            let generated = try await ProcessRunner.run(executable: "/usr/bin/ssh-keygen",
                arguments: ["-q", "-t", "ed25519", "-N", "", "-f", directory.appendingPathComponent(name).path])
            XCTAssertEqual(generated.exitCode, 0)
        }
        let publicKey = try Data(contentsOf: directory.appendingPathComponent("client_key.pub"))
        try ProtectedFile.write(publicKey, to: directory.appendingPathComponent("authorized_keys"))
        let hostKey = try String(contentsOf: directory.appendingPathComponent("host_key.pub"), encoding: .utf8)
            .split(separator: " ").prefix(2).joined(separator: " ")
        try ProtectedFile.write(Data("audit.invalid \(hostKey)\n".utf8),
                                to: directory.appendingPathComponent("known_hosts"))
        let config = """
        HostKey \(directory.appendingPathComponent("host_key").path)
        AuthorizedKeysFile \(directory.appendingPathComponent("authorized_keys").path)
        StrictModes no
        PasswordAuthentication no
        KbdInteractiveAuthentication no
        UsePAM no
        UseDNS no
        AllowUsers \(NSUserName())
        PermitUserRC no
        PermitUserEnvironment no
        DisableForwarding yes
        ForceCommand /usr/bin/true
        LogLevel DEBUG1

        """
        let configuration = directory.appendingPathComponent("sshd_config")
        try ProtectedFile.write(Data(config.utf8), to: configuration)
        // Explicit local UI audit only. Ordinary test runs never show a popup.
        // SSH has already authenticated using the disposable key. Its fixed
        // LocalCommand then exercises the genuine helper/parent authorization
        // with a synthetic destination; submitted text goes to a test pipe and is discarded.
        let channel = try makeChannel()
        let helper = HelperLayout.adapterPath
        if manualPopup { print("SSHWAKEY_UI_HELPER_PATH=\(helper)") }
        if sandboxProbe {
            try ProtectedFile.write(Data("synthetic sandbox fixture".utf8),
                to: directory.appendingPathComponent("sandbox-fixture"))
        }
        let quotedHelper = helper.replacingOccurrences(of: "%", with: "%%")
            .replacingOccurrences(of: "'", with: "'\\''")
        let localCommand = sandboxProbe ? "exec '\(quotedHelper)' --ssh-wakey-sandbox-check --diagnostic-only"
            : manualPopup ? "exec '\(quotedHelper)' 'Password:'"
            : AskpassHelper.authenticationCommand(helperPath: helper)
        let transportLog = directory.appendingPathComponent("synthetic-transport.log")
        try ProtectedFile.write(Data(), to: transportLog)
        let transportOutput = try FileHandle(forWritingTo: transportLog)
        defer { try? transportOutput.close() }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        process.arguments = ["-v", "-F", "/dev/null", "-N", "-T",
            "-o", "ProxyCommand=/usr/sbin/sshd -i -e -f '\(configuration.path)'",
            "-o", "UserKnownHostsFile=\(directory.appendingPathComponent("known_hosts").path)",
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=yes",
            "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-i", directory.appendingPathComponent("client_key").path,
            "-o", "PermitLocalCommand=yes", "-o", "LocalCommand=\(localCommand)",
            "\(NSUserName())@audit.invalid"]
        var environment = ProcessRunner.minimalEnvironment()
        environment.merge(channel.environmentAdditions()) { _, new in new }
        process.environment = environment
        process.standardInput = FileHandle.nullDevice
        let passwordPipe = Pipe()
        process.standardOutput = passwordPipe
        // This read end belongs only to the synthetic test, not the main app's
        // normal password flow. Never print or persist submitted text.
        passwordPipe.fileHandleForReading.readabilityHandler = { handle in
            _ = handle.availableData
        }
        defer { passwordPipe.fileHandleForReading.readabilityHandler = nil }
        process.standardError = transportOutput
        try process.run()
        defer {
            channel.invalidate()
            if process.isRunning { process.terminate() }
            // Bound cleanup even if a system component unexpectedly stalls.
            let cleanupDeadline = Date().addingTimeInterval(1)
            while process.isRunning && Date() < cleanupDeadline { usleep(10_000) }
        }
        try channel.registerSSHProcess(process)
        if manualPopup || sandboxProbe {
            let deadline = Date().addingTimeInterval(manualPopup ? 90 : 15)
            while !channel.outcome.served && !channel.outcome.cancelled && process.isRunning && Date() < deadline {
                try await Task.sleep(nanoseconds: 20_000_000)
            }
            let finalOutcome = channel.outcome
            print("SSHWAKEY_UI_STATUS served=\(finalOutcome.served) cancelled=\(finalOutcome.cancelled) wrongProgramAttempts=\(finalOutcome.wrongProgramAttempts)")
            XCTAssertNotNil(channel.outcome.promptedAt, "the authenticated helper did not open its native popup")
            XCTAssertTrue(channel.outcome.served || channel.outcome.cancelled,
                          "manual UI audit timed out; cleanup cancels the popup")
            XCTAssertFalse(channel.outcome.authenticated, "one password argument must not select the status callback")
            XCTAssertEqual(channel.outcome.wrongProgramAttempts, 0)
            if sandboxProbe {
                let replyDeadline = Date().addingTimeInterval(1)
                var diagnostic = try String(contentsOf: transportLog, encoding: .utf8)
                while !diagnostic.contains("SSHWAKEY_SANDBOX_") && Date() < replyDeadline {
                    try await Task.sleep(nanoseconds: 10_000_000)
                    diagnostic = try String(contentsOf: transportLog, encoding: .utf8)
                }
                XCTAssertTrue(finalOutcome.served, diagnostic)
                XCTAssertTrue(diagnostic.contains("SSHWAKEY_SANDBOX_OK"), diagnostic)
            }
            return
        }
        let deadline = Date().addingTimeInterval(5)
        while !channel.outcome.authenticated && Date() < deadline {
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        let diagnostic = (try? ProtectedFile.read(from: transportLog, maximumBytes: 64 * 1024))
            .map { String(decoding: $0, as: UTF8.self) } ?? "No bounded synthetic transport log"
        XCTAssertTrue(channel.outcome.authenticated,
                      "trusted callback was rejected: \(channel.outcome)\n\(diagnostic)")
        XCTAssertFalse(channel.outcome.served, "key authentication must never display the password popup")
        XCTAssertNil(channel.outcome.promptedAt)
        XCTAssertEqual(channel.outcome.wrongProgramAttempts, 0)
    }
    func testAuthenticationCommandQuotesAnExecutablePathForTheLocalShell() async throws {
        let executable = directory.appendingPathComponent("quote' $(touch UNEXPECTED-CALLBACK-FILE) `false`")
        try ProtectedFile.write(Data("#!/bin/sh\n/usr/bin/printf '%s\\n' \"$@\"\n".utf8), to: executable, mode: 0o700)
        let result = try await ProcessRunner.run(executable: "/bin/sh",
            arguments: ["-c", AskpassHelper.authenticationCommand(helperPath: executable.path)])
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertEqual(result.standardOutput, "--ssh-wakey-authenticated\n--post-authentication\n")
        XCTAssertFalse(FileManager.default.fileExists(atPath: "UNEXPECTED-CALLBACK-FILE"))
    }
    func testAuthenticationCommandEscapesOpenSSHPercentTokensBeforeShellParsing() {
        let command = AskpassHelper.authenticationCommand(helperPath: "/tmp/100%/app%n")
        XCTAssertTrue(command.contains("100%%/app%%n"))
    }
    func testNonceComparisonRejectsWrongLengthAndWrongContent() {
        let nonce = String(repeating: "a", count: 64)
        XCTAssertTrue(AskpassProtocol.constantTimeEquals(nonce, nonce))
        for value in ["", "a", nonce + "a", String(repeating: "b", count: 64)] {
            XCTAssertFalse(AskpassProtocol.constantTimeEquals(nonce, value))
        }
    }
    func testPromptFilteringCannotAuthorizeAHostKeyOrPrivateKeyPrompt() {
        XCTAssertTrue(AskpassProtocol.looksLikePasswordPrompt("Password:"))
        XCTAssertTrue(AskpassProtocol.looksLikePasswordPrompt("user@host's password: "))
        for prompt in ["", "Verification code:", "Enter passphrase for key:",
                       "password yes/no", "password fingerprint", "password (y/n)"] {
            XCTAssertFalse(AskpassProtocol.looksLikePasswordPrompt(prompt), prompt)
        }
    }
    func testPasswordProtocolRejectsNewlinesNULAndExcessBytes() {
        for password in ["", "a\nb", "a\rb", "a\0b", String(repeating: "a", count: 1023)] {
            XCTAssertFalse(AskpassProtocol.validPassword(password))
        }
        XCTAssertTrue(AskpassProtocol.validPassword(String(repeating: "a", count: 1022)))
        XCTAssertTrue(AskpassProtocol.validPassword("pässwörd✓"))
        XCTAssertFalse(AskpassProtocol.validPassword(String(repeating: "é", count: 512)))
    }
    func testMalformedEnvironmentAndOversizedPromptAreRejected() {
        XCTAssertNil(AskpassHelper.requestFromEnvironment(environment: [:], arguments: ["app"]))
        let valid = [AskpassProtocol.socketEnvironmentKey: "/tmp/fixture",
                     AskpassProtocol.nonceEnvironmentKey: String(repeating: "a", count: 64)]
        XCTAssertNil(AskpassHelper.requestFromEnvironment(environment: valid, arguments: ["app"]))
        XCTAssertNil(AskpassHelper.requestFromEnvironment(environment: valid,
                                                         arguments: ["app", String(repeating: "p", count: 2048)]))
        var bad = valid; bad[AskpassProtocol.nonceEnvironmentKey] = "short"
        XCTAssertNil(AskpassHelper.requestFromEnvironment(environment: bad, arguments: ["app", "Password:"]))
        XCTAssertNotNil(AskpassHelper.requestFromEnvironment(environment: valid, arguments: ["app", "Password:"]))
    }
    func testMetadataEncodingIsBoundedAndRejectsMalformedJSON() {
        XCTAssertNil(AskpassProtocol.encode(String(repeating: "a", count: AskpassProtocol.maxRequestBytes)))
        XCTAssertNil(AskpassProtocol.decode(AskpassProtocol.Message.self, "garbage"))
    }
    func testSocketFramingRejectsARequestWithoutANewlineBeforeItsDeadline() throws {
        var sockets: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer { close(sockets[0]); close(sockets[1]) }
        let bytes = Data("unterminated".utf8)
        XCTAssertTrue(bytes.withUnsafeBytes { AskpassProtocol.writeAll(sockets[0], $0) })
        let started = Date()
        XCTAssertNil(AskpassProtocol.readLine(from: sockets[1], timeout: 0.05))
        XCTAssertLessThan(Date().timeIntervalSince(started), 1)
    }
    func testSocketFramingPreservesJSONWithoutTreatingItAsAShellCommand() throws {
        var sockets: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets), 0)
        defer { close(sockets[0]); close(sockets[1]) }
        let value = "$(ignored); 'literal'"
        XCTAssertTrue(AskpassProtocol.sendLine(value, to: sockets[0]))
        XCTAssertEqual(AskpassProtocol.readLine(from: sockets[1]), value)
    }
}

final class PasswordChannelReportingTests: XCTestCase {
    private let failure = SSHFailure(kind: .authentication, headline: "Authentication failed.",
                                     guidance: "Check the username and password.", detail: nil)
    @MainActor func testAnUneventfulAttemptAddsNothing() {
        XCTAssertEqual(SSHSessionManager.annotated(failure, with: AskpassChannel.Outcome(served: true)).guidance,
                       failure.guidance)
    }
    @MainActor func testARepeatedPromptIsExplained() {
        var outcome = AskpassChannel.Outcome(); outcome.served = true; outcome.repeatedPrompts = 1
        let annotated = SSHSessionManager.annotated(failure, with: outcome)
        XCTAssertTrue(annotated.guidance?.contains("password again") ?? false)
        XCTAssertTrue(annotated.guidance?.contains("failed logins") ?? false)
    }
    func testServerPromptTextDoesNotAppearInTheSummary() {
        var outcome = AskpassChannel.Outcome(); outcome.refusedPrompts = ["synthetic-password-reflected-by-server"]
        XCTAssertFalse(outcome.summary.contains("synthetic-password"))
        XCTAssertTrue(outcome.summary.contains("unsupported authentication prompt refused"))
    }
    @MainActor func testUnauthorizedRequestsAreReported() {
        var token = AskpassChannel.Outcome(); token.wrongNonceAttempts = 1
        var user = AskpassChannel.Outcome(); user.wrongUserAttempts = 1
        var program = AskpassChannel.Outcome(); program.wrongProgramAttempts = 1
        for outcome in [token, user, program] {
            XCTAssertTrue(SSHSessionManager.annotated(failure, with: outcome).guidance?.contains("was refused") ?? false)
        }
    }
}
