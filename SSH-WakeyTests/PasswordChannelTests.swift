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
    private func makeChannel(mayRelease: @escaping @Sendable () -> Bool = { true }) throws -> AskpassChannel {
        let child = directory.appendingPathComponent(String(channels.count))
        let channel = try AskpassChannel(context: context, directory: child, mayRelease: mayRelease)
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
    func testCodeDescriptorRequirementPreservesOffsetAndRemovesTemporaryCopy() throws {
        let executable = try XCTUnwrap(Bundle.main.executableURL).resolvingSymlinksInPath()
        let expectedRequirement = try XCTUnwrap(HelperIdentity.requirement(at: Bundle.main.bundleURL))
        let temporaryDirectory = directory.appendingPathComponent("code-copy", isDirectory: true)
        try ProtectedFile.createPrivateDirectory(at: temporaryDirectory)
        let handle = try FileHandle(forReadingFrom: executable)
        defer { try? handle.close() }
        try handle.seek(toOffset: 17)

        XCTAssertEqual(HelperIdentity.requirement(from: handle, expectedExecutable: executable,
                                                temporaryDirectory: temporaryDirectory), expectedRequirement)
        XCTAssertEqual(try handle.offset(), 17)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: temporaryDirectory.path).isEmpty)
        let attributes = try FileManager.default.attributesOfItem(atPath: temporaryDirectory.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o700)
    }
    func testMalformedOrUnsignedCodeDescriptorRemovesTemporaryCopy() throws {
        let temporaryDirectory = directory.appendingPathComponent("code-copy", isDirectory: true)
        try ProtectedFile.createPrivateDirectory(at: temporaryDirectory)
        let fixtures = [Data([0, 1, 2, 3, 4]), Data("#!/bin/sh\nexit 0\n".utf8)]
        for (index, bytes) in fixtures.enumerated() {
            let executable = directory.appendingPathComponent("unsigned-\(index)")
            try ProtectedFile.write(bytes, to: executable, mode: 0o700)
            let handle = try FileHandle(forReadingFrom: executable)
            defer { try? handle.close() }
            try handle.seek(toOffset: 1)

            XCTAssertNil(HelperIdentity.requirement(from: handle, expectedExecutable: executable,
                                                  temporaryDirectory: temporaryDirectory))
            XCTAssertEqual(try handle.offset(), 1)
            XCTAssertEqual(try Data(contentsOf: executable), bytes)
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: temporaryDirectory.path).isEmpty)
        }
    }
    func testEmptyAndOversizedCodeDescriptorsAreRejectedWithoutTemporaryCopies() throws {
        let temporaryDirectory = directory.appendingPathComponent("code-copy", isDirectory: true)
        try ProtectedFile.createPrivateDirectory(at: temporaryDirectory)
        let oversizedLength = UInt64(HelperIdentity.maximumExecutableBytes) + 1
        for (index, length) in [UInt64(0), oversizedLength].enumerated() {
            let executable = directory.appendingPathComponent("invalid-size-\(index)")
            try ProtectedFile.write(Data(), to: executable)
            let writer = try FileHandle(forUpdating: executable)
            // Extending an empty file creates a sparse fixture without allocating
            // a large byte buffer or using any real executable content.
            try writer.truncate(atOffset: length)
            try writer.close()
            let handle = try FileHandle(forReadingFrom: executable)
            defer { try? handle.close() }

            XCTAssertNil(HelperIdentity.requirement(from: handle, expectedExecutable: executable,
                                                  temporaryDirectory: temporaryDirectory))
            XCTAssertEqual(try handle.offset(), 0)
            let attributes = try FileManager.default.attributesOfItem(atPath: executable.path)
            XCTAssertEqual((attributes[.size] as? NSNumber)?.uint64Value, length)
            XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: temporaryDirectory.path).isEmpty)
        }
    }
    func testUnavailableCodeCopyDirectoryLeavesSourceIntact() throws {
        let bundleExecutable = try XCTUnwrap(Bundle.main.executableURL).resolvingSymlinksInPath()
        let executable = directory.appendingPathComponent("signed-executable")
        try FileManager.default.copyItem(at: bundleExecutable, to: executable)
        let originalBytes = try Data(contentsOf: executable)
        let temporaryDirectory = directory.appendingPathComponent("blocked-code-copy")
        let blocker = Data("synthetic temporary directory blocker".utf8)
        try ProtectedFile.write(blocker, to: temporaryDirectory)
        let handle = try FileHandle(forReadingFrom: executable)
        defer { try? handle.close() }
        try handle.seek(toOffset: 17)

        XCTAssertNil(HelperIdentity.requirement(from: handle, expectedExecutable: executable,
                                              temporaryDirectory: temporaryDirectory))
        XCTAssertEqual(try handle.offset(), 17)
        XCTAssertEqual(try Data(contentsOf: executable), originalBytes)
        XCTAssertEqual(try Data(contentsOf: temporaryDirectory), blocker)
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
    func testAHelperFailureIsReportedApartFromCancellation() {
        var outcome = AskpassChannel.Outcome(); outcome.helperFailed = true
        XCTAssertTrue(outcome.summary.contains("password helper failed"), outcome.summary)
        XCTAssertFalse(outcome.summary.contains("cancelled"), outcome.summary)
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
    /// The service's real submit path with a synthetic answer in place of the
    /// popup: exactly the answer and a newline reach ssh's pipe, then it exits.
    func testTheServiceWritesExactlyTheAnswerAndANewlineAfterTheAppSaysSend() async throws {
        try await exerciseRealSSH(syntheticDelivery: .released)
    }
    func testTheServiceWritesNothingWhenTheAppWithholdsSend() async throws {
        try await exerciseRealSSH(syntheticDelivery: .withheld)
    }
    private enum SyntheticDelivery { case released, withheld }
    private func exerciseRealSSH(manualPopup: Bool = false, sandboxProbe: Bool = false,
                                 syntheticDelivery: SyntheticDelivery? = nil) async throws {
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
        let channel = try makeChannel(mayRelease: { syntheticDelivery != .withheld })
        let helper = HelperLayout.adapterPath
        if manualPopup { print("SSHWAKEY_UI_HELPER_PATH=\(helper)") }
        if sandboxProbe {
            try ProtectedFile.write(Data("synthetic sandbox fixture".utf8),
                to: directory.appendingPathComponent("sandbox-fixture"))
        }
        let quotedHelper = helper.replacingOccurrences(of: "%", with: "%%")
            .replacingOccurrences(of: "'", with: "'\\''")
        let localCommand = sandboxProbe ? "exec '\(quotedHelper)' --ssh-wakey-sandbox-check --diagnostic-only"
            : syntheticDelivery != nil ? "exec '\(quotedHelper)' --ssh-wakey-delivery-check --diagnostic-only"
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
        // normal password flow. Never print or persist submitted text. Only
        // the synthetic delivery check keeps its fixed synthetic answer.
        let received = ReceivedBytes()
        let keepsBytes = syntheticDelivery != nil
        passwordPipe.fileHandleForReading.readabilityHandler = { handle in
            let chunk = handle.availableData
            if keepsBytes { received.append(chunk) }
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
        if let syntheticDelivery {
            let deadline = Date().addingTimeInterval(15)
            var diagnostic = ""
            while !diagnostic.contains("SSHWAKEY_DELIVERY_EXIT") && process.isRunning && Date() < deadline {
                try await Task.sleep(nanoseconds: 20_000_000)
                diagnostic = (try? String(contentsOf: transportLog, encoding: .utf8)) ?? ""
            }
            // Pipe reads are asynchronous; allow the last chunk to arrive.
            let drained = Date().addingTimeInterval(0.5)
            while Date() < drained && received.bytes.count < 17 { try await Task.sleep(nanoseconds: 10_000_000) }
            XCTAssertNotNil(channel.outcome.promptedAt, diagnostic)
            XCTAssertFalse(channel.outcome.helperFailed, diagnostic)
            switch syntheticDelivery {
            case .released:
                XCTAssertTrue(diagnostic.contains("SSHWAKEY_DELIVERY_EXIT 0"), diagnostic)
                XCTAssertTrue(channel.outcome.served)
                XCTAssertEqual(received.bytes, Data("synthetic-answer\n".utf8))
            case .withheld:
                XCTAssertTrue(diagnostic.contains("SSHWAKEY_DELIVERY_EXIT 1"), diagnostic)
                XCTAssertFalse(channel.outcome.served)
                XCTAssertTrue(received.bytes.isEmpty, "no bytes may reach ssh without the app's go-ahead")
            }
            return
        }
        if manualPopup || sandboxProbe {
            let deadline = Date().addingTimeInterval(manualPopup ? 90 : 15)
            while !channel.outcome.served && !channel.outcome.cancelled && process.isRunning && Date() < deadline {
                try await Task.sleep(nanoseconds: 20_000_000)
            }
            let finalOutcome = channel.outcome
            print("SSHWAKEY_UI_STATUS served=\(finalOutcome.served) cancelled=\(finalOutcome.cancelled) wrongProgramAttempts=\(finalOutcome.wrongProgramAttempts)")
            XCTAssertNotNil(channel.outcome.promptedAt, "the authenticated helper did not open its native popup")
            XCTAssertFalse(channel.outcome.helperFailed,
                           "the password helper chain stopped before the service replied")
            XCTAssertTrue(channel.outcome.served || channel.outcome.cancelled || channel.outcome.helperFailed,
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
    func testOpenSSHConfirmationAndNotificationInvocationsAreRefused() {
        let valid = [AskpassProtocol.socketEnvironmentKey: "/tmp/fixture",
                     AskpassProtocol.nonceEnvironmentKey: String(repeating: "a", count: 64)]
        for label in ["confirm", "none", ""] {
            var labelled = valid; labelled["SSH_ASKPASS_PROMPT"] = label
            XCTAssertNil(AskpassHelper.requestFromEnvironment(environment: labelled, arguments: ["app", "Password:"]),
                         label)
        }
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
        XCTAssertTrue(annotated.guidance?.contains("does not prove the password was rejected") ?? false)
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

/// Collects only the synthetic delivery check's fixed answer.
private final class ReceivedBytes: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()
    func append(_ chunk: Data) { lock.lock(); data.append(chunk); lock.unlock() }
    var bytes: Data { lock.lock(); defer { lock.unlock() }; return data }
}


final class FileVaultReportingTests: XCTestCase {
    @MainActor func testTrustContinuationPreservesOriginalBaselineAndTimeline() async {
        let manager = SSHSessionManager(checkReadiness: { _, _ in 5900 })
        let connection = SSHConnection(name: "Synthetic", username: "tester", host: "test.example")
        manager.beginAttemptTrace(connection, mode: .unlock, continuingTrust: false)
        let baselineAt = Date(timeIntervalSince1970: 1_000)
        manager.observeBaseline(connection.id, responded: false, at: baselineAt)
        manager.retainHostTrustContinuation(connection.id)
        manager.beginAttemptTrace(connection, mode: .unlock, continuingTrust: true)
        XCTAssertEqual(manager.initialScreenSharingObservation(connection.id), false)
        var channel = AskpassChannel.Outcome(served: true, authenticated: true)
        channel.servedAt = Date(timeIntervalSince1970: 2_000)
        channel.authenticatedAt = Date(timeIntervalSince1970: 2_001)
        await manager.finishWake(connection, mode: .unlock, loginConfirmed: true, channel: channel,
                                 screenSharingRespondedBeforeSSH: manager.initialScreenSharingObservation(connection.id))
        let events = manager.diagnostics.last?.events ?? []
        XCTAssertEqual(events.filter { $0.message.contains("initial check") }.map(\.at), [baselineAt])
        XCTAssertTrue(events.contains { $0.message.contains("original attempt") })
        XCTAssertTrue(events.contains { $0.at == channel.servedAt && $0.message.contains("Password submitted") })
        XCTAssertTrue(events.contains { $0.at == channel.authenticatedAt && $0.message.contains("verified callback") })
        XCTAssertEqual(events.map(\.at), events.map(\.at).sorted())
    }

    @MainActor func testFreshWakeAndChangedDestinationDiscardTrustBaseline() {
        for changed in [false, true] {
            let manager = SSHSessionManager()
            var connection = SSHConnection(name: "Synthetic", username: "tester", host: "test.example")
            manager.beginAttemptTrace(connection, mode: .unlock, continuingTrust: false)
            manager.observeBaseline(connection.id, responded: true)
            manager.retainHostTrustContinuation(connection.id)
            if changed { connection.host = "other.example" }
            manager.beginAttemptTrace(connection, mode: .unlock, continuingTrust: changed)
            XCTAssertNil(manager.initialScreenSharingObservation(connection.id))
        }
    }

    @MainActor func testLockAndTrustCancellationDiscardContinuation() {
        for lock in [false, true] {
            let manager = SSHSessionManager()
            let connection = SSHConnection(name: "Synthetic", username: "tester", host: "test.example")
            manager.beginAttemptTrace(connection, mode: .unlock, continuingTrust: false)
            manager.observeBaseline(connection.id, responded: true)
            manager.retainHostTrustContinuation(connection.id)
            if lock { manager.setAppLocked(true); manager.setAppLocked(false) }
            else { manager.discardHostTrustContinuation(connection.id) }
            manager.beginAttemptTrace(connection, mode: .unlock, continuingTrust: true)
            XCTAssertNil(manager.initialScreenSharingObservation(connection.id))
        }
    }

    func testDiagnosticTimelineIsBoundedAndExportedWithoutRawOutput() {
        let events = (0..<50).map { DiagnosticEvent(at: Date(timeIntervalSince1970: Double($0)), message: "Synthetic observation") }
        let entry = DiagnosticEntry(at: Date(), connectionID: UUID(), connection: "Synthetic", destination: "test.example",
            mode: "Wake", result: "Ready", channel: "No password", output: "server-controlled secret", events: events)
        XCTAssertEqual(entry.events.count, 32)
        let report = DiagnosticsReport.text(entries: [entry], connectionCount: 1, isEncrypted: false)
        XCTAssertTrue(report.contains("Synthetic observation"))
        XCTAssertFalse(report.contains("server-controlled secret"))
    }

    @MainActor func testOnlyAmbiguousExitAfterPasswordCanBeAnUnlockHandoff() {
        for kind in [SSHFailure.Kind.unknown, .closedByRemote] {
            let failure = SSHFailure(kind: kind, headline: "Synthetic exit", guidance: nil, detail: nil)
            XCTAssertTrue(SSHSessionManager.mayHaveUnlocked(failure: failure, outcome: .init(served: true)))
            XCTAssertFalse(SSHSessionManager.mayHaveUnlocked(failure: failure, outcome: .init()))
            var outcome = AskpassChannel.Outcome(served: true)
            outcome.authenticated = true
            XCTAssertFalse(SSHSessionManager.mayHaveUnlocked(failure: failure, outcome: outcome))
            outcome.authenticated = false
            outcome.helperFailed = true
            XCTAssertFalse(SSHSessionManager.mayHaveUnlocked(failure: failure, outcome: outcome))
        }
    }

    @MainActor func testExplicitFailuresAreNeverReportedAsPossibleUnlocks() {
        for kind in [SSHFailure.Kind.authentication, .passwordNotOffered, .hostKeyChanged,
                     .hostKeyUnknown, .helperFailed, .cancelled, .timeout, .connectionRefused,
                     .hostUnreachable, .nameResolution, .invalidConnection, .badOption,
                     .launchFailed, .askpassRefused] {
            let failure = SSHFailure(kind: kind, headline: "Synthetic failure", guidance: nil, detail: nil)
            XCTAssertFalse(SSHSessionManager.mayHaveUnlocked(failure: failure, outcome: .init(served: true)))
        }
    }

    @MainActor func testEveryCompletedWakeChecksReadinessIncludingVerifiedLogin() async {
        for authenticated in [false, true] {
            var checks = 0
            let manager = SSHSessionManager(checkReadiness: { host, port in
                XCTAssertEqual(host, "test.example")
                XCTAssertEqual(port, 2222)
                checks += 1
                return 5900
            })
            let connection = SSHConnection(name: "Synthetic", username: "tester", host: "test.example", port: 2222)
            await manager.finishWake(connection, mode: .unlock, loginConfirmed: authenticated,
                                     channel: .init(served: true))
            XCTAssertEqual(checks, 1)
            guard case .wakeResult(let result) = manager.state(for: connection.id) else { return XCTFail() }
            XCTAssertEqual(result.loginConfirmed, authenticated)
            XCTAssertEqual(result.reachablePort, 5900)
            XCTAssertFalse(manager.state(for: connection.id).isConnected)
            XCTAssertEqual(manager.activeSessionCount, 0)
            XCTAssertTrue(manager.diagnostics.last?.result.contains("FileVault unlock not verified") ?? false)
        }
    }

    @MainActor func testReadinessTimeoutRemainsUnconfirmed() async {
        let manager = SSHSessionManager(checkReadiness: { _, _ in nil })
        let connection = SSHConnection(name: "Synthetic", username: "tester", host: "test.example")
        await manager.finishWake(connection, mode: .unlock, loginConfirmed: false, channel: .init(served: true))
        guard case .wakeResult(let result) = manager.state(for: connection.id) else { return XCTFail() }
        XCTAssertNil(result.reachablePort)
        XCTAssertFalse(result.loginConfirmed)
        XCTAssertFalse(result.desktopReady)
        XCTAssertTrue(result.headline.contains("hasn’t responded"))
        XCTAssertTrue(manager.diagnostics.last?.result.contains("No service answered") ?? false)
    }

    @MainActor func testLockDuringReadinessCannotPublishOldResult() async {
        var manager: SSHSessionManager!
        manager = SSHSessionManager(checkReadiness: { _, _ in
            manager.setAppLocked(true)
            manager.setAppLocked(false)
            return 5900
        })
        let connection = SSHConnection(name: "Synthetic", username: "tester", host: "test.example")
        await manager.finishWake(connection, mode: .unlock, loginConfirmed: false, channel: .init(served: true))
        XCTAssertEqual(manager.state(for: connection.id), .idle)
        XCTAssertTrue(manager.diagnostics.isEmpty)
    }

    @MainActor func testStoppingReadinessPreservesPasswordDeliveryWithoutClaimingFailure() async {
        let manager = SSHSessionManager(checkReadiness: { _, _ in
            withUnsafeCurrentTask { $0?.cancel() }
            return 5900
        })
        let connection = SSHConnection(name: "Synthetic", username: "tester", host: "test.example")
        let task = Task {
            await manager.finishWake(connection, mode: .unlock, loginConfirmed: false, channel: .init(served: true))
        }
        await task.value
        guard case .wakeResult(let result) = manager.state(for: connection.id) else { return XCTFail() }
        XCTAssertTrue(result.checkStopped)
        XCTAssertNil(result.reachablePort)
        XCTAssertTrue(manager.diagnostics.last?.result.contains("Password sent") ?? false)
    }

    func testReadinessFindsScreenSharingWithSSHUnavailable() async {
        let port = await WakeReadiness.check(host: "test.example", sshPort: 2222,
            pause: { XCTFail("Should finish on first reachable port") },
            probe: { host, port, timeout in
                XCTAssertEqual(host, "test.example")
                XCTAssertTrue([2222, 5900].contains(port))
                XCTAssertLessThanOrEqual(timeout, 2)
                return port == 5900
            })
        XCTAssertEqual(port, 5900)
    }

    func testReadinessHasBoundedAttemptsWhenNoPortAnswers() async {
        let counter = ReadinessCounter()
        let port = await WakeReadiness.check(host: "test.example", sshPort: 5900, now: { 0 },
            pause: {}, probe: { _, _, _ in counter.increment(); return false })
        XCTAssertNil(port)
        XCTAssertEqual(counter.value, 23)
    }

    func testTCPProbeDetectsAListeningLoopbackPortWithoutSendingData() async throws {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { close(fd) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        XCTAssertEqual(bound, 0)
        XCTAssertEqual(listen(fd, 1), 0)
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        XCTAssertEqual(named, 0)
        let reachable = await TCPReadinessProbe(host: "127.0.0.1", port: Int(UInt16(bigEndian: address.sin_port))).run(timeout: 2)
        XCTAssertTrue(reachable)
        guard reachable else { return }
        let peer = accept(fd, nil, nil)
        XCTAssertGreaterThanOrEqual(peer, 0)
        defer { close(peer) }
        _ = fcntl(peer, F_SETFL, O_NONBLOCK)
        var byte: UInt8 = 0
        let received = read(peer, &byte, 1)
        XCTAssertLessThanOrEqual(received, 0, "Readiness must not send application data")
    }

    func testScreenSharingGreetingRecognizesStandardAndVendorVersions() {
        for banner in ["RFB 003.003\n", "RFB 003.007\n", "RFB 003.008\n", "RFB 003.889\n"] {
            XCTAssertTrue(WakeReadiness.isScreenSharingGreeting(Data(banner.utf8)))
        }
        for banner in ["", "RFB 003.008", "RFB 003.00x\n", "RFB 000.000\n",
                       "RFB 003.008\r", "HTTP/1.1 200", "RFB 003.008\nextra"] {
            XCTAssertFalse(WakeReadiness.isScreenSharingGreeting(Data(banner.utf8)))
        }
    }

    func testSSHAvailabilityDoesNotEndTheScreenSharingWait() async {
        let desktopChecks = ReadinessCounter()
        let port = await WakeReadiness.check(host: "test.example", sshPort: 2222, now: { 0 },
            pause: {}, probe: { _, port, _ in
                if port == 2222 { return true }
                desktopChecks.increment()
                return desktopChecks.value == 2
            })
        XCTAssertEqual(port, 5900)
        XCTAssertEqual(desktopChecks.value, 2)
    }

    @MainActor func testReadyResultKeepsTechnicalUncertaintyInActivity() async {
        for before in [false, true] {
            let manager = SSHSessionManager(checkReadiness: { _, _ in 5900 })
            let connection = SSHConnection(name: "Synthetic", username: "tester", host: "test.example")
            await manager.finishWake(connection, mode: .unlock, loginConfirmed: false,
                                     channel: .init(served: true), screenSharingRespondedBeforeSSH: before)
            guard case .wakeResult(let result) = manager.state(for: connection.id) else { return XCTFail() }
            XCTAssertTrue(result.desktopReady)
            XCTAssertEqual(result.headline, "Ready for Remote Desktop")
            XCTAssertFalse(result.guidance.contains("FileVault"))
            XCTAssertFalse(result.guidance.contains("SSH"))
            XCTAssertFalse(result.guidance.contains("already available"))
            XCTAssertTrue(manager.diagnostics.last?.result.contains("FileVault unlock not verified") ?? false)
            XCTAssertTrue(manager.diagnostics.last?.result.contains(before
                ? "Screen Sharing responded before password submission" : "Screen Sharing was not observed in the initial check; responding afterwards") ?? false)
        }
    }

    @MainActor func testSSHOnlyResponseCannotProduceDesktopSuccess() async {
        let manager = SSHSessionManager(checkReadiness: { _, _ in 2222 })
        let connection = SSHConnection(name: "Synthetic", username: "tester", host: "test.example", port: 2222)
        await manager.finishWake(connection, mode: .unlock, loginConfirmed: true, channel: .init(served: true))
        guard case .wakeResult(let result) = manager.state(for: connection.id) else { return XCTFail() }
        XCTAssertFalse(result.desktopReady)
        XCTAssertTrue(result.loginConfirmed)
        XCTAssertTrue(manager.diagnostics.last?.result.contains("no Screen Sharing greeting") ?? false)
    }

    func testScreenSharingProbeReassemblesFragmentedGreetingWithoutSendingData() async throws {
        let ready = try await serveGreeting([Data("RFB 003.".utf8), Data("889\n".utf8)])
        XCTAssertTrue(ready)
    }

    func testScreenSharingProbeRejectsUnrelatedServiceAndTruncatedGreeting() async throws {
        for banner in ["HTTP/1.1 200", "RFB 003."] {
            let ready = try await serveGreeting([Data(banner.utf8)])
            XCTAssertFalse(ready)
        }
    }

    func testScreenSharingProbeTimesOutOnASilentOpenPort() async throws {
        let ready = try await serveGreeting([], keepOpen: true)
        XCTAssertFalse(ready)
    }

    private func serveGreeting(_ chunks: [Data], keepOpen: Bool = false) async throws -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.EIO) }
        defer { close(fd) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0, listen(fd, 1) == 0 else { throw POSIXError(.EIO) }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        guard named == 0 else { throw POSIXError(.EIO) }
        let finished = expectation(description: "Synthetic greeting server closed")
        DispatchQueue.global().async {
            defer { finished.fulfill() }
            var ready = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&ready, 1, 2000) > 0 else { return XCTFail("Probe never connected") }
            let peer = accept(fd, nil, nil)
            guard peer >= 0 else { return XCTFail("Accept failed") }
            defer { close(peer) }
            var one: Int32 = 1
            _ = setsockopt(peer, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            for chunk in chunks {
                _ = chunk.withUnsafeBytes { write(peer, $0.baseAddress, $0.count) }
                usleep(20_000)
            }
            if keepOpen { usleep(300_000) }
            _ = fcntl(peer, F_SETFL, O_NONBLOCK)
            var byte: UInt8 = 0
            XCTAssertLessThanOrEqual(read(peer, &byte, 1), 0, "Probe must not send a client greeting or credentials")
        }
        let result = await TCPReadinessProbe(host: "127.0.0.1",
            port: Int(UInt16(bigEndian: address.sin_port)), requiresScreenSharing: true).run(timeout: 0.2)
        await fulfillment(of: [finished], timeout: 3)
        return result
    }

    func testTCPProbeCancellationBeforeStartCompletesWithoutConnecting() async {
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return await TCPReadinessProbe(host: "127.0.0.1", port: 1).run(timeout: 30)
        }
        let reachable = await task.value
        XCTAssertFalse(reachable)
    }

    func testCancelledReadinessDoesNotProbe() async {
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return await WakeReadiness.check(host: "test.example", sshPort: 22,
                probe: { _, _, _ in XCTFail("Cancelled check must not connect"); return true })
        }
        let port = await task.value
        XCTAssertNil(port)
    }
}

private final class ReadinessCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    var value: Int { lock.lock(); defer { lock.unlock() }; return count }
    func increment() { lock.lock(); count += 1; lock.unlock() }
}
