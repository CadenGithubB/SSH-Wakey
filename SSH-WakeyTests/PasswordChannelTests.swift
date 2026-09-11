import Darwin
import XCTest
@testable import SSH_Wakey

/// Exercises the password path end to end, in process: the app's channel on one
/// side and the real askpass client code on the other.
final class PasswordChannelTests: XCTestCase {

    private let secret = "correct horse battery staple"

    private func socketPath(of channel: AskpassChannel) throws -> String {
        let environment = channel.environmentAdditions()
        return try XCTUnwrap(environment[AskpassProtocol.socketEnvironmentKey])
    }

    /// Runs the client half off the main thread, which is where ssh would run it.
    private func ask(
        socket: String, nonce: String, prompt: String, timeout: TimeInterval = 5
    ) -> [UInt8]? {
        let finished = expectation(description: "askpass client finished")
        let box = ResultBox()
        DispatchQueue.global().async {
            box.value = AskpassHelper.fetch(
                AskpassHelper.Request(socketPath: socket, nonce: nonce, prompt: prompt))
            finished.fulfill()
        }
        wait(for: [finished], timeout: timeout)
        return box.value
    }

    private final class ResultBox: @unchecked Sendable {
        var value: [UInt8]?
    }

    func testTheChannelHandsThePasswordToAValidRequest() throws {
        let channel = try AskpassChannel(password: SecureBuffer(secret))
        defer { channel.invalidate() }

        let answer = ask(
            socket: try socketPath(of: channel),
            nonce: channel.nonce,
            prompt: "morgan@10.0.0.4's password: ")

        XCTAssertEqual(String(decoding: try XCTUnwrap(answer), as: UTF8.self), secret + "\n")
        XCTAssertTrue(channel.outcome.served)
        XCTAssertEqual(channel.outcome.askedAgainAfterServing, 0)
    }

    func testAWrongNonceGetsNothing() throws {
        let channel = try AskpassChannel(password: SecureBuffer(secret))
        defer { channel.invalidate() }

        let answer = ask(
            socket: try socketPath(of: channel),
            nonce: String(repeating: "0", count: 64),
            prompt: "morgan@10.0.0.4's password: ")

        XCTAssertTrue(answer?.isEmpty ?? true)
        XCTAssertFalse(channel.outcome.served)
        XCTAssertEqual(channel.outcome.wrongNonceAttempts, 1)
    }

    /// The password must never be offered up to a host key confirmation, a key
    /// passphrase, or any other question ssh might route through askpass.
    func testOnlyAPasswordPromptIsAnswered() throws {
        let prompts = [
            "Are you sure you want to continue connecting (yes/no/[fingerprint])?",
            "Enter passphrase for key '/Users/morgan/.ssh/id_ed25519': ",
            "(morgan@10.0.0.4) Verification code: ",
            "",
        ]
        for prompt in prompts {
            let channel = try AskpassChannel(password: SecureBuffer(secret))
            defer { channel.invalidate() }

            let answer = ask(socket: try socketPath(of: channel), nonce: channel.nonce, prompt: prompt)
            XCTAssertTrue(answer?.isEmpty ?? true, prompt)
            XCTAssertFalse(channel.outcome.served, prompt)
            XCTAssertEqual(channel.outcome.refusedPrompts, [prompt.trimmingCharacters(in: .whitespaces)])
        }
    }

    /// ssh asks a second time when the first authentication method rejects the
    /// password. Answering would be a silent retry, so the second ask is
    /// recorded and left unanswered.
    func testThePasswordIsServedOnlyOnce() throws {
        let channel = try AskpassChannel(password: SecureBuffer(secret))
        defer { channel.invalidate() }
        let path = try socketPath(of: channel)

        let first = ask(socket: path, nonce: channel.nonce, prompt: "user@host's password: ")
        XCTAssertEqual(String(decoding: try XCTUnwrap(first), as: UTF8.self), secret + "\n")

        let second = ask(socket: path, nonce: channel.nonce, prompt: "(user@host) Password:")
        XCTAssertTrue(second?.isEmpty ?? true)
        XCTAssertEqual(channel.outcome.askedAgainAfterServing, 1)
        XCTAssertTrue(channel.outcome.served)
    }

    func testTheChannelIsUnusableOnceTheAttemptIsOver() throws {
        let channel = try AskpassChannel(password: SecureBuffer(secret))
        let path = try socketPath(of: channel)

        channel.invalidate()

        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        XCTAssertNil(ask(socket: path, nonce: channel.nonce, prompt: "password: "))
    }

    func testInvalidatingRemovesTheSocketAndItsFolder() throws {
        let channel = try AskpassChannel(password: SecureBuffer(secret))
        let path = try socketPath(of: channel)
        XCTAssertTrue(FileManager.default.fileExists(atPath: path))

        channel.invalidate()
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: URL(fileURLWithPath: path).deletingLastPathComponent().path))
    }

    func testTheSocketLivesInAFolderOnlyThisUserCanEnter() throws {
        let channel = try AskpassChannel(password: SecureBuffer(secret))
        defer { channel.invalidate() }

        let folder = URL(fileURLWithPath: try socketPath(of: channel)).deletingLastPathComponent()
        let permissions = try FileManager.default
            .attributesOfItem(atPath: folder.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(permissions?.int16Value, 0o700)
    }

    func testTheEnvironmentHandedToSSHCarriesNoPassword() throws {
        let channel = try AskpassChannel(
            password: SecureBuffer(secret), helperPath: "/path/to/SSH-Wakey")
        defer { channel.invalidate() }

        let environment = channel.environmentAdditions()
        XCTAssertEqual(environment["SSH_ASKPASS"], "/path/to/SSH-Wakey")
        XCTAssertEqual(environment["SSH_ASKPASS_REQUIRE"], "force")
        for value in environment.values {
            XCTAssertFalse(value.contains(secret))
        }
    }

    func testTheNonceIsLongAndDifferentEveryTime() throws {
        let first = try AskpassChannel(password: SecureBuffer(secret))
        defer { first.invalidate() }
        let second = try AskpassChannel(password: SecureBuffer(secret))
        defer { second.invalidate() }

        XCTAssertEqual(first.nonce.count, 64)
        XCTAssertNotEqual(first.nonce, second.nonce)
    }

    /// The socket path and the nonce both live in ssh's environment, and on
    /// macOS anything running as this user can read that. So the nonce alone is
    /// not proof of identity: the program on the other end has to be the helper
    /// this app actually started.
    func testAnotherProgramWithTheRightTokenIsStillRefused() throws {
        let channel = try AskpassChannel(
            password: SecureBuffer(secret), helperPath: "/usr/bin/true")
        defer { channel.invalidate() }

        let answer = ask(
            socket: try socketPath(of: channel),
            nonce: channel.nonce,
            prompt: "morgan@10.0.0.4's password: ")

        XCTAssertTrue(answer?.isEmpty ?? true, "the password must not be handed over")
        XCTAssertFalse(channel.outcome.served)
        XCTAssertEqual(channel.outcome.wrongProgramAttempts, 1)
    }

    func testTheRealHelperIsStillAnswered() throws {
        // The tests run inside the app, so this process is the expected program.
        let channel = try AskpassChannel(password: SecureBuffer(secret))
        defer { channel.invalidate() }

        let answer = ask(
            socket: try socketPath(of: channel),
            nonce: channel.nonce,
            prompt: "morgan@10.0.0.4's password: ")

        XCTAssertEqual(String(decoding: try XCTUnwrap(answer), as: UTF8.self), secret + "\n")
        XCTAssertEqual(channel.outcome.wrongProgramAttempts, 0)
    }

    /// If this ever fails, the identity check is comparing two spellings of the
    /// same file and will refuse the genuine helper, which would break every
    /// connection. Better to fail here, saying exactly that, than to have three
    /// unrelated-looking tests fail somewhere else.
    func testThisProcessIsRecognisedByTheSamePathItReports() throws {
        let expected = URL(fileURLWithPath: try XCTUnwrap(Bundle.main.executablePath))
            .resolvingSymlinksInPath().path

        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        XCTAssertGreaterThan(proc_pidpath(getpid(), &buffer, UInt32(buffer.count)), 0)
        let running = URL(fileURLWithPath: String(cString: buffer)).resolvingSymlinksInPath().path

        XCTAssertEqual(running, expected,
                       "the identity check compares these two, so they have to agree")
    }

    /// The whole path, for real: a separate process of this very binary, started
    /// the way ssh starts it, asking over the socket and being answered.
    ///
    /// This is what proves the identity check does not lock out the genuine
    /// helper, which would break every connection.
    func testARealHelperProcessIsAnswered() throws {
        let executable = try XCTUnwrap(Bundle.main.executablePath)
        let channel = try AskpassChannel(password: SecureBuffer(secret), helperPath: executable)
        defer { channel.invalidate() }

        let helper = Process()
        helper.executableURL = URL(fileURLWithPath: executable)
        helper.arguments = ["morgan@10.0.0.4's password: "]
        var environment = ProcessRunner.minimalEnvironment()
        environment.merge(channel.environmentAdditions()) { _, new in new }
        helper.environment = environment

        let output = Pipe()
        let errors = Pipe()
        helper.standardOutput = output
        helper.standardError = errors
        try helper.run()

        let answer = output.fileHandleForReading.readDataToEndOfFile()
        let complaints = errors.fileHandleForReading.readDataToEndOfFile()
        helper.waitUntilExit()

        let diagnosis = """
        status \(helper.terminationStatus), reason \(helper.terminationReason.rawValue),         outcome \(channel.outcome), stderr: \(String(decoding: complaints, as: UTF8.self))
        """
        XCTAssertEqual(String(decoding: answer, as: UTF8.self), secret + "\n", diagnosis)
        XCTAssertEqual(helper.terminationStatus, 0, diagnosis)
        XCTAssertTrue(channel.outcome.served, diagnosis)
        XCTAssertEqual(channel.outcome.wrongProgramAttempts, 0, diagnosis)
    }

    // MARK: - Prompt matching

    func testPromptMatching() {
        XCTAssertTrue(AskpassProtocol.looksLikePasswordPrompt("morgan@host's password: "))
        XCTAssertTrue(AskpassProtocol.looksLikePasswordPrompt("Password:"))
        XCTAssertFalse(AskpassProtocol.looksLikePasswordPrompt(
            "Are you sure you want to continue connecting (yes/no)?"))
        XCTAssertFalse(AskpassProtocol.looksLikePasswordPrompt("Enter passphrase for key: "))
        XCTAssertFalse(AskpassProtocol.looksLikePasswordPrompt(""))
    }

    func testNonceComparisonIgnoresLengthDifferences() {
        XCTAssertTrue(AskpassProtocol.constantTimeEquals("abc", "abc"))
        XCTAssertFalse(AskpassProtocol.constantTimeEquals("abc", "abcd"))
        XCTAssertFalse(AskpassProtocol.constantTimeEquals("abc", ""))
        XCTAssertTrue(AskpassProtocol.constantTimeEquals("", ""))
    }

    // MARK: - Askpass mode selection

    func testAskpassModeIsOffUnlessBothEnvironmentValuesArePresent() {
        XCTAssertNil(AskpassHelper.requestFromEnvironment(environment: [:], arguments: ["SSH-Wakey"]))
        XCTAssertNil(AskpassHelper.requestFromEnvironment(
            environment: [AskpassProtocol.socketEnvironmentKey: "/tmp/s"], arguments: ["SSH-Wakey"]))
        XCTAssertNil(AskpassHelper.requestFromEnvironment(
            environment: [AskpassProtocol.socketEnvironmentKey: "",
                          AskpassProtocol.nonceEnvironmentKey: ""], arguments: ["SSH-Wakey"]))
    }

    func testAskpassModeCollectsThePromptFromTheArguments() throws {
        let request = try XCTUnwrap(AskpassHelper.requestFromEnvironment(
            environment: [AskpassProtocol.socketEnvironmentKey: "/tmp/s",
                          AskpassProtocol.nonceEnvironmentKey: "abc"],
            arguments: ["SSH-Wakey", "morgan@host's password: "]))
        XCTAssertEqual(request.socketPath, "/tmp/s")
        XCTAssertEqual(request.nonce, "abc")
        XCTAssertEqual(request.prompt, "morgan@host's password: ")
    }
}

/// Covers how the password channel's observations are turned into a message.
final class PasswordChannelReportingTests: XCTestCase {

    private let failure = SSHFailure(
        kind: .authentication, headline: "Authentication failed.",
        guidance: "Check the username and password.", detail: nil)

    @MainActor
    func testAnUneventfulAttemptAddsNothing() {
        let annotated = SSHSessionManager.annotated(failure, with: AskpassChannel.Outcome(served: true))
        XCTAssertEqual(annotated.guidance, failure.guidance)
    }

    @MainActor
    func testASecondAskIsExplainedRatherThanHidden() {
        var outcome = AskpassChannel.Outcome()
        outcome.served = true
        outcome.askedAgainAfterServing = 1

        let annotated = SSHSessionManager.annotated(failure, with: outcome)
        let guidance = try? XCTUnwrap(annotated.guidance)
        XCTAssertTrue(guidance?.contains("second time") ?? false, annotated.guidance ?? "")
        XCTAssertTrue(guidance?.contains("silent retry") ?? false, annotated.guidance ?? "")
    }

    @MainActor
    func testAnUnansweredPromptIsQuoted() {
        var outcome = AskpassChannel.Outcome()
        outcome.refusedPrompts = ["Verification code: "]

        let annotated = SSHSessionManager.annotated(failure, with: outcome)
        XCTAssertTrue(annotated.guidance?.contains("Verification code") ?? false)
    }

    @MainActor
    func testAnUnauthorisedReadOfTheChannelIsReported() {
        var wrongToken = AskpassChannel.Outcome()
        wrongToken.wrongNonceAttempts = 2
        var wrongUser = AskpassChannel.Outcome()
        wrongUser.wrongUserAttempts = 1
        var wrongProgram = AskpassChannel.Outcome()
        wrongProgram.wrongProgramAttempts = 1

        for outcome in [wrongToken, wrongUser, wrongProgram] {
            let annotated = SSHSessionManager.annotated(failure, with: outcome)
            XCTAssertTrue(annotated.guidance?.contains("was refused") ?? false, "\(outcome)")
            XCTAssertTrue(annotated.guidance?.contains("worth looking into") ?? false, "\(outcome)")
        }
    }
}
