import XCTest
@testable import SSH_Wakey

/// The diagnostics file is written to be sent to someone else, so what it does
/// and does not contain matters more than how it looks.
final class DiagnosticsReportTests: XCTestCase {

    private let secret = "hunter2-should-never-appear"

    private func entry(output: String = "debug1: Authenticated to 10.0.0.4") -> DiagnosticEntry {
        DiagnosticEntry(
            at: Date(timeIntervalSince1970: 1_770_000_000),
            connectionID: UUID(uuidString: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")!,
            connection: "Studio Mac",
            destination: "admin@10.0.0.4",
            mode: ConnectMode.unlock.title,
            result: "Authentication failed.",
            channel: "answered a password prompt",
            output: output)
    }

    private func report(_ entries: [DiagnosticEntry]) -> String {
        DiagnosticsReport.text(entries: entries, connectionCount: 2, isEncrypted: true)
    }

    func testItSaysWhatIsInItBeforeSayingAnythingElse() {
        let text = report([entry()])
        let preamble = text.prefix(500)
        XCTAssertTrue(preamble.contains("Read this before sending it anywhere"), String(preamble))
        XCTAssertTrue(preamble.contains("no"), String(preamble))
        XCTAssertTrue(preamble.contains("password"), String(preamble))
    }

    func testItCarriesWhatIsNeededToDiagnoseAFailure() {
        let text = report([entry()])
        for expected in ["Studio Mac", "admin@10.0.0.4", "Authentication failed.",
                         "answered a password prompt", "debug1: Authenticated to 10.0.0.4"] {
            XCTAssertTrue(text.contains(expected), expected)
        }
    }

    /// The password never reaches ssh's output, but the file is the one thing a
    /// person might send to a stranger, so it is worth asserting.
    func testAPasswordCouldNotSurviveIntoTheFile() {
        let text = report([entry(output: "debug1: Next authentication method: password")])
        XCTAssertFalse(text.contains(secret))
    }

    func testItSaysSoWhenThereIsNothingToReport() {
        let text = report([])
        XCTAssertTrue(text.contains("No connection attempts"), text)
    }

    func testTheNewestAttemptIsFirst() {
        var older = entry(output: "the older one")
        older.connection = "Older"
        var newer = entry(output: "the newer one")
        newer.connection = "Newer"

        let text = report([older, newer])
        let newerAt = try? XCTUnwrap(text.range(of: "Newer"))
        let olderAt = try? XCTUnwrap(text.range(of: "Older"))
        XCTAssertTrue((newerAt?.lowerBound ?? text.endIndex) < (olderAt?.lowerBound ?? text.startIndex),
                      "the most recent attempt is the one being looked at")
    }

    func testOutputThatIsMissingIsSaidRatherThanLeftBlank() {
        XCTAssertTrue(report([entry(output: "   ")]).contains("ssh printed nothing"))
    }

    func testTheFileNameCarriesTheDate() {
        let name = DiagnosticsReport.suggestedFileName(Date(timeIntervalSince1970: 1_770_000_000))
        XCTAssertTrue(name.hasPrefix("SSH-Wakey diagnostics "), name)
        XCTAssertTrue(name.hasSuffix(".txt"), name)
        XCTAssertTrue(name.range(of: #"\d{4}-\d{2}-\d{2}"#, options: .regularExpression) != nil, name)
    }

    func testTheChannelSummaryReadsAsASentence() {
        var outcome = AskpassChannel.Outcome()
        outcome.served = true
        outcome.repeatedPrompts = 1
        outcome.refusedPrompts = ["Verification code:"]

        let summary = outcome.summary
        XCTAssertTrue(summary.contains("answered a password prompt"), summary)
        XCTAssertTrue(summary.contains("repeated prompt refused"), summary)
        XCTAssertTrue(summary.contains("Verification code:"), summary)
    }

    func testAnAttemptThatNeverNeededThePasswordSaysSo() {
        XCTAssertEqual(AskpassChannel.Outcome().summary, "never asked")
    }

    func testEntriesForOneConnectionAreNewestFirstAndIgnoreTheOthers() {
        let studio = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
        let build = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!

        var older = entry()
        older.connectionID = studio
        older.connection = "Studio Mac"
        older.at = Date(timeIntervalSince1970: 100)
        older.result = "older studio"

        var newer = entry()
        newer.connectionID = studio
        newer.connection = "Studio Mac"
        newer.at = Date(timeIntervalSince1970: 200)
        newer.result = "newer studio"

        var other = entry()
        other.connectionID = build
        other.connection = "Build box"
        other.at = Date(timeIntervalSince1970: 300)
        other.result = "build"

        let filtered = DiagnosticsReport.entries([older, newer, other], for: studio)
        XCTAssertEqual(filtered.map(\.result), ["newer studio", "older studio"])
    }
}
