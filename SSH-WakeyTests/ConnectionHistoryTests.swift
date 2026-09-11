import XCTest
@testable import SSH_Wakey

@MainActor
final class ConnectionHistoryTests: XCTestCase {

    private var directory: URL!
    private var store: ConnectionStore!

    override func setUp() async throws {
        directory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("SSH-WakeyHistory-\(UUID().uuidString)", isDirectory: true)
        store = ConnectionStore(fileStore: ConnectionFileStore(directoryURL: directory))
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func makeConnection() -> SSHConnection {
        SSHConnection(name: "Studio Mac", username: "admin", host: "192.168.1.24")
    }

    func testAddingStampsBothDates() throws {
        store.add(makeConnection())
        let saved = try XCTUnwrap(store.connections.first)

        XCTAssertNotNil(saved.createdAt)
        XCTAssertEqual(saved.createdAt, saved.modifiedAt)
        XCTAssertTrue(saved.revisions.isEmpty)
        XCTAssertLessThan(abs(saved.createdAt!.timeIntervalSinceNow), 5)
    }

    func testEditingRecordsWhatChanged() throws {
        store.add(makeConnection())
        var edited = try XCTUnwrap(store.connections.first)
        let added = try XCTUnwrap(edited.createdAt)

        edited.host = "10.0.0.9"
        edited.port = 2222
        store.update(edited)

        let saved = try XCTUnwrap(store.connections.first)
        XCTAssertEqual(saved.createdAt, added, "the creation date must survive an edit")
        XCTAssertEqual(saved.revisions.count, 1)

        let summary = try XCTUnwrap(saved.revisions.first?.summary)
        XCTAssertTrue(summary.contains("Host: 192.168.1.24 → 10.0.0.9"), summary)
        XCTAssertTrue(summary.contains("Port: 22 → 2222"), summary)
    }

    func testSavingWithNothingChangedRecordsNothing() throws {
        store.add(makeConnection())
        let unchanged = try XCTUnwrap(store.connections.first)
        let originalModified = unchanged.modifiedAt

        store.update(unchanged)

        let saved = try XCTUnwrap(store.connections.first)
        XCTAssertTrue(saved.revisions.isEmpty)
        XCTAssertEqual(saved.modifiedAt, originalModified)
    }

    func testTheHostKeyPolicyChangeIsRecordedInWords() throws {
        store.add(makeConnection())
        var edited = try XCTUnwrap(store.connections.first)
        edited.strictHostKeyChecking = false
        store.update(edited)

        let summary = try XCTUnwrap(store.connections.first?.revisions.first?.summary)
        XCTAssertEqual(summary, "Known host key: required → trust on first use")
    }

    func testHistoryDoesNotGrowWithoutBound() throws {
        store.add(makeConnection())
        for index in 1...(SSHConnection.maxRevisions + 5) {
            var edited = try XCTUnwrap(store.connections.first)
            edited.name = "Rename \(index)"
            store.update(edited)
        }

        let saved = try XCTUnwrap(store.connections.first)
        XCTAssertEqual(saved.revisions.count, SSHConnection.maxRevisions)
        // The oldest were dropped, not the newest.
        XCTAssertTrue(saved.revisions.last?.summary.contains("Rename \(SSHConnection.maxRevisions + 5)") ?? false)
    }

    func testDatesAndHistorySurviveASaveAndReload() throws {
        store.add(makeConnection())
        var edited = try XCTUnwrap(store.connections.first)
        edited.username = "admin"
        store.update(edited)
        let before = try XCTUnwrap(store.connections.first)

        let reloaded = ConnectionStore(fileStore: ConnectionFileStore(directoryURL: directory))
        let after = try XCTUnwrap(reloaded.connections.first)

        XCTAssertEqual(after, before, "dates are stored to the second so they round-trip exactly")
        XCTAssertEqual(after.createdAt, before.createdAt)
        XCTAssertEqual(after.revisions, before.revisions)
    }

    func testTimestampsAreWrittenInAReadableForm() throws {
        store.add(makeConnection())
        let text = try String(contentsOf: store.fileURL, encoding: .utf8)
        XCTAssertTrue(text.contains("\"createdAt\""), text)
        XCTAssertTrue(text.range(of: #""createdAt" : "\d{4}-\d{2}-\d{2}T"#, options: .regularExpression) != nil, text)
    }

    func testAConnectionFromAnOlderBuildHasNoDatesRatherThanInventedOnes() throws {
        let fileStore = ConnectionFileStore(directoryURL: directory)
        try fileStore.createDirectoryIfNeeded()
        try Data("""
        {"version":1,"connections":[{"name":"Old","username":"admin","host":"10.0.0.9"}]}
        """.utf8).write(to: fileStore.fileURL)

        let loaded = try XCTUnwrap(fileStore.load().first)
        XCTAssertNil(loaded.createdAt)
        XCTAssertNil(loaded.modifiedAt)
        XCTAssertTrue(loaded.revisions.isEmpty)
    }

    func testANewConnectionDoesNotGuessTheUsername() {
        XCTAssertEqual(SSHConnection().username, "",
                       "the account on the remote machine is rarely the one on this Mac")
    }
}
