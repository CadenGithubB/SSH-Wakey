import XCTest
@testable import SSH_Wakey

final class SpyPreferences: ManagedPreferenceReading, @unchecked Sendable {
    var values: [String: Any]
    var forced: Set<String>
    private(set) var objectCalls: [String] = []
    private(set) var forcedCalls: [String] = []

    init(values: [String: Any] = [:], forced: Set<String> = []) {
        self.values = values
        self.forced = forced
    }

    func object(forKey key: String) -> Any? {
        objectCalls.append(key)
        return values[key]
    }

    func isForced(_ key: String) -> Bool {
        forcedCalls.append(key)
        return forced.contains(key)
    }
}

final class ManagedPolicyTests: XCTestCase {

    func testStandardNeverReadsTheProfile() {
        let spy = SpyPreferences(
            values: [ManagedPolicy.connectionsKey: [["Username": "admin", "Host": "10.0.0.1"]]],
            forced: [ManagedPolicy.connectionsKey])
        let policy = ManagedPolicy.load(from: spy, acceptsManagedPreferences: false)
        XCTAssertTrue(spy.objectCalls.isEmpty)
        XCTAssertTrue(spy.forcedCalls.isEmpty)
        XCTAssertTrue(policy.connections.isEmpty)
        XCTAssertTrue(policy.allowsDiagnostics)
    }

    func testUnforcedConnectionsAreIgnored() {
        let reader = SnapshotPreferences(
            values: [
                ManagedPolicy.connectionsKey: [
                    ["Username": "admin", "Host": "10.0.0.1", "Name": "Office"],
                ],
            ],
            forced: [])
        let policy = ManagedPolicy.load(from: reader, acceptsManagedPreferences: true)
        XCTAssertTrue(policy.connections.isEmpty)
    }

    func testForcedPayloadBecomesWakeOnlyRows() {
        let reader = SnapshotPreferences(
            values: [
                ManagedPolicy.organizationNameKey: "Example Corp",
                ManagedPolicy.connectionsKey: [
                    [
                        "Name": "Office Mac",
                        "Username": "jsmith",
                        "Host": "office.example",
                        "Port": 2222,
                    ],
                ],
            ],
            forced: [ManagedPolicy.organizationNameKey, ManagedPolicy.connectionsKey])
        let policy = ManagedPolicy.load(from: reader, acceptsManagedPreferences: true)
        XCTAssertEqual(policy.organizationName, "Example Corp")
        XCTAssertEqual(policy.connections.count, 1)
        XCTAssertEqual(policy.connections.first?.name, "Office Mac")
        XCTAssertEqual(policy.connections.first?.username, "jsmith")
        XCTAssertEqual(policy.connections.first?.host, "office.example")
        XCTAssertEqual(policy.connections.first?.port, 2222)
        XCTAssertEqual(policy.connections.first?.connectMode, .unlock)
        XCTAssertEqual(policy.connections.first?.extraArguments, "")
        XCTAssertTrue(policy.connections.first?.strictHostKeyChecking == true)
    }

    func testOmittedConnectionsAreAnEmptyCatalog() {
        let reader = SnapshotPreferences(values: [:], forced: [])
        let policy = ManagedPolicy.load(from: reader, acceptsManagedPreferences: true)
        XCTAssertTrue(policy.connections.isEmpty)
        XCTAssertTrue(policy.allowsDiagnostics)
    }

    func testForcedDiagnosticsOff() {
        let reader = SnapshotPreferences(
            values: [ManagedPolicy.allowDiagnosticsKey: false],
            forced: [ManagedPolicy.allowDiagnosticsKey])
        let policy = ManagedPolicy.load(from: reader, acceptsManagedPreferences: true)
        XCTAssertFalse(policy.allowsDiagnostics)
    }

    func testStableIDsSurviveAReload() {
        let first = ManagedPolicy.stableID(username: "Admin", host: "Office.Example", port: 22)
        let second = ManagedPolicy.stableID(username: "admin", host: "office.example", port: 22)
        XCTAssertEqual(first, second)
        XCTAssertNotEqual(
            first,
            ManagedPolicy.stableID(username: "admin", host: "office.example", port: 2222))
    }

    func testRowsWithoutAUserOrHostAreDropped() {
        let rows = ManagedPolicy.parseConnections([
            ["Name": "Nope", "Host": "10.0.0.1"],
            ["Username": "admin"],
            ["Username": "admin", "Host": "10.0.0.2"],
        ])
        XCTAssertEqual(rows.map(\.host), ["10.0.0.2"])
    }

    /// Live Managed Preferences hand back CF/NS types, not Swift dictionaries.
    /// This round-trips the example plist through PropertyListSerialization so
    /// that path is covered without talking to cfprefsd.
    func testParseConnectionsFromPropertyListXML() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("docs/jamf/example-managed.plist")
        let data = try Data(contentsOf: url)
        let raw = try PropertyListSerialization.propertyList(from: data, format: nil)
        guard let plist = raw as? [String: Any] else {
            return XCTFail("example plist did not decode as a dictionary")
        }
        let rows = ManagedPolicy.parseConnections(plist[ManagedPolicy.connectionsKey])
        XCTAssertEqual(rows.map(\.name), ["Office Mac", "Lab iMac"])
        XCTAssertEqual(rows.map(\.username), ["jsmith", "wakey"])
        XCTAssertEqual(rows.map(\.host), ["192.0.2.10", "lab-imac.example.test"])
        XCTAssertEqual(rows.map(\.port), [22, 22])
        XCTAssertEqual(rows.map(\.connectMode), [.unlock, .unlock])
        XCTAssertEqual(plist[ManagedPolicy.organizationNameKey] as? String, "Example Corp")
        XCTAssertEqual(plist[ManagedPolicy.allowDiagnosticsKey] as? Bool, true)
    }
}
