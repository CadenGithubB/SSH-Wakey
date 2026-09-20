import XCTest
@testable import SSH_Wakey

@MainActor
final class ManagedStoreTests: XCTestCase {

    private var directory: URL!
    private var store: ConnectionStore!
    private var reader: SnapshotPreferences!

    override func setUp() async throws {
        directory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("SSH-WakeyManaged-\(UUID().uuidString)", isDirectory: true)
        reader = SnapshotPreferences(
            values: [
                ManagedPolicy.connectionsKey: [
                    ["Name": "Office Mac", "Username": "admin", "Host": "192.168.1.24"],
                ],
                ManagedPolicy.organizationNameKey: "Example Corp",
            ],
            forced: [ManagedPolicy.connectionsKey, ManagedPolicy.organizationNameKey])
        store = ConnectionStore(
            fileStore: ConnectionFileStore(directoryURL: directory),
            keychainAccount: "managed-test-\(UUID().uuidString)",
            isManagedBuild: true,
            preferences: reader)
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: directory)
    }

    func testForcedPayloadIsTheLiveList() {
        XCTAssertEqual(store.connections.count, 1)
        XCTAssertEqual(store.connections.first?.name, "Office Mac")
        XCTAssertEqual(store.organizationName, "Example Corp")
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: ConnectionFileStore(directoryURL: directory).fileURL.path),
            "the MDM catalog must not be copied into connections.json")
    }

    func testAddUpdateAndRemoveDoNothing() throws {
        store.add(SSHConnection(name: "Extra", username: "u", host: "10.0.0.9"))
        XCTAssertEqual(store.connections.count, 1)
        XCTAssertEqual(store.connections.first?.name, "Office Mac")

        var edited = try XCTUnwrap(store.connections.first)
        edited.host = "10.0.0.9"
        store.update(edited)
        XCTAssertEqual(store.connections.first?.host, "192.168.1.24")

        store.remove(ids: Set(store.connections.map(\.id)))
        XCTAssertEqual(store.connections.count, 1)
    }

    func testUnforcedPayloadIsIgnoredEvenOnTheManagedBuild() {
        let local = SnapshotPreferences(
            values: [
                ManagedPolicy.connectionsKey: [
                    ["Username": "admin", "Host": "evil.example"],
                ],
            ],
            forced: [])
        let isolated = ConnectionStore(
            fileStore: ConnectionFileStore(directoryURL: directory),
            isManagedBuild: true,
            preferences: local)
        XCTAssertTrue(isolated.connections.isEmpty)
    }

    func testAForcedRowWithAnUnsafeFieldIsDropped() {
        let profile = SnapshotPreferences(
            values: [
                ManagedPolicy.connectionsKey: [
                    ["Name": "Good", "Username": "admin", "Host": "192.168.1.10"],
                    ["Name": "Dash host", "Username": "admin", "Host": "-oProxyCommand=x"],
                    ["Name": "Dash user", "Username": "-oProxyCommand=x", "Host": "192.168.1.11"],
                ],
            ],
            forced: [ManagedPolicy.connectionsKey])
        let policy = ManagedPolicy.load(from: profile, acceptsManagedPreferences: true)
        XCTAssertEqual(policy.connections.map(\.name), ["Good"],
                       "a forced row whose fields fail validation must be dropped, not carried to ssh")
    }

    func testStandardIgnoresAForcedPayload() {
        let isolated = ConnectionStore(
            fileStore: ConnectionFileStore(directoryURL: directory),
            isManagedBuild: false,
            preferences: reader)
        XCTAssertTrue(isolated.connections.isEmpty)
    }

    func testEncryptionAndExportAreRefused() throws {
        XCTAssertNoThrow(try store.enableEncryption(passphrase: "a-long-enough-passphrase"))
        XCTAssertFalse(store.isEncrypted)
        XCTAssertThrowsError(try store.export(to: directory.appendingPathComponent("out.json")))
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: directory.appendingPathComponent("out.json").path))
    }

    func testLearnedMACIsCachedWithoutWritingConnections() throws {
        let id = try XCTUnwrap(store.connections.first?.id)
        store.rememberLinkAddress("aa:bb:cc:dd:ee:ff", for: id)
        XCTAssertEqual(store.connections.first?.hardwareAddress, "aa:bb:cc:dd:ee:ff")
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: ConnectionFileStore(directoryURL: directory).fileURL.path))
        let cache = LinkAddressCache(directoryURL: directory)
        XCTAssertEqual(cache.address(for: "192.168.1.24"), "aa:bb:cc:dd:ee:ff")
    }
}

@MainActor
final class ManagedSessionTests: XCTestCase {

    func testOpenInTerminalIsRefusedWhenUnlockIsForced() {
        let sessions = SSHSessionManager()
        sessions.forcesUnlock = true
        sessions.openInTerminal(UUID())
        XCTAssertEqual(sessions.lastActionError, "This copy of SSH-Wakey cannot open a session.")
    }
}

final class StatusPanelIdleTests: XCTestCase {

    func testManagedUnselectedWithAssignedMachinesDoesNotClaimTheCatalogIsEmpty() {
        XCTAssertEqual(
            StatusPanel.unselectedHeadline(isManagedCatalog: true, assignedCount: 2),
            "Select a machine.")
        XCTAssertEqual(
            StatusPanel.unselectedGuidance(isManagedCatalog: true, assignedCount: 2),
            "Pick one from the list to wake it.")
    }

    func testManagedUnselectedWithAnEmptyCatalogKeepsTheEmptyCopy() {
        XCTAssertEqual(
            StatusPanel.unselectedHeadline(isManagedCatalog: true, assignedCount: 0),
            "Your organization has not assigned any machines.")
        XCTAssertNil(StatusPanel.unselectedGuidance(isManagedCatalog: true, assignedCount: 0))
    }

    func testStandardUnselectedCopyIsUnchanged() {
        XCTAssertEqual(
            StatusPanel.unselectedHeadline(isManagedCatalog: false, assignedCount: 0),
            "Select a connection.")
        XCTAssertEqual(
            StatusPanel.unselectedGuidance(isManagedCatalog: false, assignedCount: 0),
            "Add a machine, or pick one from the list.")
    }

    func testUnavailableIdleCopyDoesNotInviteAdding() {
        XCTAssertEqual(
            StatusPanel.unselectedHeadline(
                isManagedCatalog: false, assignedCount: 0, fileUnavailable: true),
            "The saved connections file could not be opened.")
        XCTAssertNil(
            StatusPanel.unselectedGuidance(
                isManagedCatalog: false, assignedCount: 0, fileUnavailable: true))
    }
}
