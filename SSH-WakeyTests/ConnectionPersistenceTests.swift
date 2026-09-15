import XCTest
@testable import SSH_Wakey

final class ConnectionPersistenceTests: XCTestCase {

    private var directory: URL!
    private var store: ConnectionFileStore!

    override func setUpWithError() throws {
        directory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("SSH-WakeyTests-\(UUID().uuidString)", isDirectory: true)
        store = ConnectionFileStore(directoryURL: directory)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    func testLoadingWithNoFileReturnsEmptyList() throws {
        XCTAssertEqual(try store.load(), [])
    }

    func testRoundTripPreservesEveryField() throws {
        let saved = [
            SSHConnection(name: "Studio Mac", username: "admin", host: "192.168.1.24",
                          port: 2222, extraArguments: "-o ServerAliveInterval=30",
                          strictHostKeyChecking: true),
            SSHConnection(name: "Build box", username: "ci", host: "build.example.internal",
                          port: 22, extraArguments: "", strictHostKeyChecking: false,
                          connectMode: .session, hardwareAddress: "aa:bb:cc:dd:ee:ff"),
        ]
        try store.save(saved)

        let loaded = try store.load()
        XCTAssertEqual(loaded, saved)
        XCTAssertEqual(loaded.map(\.id), saved.map(\.id))
    }

    func testSaveIsWrittenToTheExpectedFileName() throws {
        try store.save([SSHConnection(name: "A", username: "u", host: "h")])
        XCTAssertEqual(store.fileURL.lastPathComponent, "connections.json")
        XCTAssertTrue(FileManager.default.fileExists(atPath: store.fileURL.path))
    }

    func testDefaultDirectoryIsInsideApplicationSupport() {
        let path = ConnectionFileStore.defaultDirectory.path
        XCTAssertTrue(path.hasSuffix("/Library/Application Support/SSH-Wakey"), path)
    }

    func testFileAndDirectoryAreOnlyReadableByThisUser() throws {
        try store.save([SSHConnection(name: "A", username: "u", host: "h")])

        let filePermissions = try FileManager.default
            .attributesOfItem(atPath: store.fileURL.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(filePermissions?.int16Value, 0o600)

        let directoryPermissions = try FileManager.default
            .attributesOfItem(atPath: directory.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(directoryPermissions?.int16Value, 0o700)
    }

    func testSavedFileHoldsNoPasswordField() throws {
        try store.save([SSHConnection(name: "A", username: "admin", host: "h", port: 22)])
        let text = try String(contentsOf: store.fileURL, encoding: .utf8).lowercased()
        XCTAssertFalse(text.contains("password"))
        XCTAssertFalse(text.contains("secret"))
        XCTAssertFalse(text.contains("passphrase"))
    }

    func testSavingReplacesThePreviousContents() throws {
        try store.save([SSHConnection(name: "First", username: "u", host: "h")])
        try store.save([SSHConnection(name: "Second", username: "u", host: "h")])

        let loaded = try store.load()
        XCTAssertEqual(loaded.count, 1)
        XCTAssertEqual(loaded.first?.name, "Second")
    }

    func testFileWrittenByAnOlderBuildStillLoads() throws {
        // No port, no extraArguments, no strictHostKeyChecking key.
        let legacy = """
        {"version":1,"connections":[{"name":"Old","username":"admin","host":"10.0.0.9"}]}
        """
        try store.createDirectoryIfNeeded()
        try Data(legacy.utf8).write(to: store.fileURL)

        let loaded = try store.load()
        XCTAssertEqual(loaded.count, 1)
        XCTAssertEqual(loaded.first?.port, 22)
        XCTAssertEqual(loaded.first?.extraArguments, "")
        XCTAssertEqual(loaded.first?.strictHostKeyChecking, true)
        XCTAssertEqual(loaded.first?.connectMode, .unlock)
        XCTAssertNil(loaded.first?.hardwareAddress)
    }

    func testAnUnrecognisedConnectModeFallsBackToWake() throws {
        let legacy = """
        {"version":1,"connections":[{"name":"Old","username":"admin","host":"10.0.0.9","connectMode":"nope"}]}
        """
        try store.createDirectoryIfNeeded()
        try Data(legacy.utf8).write(to: store.fileURL)

        let loaded = try store.load()
        XCTAssertEqual(loaded.first?.connectMode, .unlock)
    }

    func testFileFromANewerFormatIsRefusedRatherThanMisread() throws {
        try store.createDirectoryIfNeeded()
        try Data("""
        {"version":99,"connections":[]}
        """.utf8).write(to: store.fileURL)

        XCTAssertThrowsError(try store.load()) { error in
            XCTAssertEqual(error as? ConnectionFileStore.StoreError, .unsupportedVersion(99))
        }
    }

    func testCorruptFileReportsAReadableError() throws {
        try store.createDirectoryIfNeeded()
        try Data("this is not json".utf8).write(to: store.fileURL)

        XCTAssertThrowsError(try store.load()) { error in
            guard case .damagedOrAltered = error as? ConnectionFileStore.StoreError else {
                return XCTFail("Expected .damagedOrAltered, got \(error)")
            }
            XCTAssertTrue(
                (error as? LocalizedError)?.errorDescription?
                    .localizedCaseInsensitiveContains("damaged or altered") == true,
                String(describing: error))
        }
    }

    func testNormalizationTrimsWhitespaceBeforeSaving() throws {
        let messy = SSHConnection(name: "  Studio  ", username: " admin ", host: " 10.0.0.4 ",
                                  port: 22, extraArguments: "  -v  ")
        try store.save([messy.normalized])

        let loaded = try XCTUnwrap(try store.load().first)
        XCTAssertEqual(loaded.name, "Studio")
        XCTAssertEqual(loaded.username, "admin")
        XCTAssertEqual(loaded.host, "10.0.0.4")
        XCTAssertEqual(loaded.extraArguments, "-v")
    }

    func testDisplayDestinationShowsPortOnlyWhenItIsNotTheDefault() {
        XCTAssertEqual(
            SSHConnection(name: "A", username: "admin", host: "mac.local").displayDestination,
            "admin@mac.local")
        XCTAssertEqual(
            SSHConnection(name: "A", username: "admin", host: "mac.local", port: 2222).displayDestination,
            "admin@mac.local:2222")
    }
}
