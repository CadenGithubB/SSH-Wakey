import XCTest
@testable import SSH_Wakey

/// A file written with `.atomic` is created using the umask, normally 0644, and
/// only narrowed afterwards. These cover the replacement that never has a
/// world-readable moment.
final class ProtectedFileTests: XCTestCase {

    private var directory: URL!

    override func setUpWithError() throws {
        directory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("SSH-WakeyProtected-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func mode(of url: URL) throws -> Int16? {
        (try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber)?
            .int16Value
    }

    func testTheFileIsWrittenAndReadableOnlyByThisUser() throws {
        let url = directory.appendingPathComponent("secret.json")
        try ProtectedFile.write(Data("hello".utf8), to: url)

        XCTAssertEqual(try String(contentsOf: url, encoding: .utf8), "hello")
        XCTAssertEqual(try mode(of: url), 0o600)
    }

    func testReplacingAFileKeepsThePermissionsTight() throws {
        let url = directory.appendingPathComponent("secret.json")
        FileManager.default.createFile(atPath: url.path, contents: Data("old".utf8),
                                       attributes: [.posixPermissions: 0o644])

        try ProtectedFile.write(Data("new".utf8), to: url)

        XCTAssertEqual(try String(contentsOf: url, encoding: .utf8), "new")
        XCTAssertEqual(try mode(of: url), 0o600)
    }

    func testNoTemporaryFileIsLeftBehind() throws {
        let url = directory.appendingPathComponent("secret.json")
        try ProtectedFile.write(Data("hello".utf8), to: url)

        let left = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        XCTAssertEqual(left, ["secret.json"], "the temporary file must be renamed, not abandoned")
    }

    func testAnUnwritableDestinationFailsWithoutLeavingAMess() throws {
        let missing = directory.appendingPathComponent("no-such-folder/secret.json")
        XCTAssertThrowsError(try ProtectedFile.write(Data("hello".utf8), to: missing))

        let left = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        XCTAssertTrue(left.isEmpty, "\(left)")
    }

    func testAnEmptyFileIsStillWrittenCorrectly() throws {
        let url = directory.appendingPathComponent("empty.json")
        try ProtectedFile.write(Data(), to: url)

        XCTAssertEqual(try Data(contentsOf: url).count, 0)
        XCTAssertEqual(try mode(of: url), 0o600)
    }
}
