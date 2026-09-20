import Darwin
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

    private func addACL(_ entry: String, to url: URL) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = ["+a", entry, url.path]
        try process.run()
        process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
    }

    func testInheritedACLDoesNotGrantReadAccessToWrittenFile() throws {
        try addACL("everyone allow read,execute,file_inherit,directory_inherit", to: directory)
        let file = directory.appendingPathComponent("private.json")
        try ProtectedFile.write(Data("private metadata".utf8), to: file)
        let descriptor = open(file.path, O_RDONLY | O_NOFOLLOW)
        XCTAssertGreaterThanOrEqual(descriptor, 0)
        defer { close(descriptor) }
        if let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) {
            defer { acl_free(UnsafeMutableRawPointer(acl)) }
            var entry: acl_entry_t?
            XCTAssertEqual(acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry), -1,
                           "new file must have an empty ACL before it receives data")
        } else {
            XCTAssertEqual(errno, ENOENT)
        }
        XCTAssertEqual(try mode(of: file), 0o600)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), ["private.json"])
    }

    func testACLWritableParentIsRefused() throws {
        try addACL("everyone allow write,add_subdirectory,delete_child", to: directory)
        XCTAssertThrowsError(try ProtectedFile.write(Data("private".utf8), to: directory.appendingPathComponent("secret")))
    }

    func testSymlinkedParentAndLeafAreRefused() throws {
        let real = directory.appendingPathComponent("real", isDirectory: true)
        try ProtectedFile.createPrivateDirectory(at: real)
        let link = directory.appendingPathComponent("link", isDirectory: true)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)
        XCTAssertThrowsError(try ProtectedFile.createPrivateDirectory(at: link))
        XCTAssertThrowsError(try ProtectedFile.write(Data(), to: link.appendingPathComponent("secret")))
        let target = real.appendingPathComponent("secret")
        try ProtectedFile.write(Data("original".utf8), to: target)
        let leaf = directory.appendingPathComponent("leaf")
        try FileManager.default.createSymbolicLink(at: leaf, withDestinationURL: target)
        XCTAssertThrowsError(try ProtectedFile.read(from: leaf))
        XCTAssertThrowsError(try ProtectedFile.write(Data(), to: leaf))
        XCTAssertEqual(try ProtectedFile.read(from: target), Data("original".utf8))
    }

    func testFIFOAndHardLinkedFilesAreRefused() throws {
        let fifo = directory.appendingPathComponent("fifo")
        XCTAssertEqual(mkfifo(fifo.path, 0o600), 0)
        XCTAssertThrowsError(try ProtectedFile.read(from: fifo))
        let file = directory.appendingPathComponent("one")
        try ProtectedFile.write(Data("original".utf8), to: file)
        let alias = directory.appendingPathComponent("two")
        XCTAssertEqual(link(file.path, alias.path), 0)
        XCTAssertThrowsError(try ProtectedFile.read(from: file))
        XCTAssertThrowsError(try ProtectedFile.write(Data(), to: file))
    }

    func testRevisionConflictPreservesExternalReplacement() throws {
        let file = directory.appendingPathComponent("state.json")
        let original = Data("original".utf8)
        try ProtectedFile.write(original, to: file)
        let revision = ProtectedFile.revision(of: original)
        let replacement = Data("external edit".utf8)
        try ProtectedFile.write(replacement, to: file)
        XCTAssertThrowsError(try ProtectedFile.write(Data("stale edit".utf8), to: file, expectedRevision: revision))
        XCTAssertEqual(try ProtectedFile.read(from: file), replacement)
    }

    func testReadSizeLimitRejectsOversizedFile() throws {
        let file = directory.appendingPathComponent("bounded")
        try ProtectedFile.write(Data(repeating: 7, count: 128), to: file)
        XCTAssertThrowsError(try ProtectedFile.read(from: file, maximumBytes: 64))
    }

    func testConcurrentUpdatesPreserveEveryWrite() async throws {
        let file = directory.appendingPathComponent("updates")
        let successes = await withTaskGroup(of: Bool.self, returning: Int.self) { group in
            for _ in 0..<20 {
                group.addTask {
                    do {
                        try ProtectedFile.update(at: file) { existing in
                            var data = existing ?? Data()
                            data.append(1)
                            return data
                        }
                        return true
                    } catch { return false }
                }
            }
            var count = 0
            for await succeeded in group { if succeeded { count += 1 } }
            return count
        }
        XCTAssertEqual(successes, 20)
        XCTAssertEqual(try ProtectedFile.read(from: file)?.count, 20)
    }


    func testPostCommitSideEffectRunsBeforeReleasingDirectoryLock() throws {
        let file = directory.appendingPathComponent("transaction")
        let otherDescriptor = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        XCTAssertGreaterThanOrEqual(otherDescriptor, 0)
        defer { close(otherDescriptor) }
        var called = false
        try ProtectedFile.update(at: file, afterWrite: {
            called = true
            XCTAssertEqual(flock(otherDescriptor, LOCK_EX | LOCK_NB), -1)
            XCTAssertEqual(errno, EWOULDBLOCK)
        }) { _ in Data("committed".utf8) }
        XCTAssertTrue(called)
        XCTAssertEqual(flock(otherDescriptor, LOCK_EX | LOCK_NB), 0)
        flock(otherDescriptor, LOCK_UN)
    }

}
