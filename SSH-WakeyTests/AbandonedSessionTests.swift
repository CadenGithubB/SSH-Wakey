import XCTest
@testable import SSH_Wakey

/// Quitting disconnects every session. A crash or a Force Quit does not: the
/// ssh master is reparented and keeps holding an authenticated connection with a
/// control socket still sitting in the temporary folder. These cover telling
/// that apart from a session belonging to another running copy of the app.
@MainActor
final class AbandonedSessionTests: XCTestCase {

    private var directory: URL!

    override func setUp() async throws {
        directory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("SSH-WakeyAbandoned-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func session(owner: pid_t?, modified: Date? = nil) throws -> URL {
        let folder = directory.appendingPathComponent("s-\(UUID().uuidString.prefix(8))",
                                                      isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        if let owner {
            try Data(String(owner).utf8)
                .write(to: folder.appendingPathComponent(SSHSessionManager.ownerFileName))
        }
        if let modified {
            try FileManager.default.setAttributes(
                [.modificationDate: modified], ofItemAtPath: folder.path)
        }
        return folder
    }

    /// A pid that has certainly finished.
    private func deadProcessID() throws -> pid_t {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try process.run()
        let pid = process.processIdentifier
        process.waitUntilExit()
        return pid
    }

    func testASessionOwnedByThisProcessIsNotAbandoned() throws {
        XCTAssertFalse(SSHSessionManager.isAbandoned(try session(owner: getpid())))
    }

    func testASessionWhoseOwnerHasGoneIsAbandoned() throws {
        XCTAssertTrue(SSHSessionManager.isAbandoned(try session(owner: try deadProcessID())))
    }

    /// The risk to avoid is a second copy of the app tearing down the first
    /// copy's live sessions.
    func testASessionOwnedByAnotherRunningProcessIsLeftAlone() throws {
        let other = Process()
        other.executableURL = URL(fileURLWithPath: "/bin/sleep")
        other.arguments = ["30"]
        try other.run()
        defer { other.terminate() }

        XCTAssertFalse(SSHSessionManager.isAbandoned(try session(owner: other.processIdentifier)))
    }

    func testAFolderWithNoOwnerIsLeftAloneWhileItCouldStillBeInUse() throws {
        XCTAssertFalse(SSHSessionManager.isAbandoned(try session(owner: nil)))
    }

    func testAnOldFolderWithNoOwnerIsCleared() throws {
        let old = Date().addingTimeInterval(-7200)
        XCTAssertTrue(SSHSessionManager.isAbandoned(try session(owner: nil, modified: old)))
    }

    func testSweepingIsSafeWhenThereIsNothingThere() async {
        await SSHSessionManager.sweepAbandonedSessions()
    }
}
