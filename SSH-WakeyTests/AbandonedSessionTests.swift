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
        try ProtectedFile.createPrivateDirectory(at: directory)
    }

    override func tearDown() async throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func session(owner: pid_t?, modified: Date? = nil) throws -> URL {
        let folder = directory.appendingPathComponent("s-\(UUID().uuidString.prefix(8))",
                                                      isDirectory: true)
        try ProtectedFile.createPrivateDirectory(at: folder)
        if let owner {
            try ProtectedFile.write(Data(String(owner).utf8),
                to: folder.appendingPathComponent(SSHSessionManager.ownerFileName))
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
        await SSHSessionManager.sweepAbandonedSessions(in: directory)
    }

    func testDisconnectAllAlsoCancelsAnAttemptBeforeItsTaskStarts() async {
        let manager = SSHSessionManager()
        let connection = SSHConnection(name: "Synthetic", username: "test", host: "audit.invalid")
        manager.connect(connection, mode: .unlock)
        XCTAssertTrue(manager.state(for: connection.id).isConnecting)
        manager.disconnectAll()
        for _ in 0..<20 where manager.state(for: connection.id).isConnecting {
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertEqual(manager.state(for: connection.id), .failed(SSHSessionManager.cancelledFailure))
    }

    func testAppLockRejectsConnectionAndTerminalRequestsAtTheModelBoundary() async {
        var directoryRequests = 0
        let manager = SSHSessionManager(makeSessionDirectory: {
            directoryRequests += 1
            throw POSIXError(.EACCES)
        })
        manager.forcesUnlock = false
        XCTAssertFalse(manager.isAppLocked)
        manager.setAppLocked(true)
        let connection = SSHConnection(name: "Synthetic", username: "test", host: "audit.invalid")
        manager.connect(connection, mode: .session)
        manager.openInTerminal(connection.id)
        await Task.yield()
        XCTAssertTrue(manager.isAppLocked)
        XCTAssertEqual(directoryRequests, 0)
        XCTAssertTrue(manager.states.isEmpty)
        XCTAssertTrue(manager.diagnostics.isEmpty)
        XCTAssertEqual(manager.activeSessionCount, 0)
        XCTAssertNil(manager.lastActionError)
    }

    func testAppLockClearsRetainedFailureAndActionState() async {
        let manager = SSHSessionManager()
        var connection = SSHConnection(name: "Synthetic", username: "test", host: "audit.invalid")
        connection.username = "unsafe user"
        manager.connect(connection, mode: .unlock)
        for _ in 0..<20 where manager.state(for: connection.id).isConnecting {
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        guard case .failed = manager.state(for: connection.id) else {
            return XCTFail("The invalid fixture must fail without opening a connection")
        }
        manager.openInTerminal(connection.id)
        XCTAssertNotNil(manager.lastActionError)
        manager.setAppLocked(true)
        XCTAssertTrue(manager.states.isEmpty)
        XCTAssertTrue(manager.diagnostics.isEmpty)
        XCTAssertNil(manager.lastActionError)
        XCTAssertEqual(manager.state(for: connection.id), .idle)
    }

    func testLockBeforeTaskStartsCannotRestoreStateEvenAfterImmediateUnlock() async {
        var directoryRequests = 0
        let manager = SSHSessionManager(makeSessionDirectory: {
            directoryRequests += 1
            throw POSIXError(.EACCES)
        })
        let connection = SSHConnection(name: "Synthetic", username: "test", host: "audit.invalid")
        manager.connect(connection, mode: .unlock)
        manager.setAppLocked(true)
        manager.setAppLocked(false)
        for _ in 0..<5 { await Task.yield() }
        XCTAssertEqual(directoryRequests, 0)
        XCTAssertTrue(manager.states.isEmpty)
        XCTAssertTrue(manager.diagnostics.isEmpty)
        XCTAssertEqual(manager.activeSessionCount, 0)
    }

    func testLateWakeFromBeforeLockCannotOverwriteOrCancelANewAttempt() async throws {
        let firstWake = expectation(description: "First attempt is suspended before SSH")
        let secondWake = expectation(description: "Fresh attempt is suspended before SSH")
        var pending: [CheckedContinuation<Void, Never>] = []
        var created: [URL] = []
        let manager = SSHSessionManager(wake: { _, _ in
            await withCheckedContinuation { continuation in
                pending.append(continuation)
                if pending.count == 1 { firstWake.fulfill() } else { secondWake.fulfill() }
            }
        }, makeSessionDirectory: {
            let folder = self.directory.appendingPathComponent("s-\(UUID().uuidString)")
            try ProtectedFile.createPrivateDirectory(at: folder)
            created.append(folder)
            return folder
        })
        defer { manager.setAppLocked(true) }
        let connection = SSHConnection(name: "Synthetic", username: "test", host: "audit.local")
        manager.connect(connection, mode: .unlock)
        await fulfillment(of: [firstWake], timeout: 2)
        guard pending.count == 1, created.count == 1 else { return XCTFail("First wake did not suspend") }
        manager.setAppLocked(true)
        XCTAssertFalse(FileManager.default.fileExists(atPath: created[0].path))
        XCTAssertTrue(manager.states.isEmpty)
        manager.setAppLocked(false)
        manager.connect(connection, mode: .unlock)
        await fulfillment(of: [secondWake], timeout: 2)
        guard pending.count == 2, created.count == 2 else {
            pending.first?.resume()
            return XCTFail("Unlock did not permit a fresh attempt")
        }
        pending[0].resume() // Deliberately ignores the old task's cancellation.
        for _ in 0..<5 { await Task.yield() }
        XCTAssertTrue(manager.state(for: connection.id).isConnecting)
        XCTAssertTrue(FileManager.default.fileExists(atPath: created[1].path))
        // A stale task's defer must not remove the fresh task from the map.
        manager.cancelConnect(connection.id)
        pending[1].resume()
        for _ in 0..<20 where manager.state(for: connection.id).isConnecting {
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertEqual(manager.state(for: connection.id), .failed(SSHSessionManager.cancelledFailure))
        XCTAssertFalse(FileManager.default.fileExists(atPath: created[1].path))
        XCTAssertEqual(manager.activeSessionCount, 0)
    }

    func testSweepingOnlyTheSuppliedRootPreservesLiveSessions() async throws {
        let live = try session(owner: getpid())
        let abandoned = try session(owner: try deadProcessID())
        await SSHSessionManager.sweepAbandonedSessions(in: directory)
        XCTAssertTrue(FileManager.default.fileExists(atPath: live.path))
        XCTAssertFalse(FileManager.default.fileExists(atPath: abandoned.path))
    }

    func testSymlinkedSessionIsNeverFollowedOrSwept() async throws {
        let target = try session(owner: getpid())
        let link = directory.appendingPathComponent("s-link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        XCTAssertFalse(SSHSessionManager.isAbandoned(link))
        await SSHSessionManager.sweepAbandonedSessions(in: directory)
        XCTAssertTrue(FileManager.default.fileExists(atPath: target.path))
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: link.path), target.path)
    }

    func testMalformedOwnerRecordsAreLeftAloneEvenWhenOld() throws {
        for text in ["", "garbage", "-1", "0", "{}", "{\"pid\":\"not-a-pid\"}"] {
            let folder = try session(owner: nil)
            try ProtectedFile.write(Data(text.utf8), to: folder.appendingPathComponent(SSHSessionManager.ownerFileName))
            try FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(-7200)], ofItemAtPath: folder.path)
            XCTAssertFalse(SSHSessionManager.isAbandoned(folder), text)
        }
    }

    func testSymlinkedOwnerRecordIsRefused() throws {
        let folder = try session(owner: nil)
        let target = directory.appendingPathComponent("owner-target")
        try ProtectedFile.write(Data(String(try deadProcessID()).utf8), to: target)
        let owner = folder.appendingPathComponent(SSHSessionManager.ownerFileName)
        try FileManager.default.createSymbolicLink(at: owner, withDestinationURL: target)
        XCTAssertFalse(SSHSessionManager.isAbandoned(folder))
    }

    func testJSONOwnerRequiresTheExactProcessStartTime() throws {
        let current = try XCTUnwrap(ProcessIdentity.read(getpid()))
        let folder = try session(owner: nil)
        let owner = folder.appendingPathComponent(SSHSessionManager.ownerFileName)
        try ProtectedFile.write(JSONEncoder().encode(current), to: owner)
        XCTAssertFalse(SSHSessionManager.isAbandoned(folder))
        let reused = ProcessIdentity(pid: current.pid, parent: current.parent, uid: current.uid,
            startedSeconds: current.startedSeconds + 1, startedMicroseconds: current.startedMicroseconds,
            path: current.path)
        try ProtectedFile.write(JSONEncoder().encode(reused), to: owner)
        XCTAssertTrue(SSHSessionManager.isAbandoned(folder), "a reused live PID does not own the older session")
    }
}
