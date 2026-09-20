import AppKit
import XCTest
@testable import SSH_Wakey

@MainActor
final class AppLockControllerTests: XCTestCase {
    private var instant: TimeInterval = 1000
    private var reasons: [AppLockController.Reason] = []

    private func makeController(interval: TimeInterval = 300) -> AppLockController {
        AppLockController(interval: interval, now: { [unowned self] in self.instant },
                          onLock: { [unowned self] in self.reasons.append($0) })
    }

    func testStartsWithoutAnUnlockedLeaseOrSystemMonitoring() {
        let controller = makeController()
        XCTAssertEqual(controller.interval, 300)
        XCTAssertFalse(controller.enabled)
        XCTAssertFalse(controller.isUnlocked)
        XCTAssertFalse(controller.isMonitoring)
        XCTAssertNil(controller.deadline)
        XCTAssertFalse(controller.checkDeadline())
        XCTAssertTrue(reasons.isEmpty)
    }

    func testUnlockStartsAFiveMinuteLeaseUsingTheInjectedMonotonicClock() {
        let controller = makeController()
        controller.configure(enabled: true, isUnlocked: true)
        XCTAssertEqual(controller.deadline, 1300)
        instant = 1299.99
        XCTAssertTrue(controller.checkDeadline())
        XCTAssertTrue(reasons.isEmpty)
    }

    func testActivityBeforeExpiryRenewsTheLease() {
        let controller = makeController()
        controller.configure(enabled: true, isUnlocked: true)
        instant = 1200
        controller.recordActivity()
        XCTAssertEqual(controller.deadline, 1500)
        instant = 1300
        XCTAssertTrue(controller.checkDeadline())
    }

    func testActivityAtOrAfterExpiryCannotReviveAccess() {
        for delay in [300.0, 301, 3600] {
            instant = 1000
            let controller = makeController()
            controller.configure(enabled: true, isUnlocked: true)
            instant += delay
            XCTAssertFalse(controller.recordActivity(), "the event that discovers expiry must be dropped")
            XCTAssertFalse(controller.isUnlocked)
            XCTAssertNil(controller.deadline)
        }
        XCTAssertEqual(reasons, [.inactivity, .inactivity, .inactivity])
    }

    func testInputWhileAlreadyLockedCanReachTheUnlockButton() {
        let controller = makeController()
        controller.configure(enabled: true, isUnlocked: false)
        XCTAssertTrue(controller.recordActivity())
        XCTAssertTrue(reasons.isEmpty)
    }

    func testDeadlineChecksLockExactlyOnceUntilAnotherUnlock() {
        let controller = makeController()
        controller.configure(enabled: true, isUnlocked: true)
        instant = 1300
        XCTAssertFalse(controller.checkDeadline())
        XCTAssertFalse(controller.checkDeadline())
        controller.recordActivity()
        XCTAssertEqual(reasons, [.inactivity])
    }

    func testRepeatedConfigurationDoesNotRenewTheLease() {
        let controller = makeController()
        controller.configure(enabled: true, isUnlocked: true)
        instant = 1200
        controller.configure(enabled: true, isUnlocked: true)
        XCTAssertEqual(controller.deadline, 1300)
        instant = 1300
        controller.configure(enabled: true, isUnlocked: true)
        XCTAssertFalse(controller.isUnlocked)
        XCTAssertEqual(reasons, [.inactivity])
    }

    func testAFreshUnlockStartsANewLease() {
        let controller = makeController()
        controller.configure(enabled: true, isUnlocked: true)
        controller.lockNow()
        controller.configure(enabled: true, isUnlocked: false)
        instant = 1400
        controller.configure(enabled: true, isUnlocked: true)
        XCTAssertTrue(controller.isUnlocked)
        XCTAssertEqual(controller.deadline, 1700)
    }

    func testDisablingPolicyClearsItsDeadlineAndActivityDoesNotCreateOne() {
        let controller = makeController()
        controller.configure(enabled: true, isUnlocked: true)
        controller.configure(enabled: false, isUnlocked: true)
        instant = 4000
        controller.recordActivity()
        XCTAssertFalse(controller.checkDeadline())
        XCTAssertNil(controller.deadline)
        XCTAssertTrue(reasons.isEmpty)
    }

    func testExternalStoreLockClearsTheLeaseWithoutRecursivelyCallingOnLock() {
        let controller = makeController()
        controller.configure(enabled: true, isUnlocked: true)
        controller.configure(enabled: true, isUnlocked: false)
        XCTAssertFalse(controller.isUnlocked)
        XCTAssertNil(controller.deadline)
        XCTAssertTrue(reasons.isEmpty)
    }

    func testLifecycleEventsStillInvalidatePendingAuthenticationWhileAlreadyLocked() {
        let controller = makeController()
        for reason in [AppLockController.Reason.screenLocked, .sleep, .userSwitch, .screenLocked] {
            controller.lockNow(reason: reason)
        }
        XCTAssertEqual(reasons, [.screenLocked, .sleep, .userSwitch, .screenLocked])
        XCTAssertFalse(controller.isUnlocked)
        XCTAssertNil(controller.deadline)
    }

    func testMonitoringWiresLocalSleepNotificationAndStartingTwiceDoesNotDuplicateCallbacks() {
        let controller = makeController()
        controller.configure(enabled: true, isUnlocked: true)
        controller.startMonitoring()
        controller.startMonitoring()
        defer { controller.stopMonitoring() }
        XCTAssertTrue(controller.isMonitoring)

        // This is an in-process notification only. It does not sleep the Mac
        // or post anything through DistributedNotificationCenter.
        NSWorkspace.shared.notificationCenter.post(name: NSWorkspace.willSleepNotification, object: nil)

        XCTAssertEqual(reasons, [.sleep])
        XCTAssertFalse(controller.isUnlocked)
        XCTAssertNil(controller.deadline)
    }

    func testMonitoringWiresLocalUserSwitchNotificationAndStoppingRemovesLifecycleObservers() {
        let controller = makeController()
        controller.configure(enabled: true, isUnlocked: false)
        controller.startMonitoring()
        defer { controller.stopMonitoring() }
        let notifications = NSWorkspace.shared.notificationCenter
        notifications.post(name: NSWorkspace.sessionDidResignActiveNotification, object: nil)
        XCTAssertEqual(reasons, [.userSwitch], "a pending unlock must be invalidated even without an open lease")

        controller.stopMonitoring()
        XCTAssertFalse(controller.isMonitoring)
        controller.configure(enabled: true, isUnlocked: true)
        notifications.post(name: NSWorkspace.sessionDidResignActiveNotification, object: nil)
        notifications.post(name: NSWorkspace.willSleepNotification, object: nil)

        XCTAssertEqual(reasons, [.userSwitch])
        XCTAssertTrue(controller.isUnlocked)
        XCTAssertEqual(controller.deadline, 1300)
    }

    func testLockCallbackObservesRevokedAccessAndCanSynchronizeTheStore() {
        var controller: AppLockController!
        controller = AppLockController(now: { self.instant }, onLock: { _ in
            XCTAssertFalse(controller.isUnlocked)
            XCTAssertNil(controller.deadline)
            controller.configure(enabled: true, isUnlocked: false)
        })
        controller.configure(enabled: true, isUnlocked: true)
        controller.lockNow()
        XCTAssertFalse(controller.isUnlocked)
        // Break the deliberately reentrant test callback's reference cycle.
        controller = nil
    }

    func testInvalidOrBackwardClockFailsClosed() {
        for invalid in [Double.nan, .infinity, -.infinity, -1, 999] {
            instant = 1000
            let controller = makeController()
            controller.configure(enabled: true, isUnlocked: true)
            instant = invalid
            controller.recordActivity()
            XCTAssertFalse(controller.isUnlocked)
            XCTAssertNil(controller.deadline)
        }
        XCTAssertEqual(reasons, Array(repeating: .inactivity, count: 5))
    }

    func testInvalidClockCannotStartAnUnlockedLease() {
        instant = .nan
        let controller = makeController()
        controller.configure(enabled: true, isUnlocked: true)
        XCTAssertFalse(controller.isUnlocked)
        XCTAssertNil(controller.deadline)
        XCTAssertEqual(reasons, [.inactivity])
    }

    func testInvalidIntervalsUseTheFiveMinuteDefault() {
        for interval in [Double.nan, .infinity, -.infinity, -1, 0, 0.5, 3601] {
            XCTAssertEqual(makeController(interval: interval).interval, 300)
        }
        XCTAssertEqual(makeController(interval: 1).interval, 1)
        XCTAssertEqual(makeController(interval: 3600).interval, 3600)
    }
}

/// Uses only uniquely named synthetic pasteboards, never the system clipboard.
@MainActor
final class RecoveryClipboardTests: XCTestCase {
    private var pasteboards: [NSPasteboard] = []

    private func makePasteboard() -> NSPasteboard {
        let board = NSPasteboard(name: .init("com.CadenGithubB.sshwakey.clipboard-test.\(UUID().uuidString)"))
        pasteboards.append(board)
        return board
    }

    @discardableResult
    private func write(_ value: String, to board: NSPasteboard) -> Int {
        board.clearContents()
        XCTAssertTrue(board.setString(value, forType: .string))
        return board.changeCount
    }

    override func tearDown() async throws {
        for board in pasteboards {
            RecoveryClipboard.clearIfOwned(pasteboard: board)
            board.clearContents()
            board.releaseGlobally()
        }
        pasteboards.removeAll()
    }

    func testLockClearsTheExplicitlyCopiedRecoveryPhrase() {
        let board = makePasteboard()
        let stamp = write("synthetic recovery phrase", to: board)
        RecoveryClipboard.remember(changeCount: stamp)

        RecoveryClipboard.clearIfOwned(pasteboard: board)

        XCTAssertNil(board.string(forType: .string))
        XCTAssertNotEqual(board.changeCount, stamp)
    }

    func testLockPreservesNewerUnrelatedClipboardContents() {
        let board = makePasteboard()
        let stamp = write("synthetic recovery phrase", to: board)
        RecoveryClipboard.remember(changeCount: stamp)
        let unrelatedStamp = write("unrelated copied text", to: board)
        XCTAssertNotEqual(unrelatedStamp, stamp)

        RecoveryClipboard.clearIfOwned(pasteboard: board)

        XCTAssertEqual(board.string(forType: .string), "unrelated copied text")
        XCTAssertEqual(board.changeCount, unrelatedStamp)
    }

    func testAnOldExpiryCannotClearANewerOwnedCopyOrForgetItsOwnership() {
        let board = makePasteboard()
        let first = write("first synthetic phrase", to: board)
        RecoveryClipboard.remember(changeCount: first)
        let second = write("second synthetic phrase", to: board)
        RecoveryClipboard.remember(changeCount: second)

        RecoveryClipboard.clearIfOwned(changeCount: first, pasteboard: board)
        XCTAssertEqual(board.string(forType: .string), "second synthetic phrase")
        RecoveryClipboard.clearIfOwned(changeCount: second, pasteboard: board)
        XCTAssertNil(board.string(forType: .string))
    }

    func testAnExternalReplacementDiscardsTheRememberedOwnershipGeneration() {
        let original = makePasteboard()
        let originalStamp = write("synthetic original generation", to: original)
        RecoveryClipboard.remember(changeCount: originalStamp)
        let replacement = makePasteboard()
        var replacementStamp = write("unrelated replacement", to: replacement)
        if replacementStamp == originalStamp {
            replacementStamp = write("unrelated replacement", to: replacement)
        }
        XCTAssertNotEqual(replacementStamp, originalStamp)

        // A second named board supplies a changed generation while retaining
        // the original generation as a probe of the private ownership state.
        RecoveryClipboard.clearIfOwned(pasteboard: replacement)
        RecoveryClipboard.clearIfOwned(changeCount: originalStamp, pasteboard: original)

        XCTAssertEqual(replacement.string(forType: .string), "unrelated replacement")
        XCTAssertEqual(original.string(forType: .string), "synthetic original generation",
                       "a stale remembered owner would incorrectly clear this generation")
    }
}
