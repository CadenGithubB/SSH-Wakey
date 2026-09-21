import AppKit
import Darwin
import Foundation
import Observation

/// An app-local inactivity lease. Input is observed only while it is being
/// delivered to this app; no global keyboard monitor or accessibility access is
/// used. The owner must invalidate outstanding authentication when onLock runs.
@MainActor
@Observable
final class AppLockController {
    enum Reason: Equatable {
        case manual
        case inactivity
        case screenLocked
        case sleep
        case userSwitch
    }

    nonisolated static let defaultInterval: TimeInterval = 300
    let interval: TimeInterval
    private(set) var enabled = false
    private(set) var isUnlocked = false
    private(set) var deadline: TimeInterval?
    private(set) var isMonitoring = false

    @ObservationIgnored private let now: @MainActor () -> TimeInterval
    @ObservationIgnored private let onLock: @MainActor (Reason) -> Void
    @ObservationIgnored private var lastObservedTime: TimeInterval?
    @ObservationIgnored private var timer: Timer?
    @ObservationIgnored private var inputMonitor: Any?
    @ObservationIgnored private var observers: [(NotificationCenter, NSObjectProtocol)] = []
    @ObservationIgnored private var distributedObservers: [NSObjectProtocol] = []

    init(interval: TimeInterval = AppLockController.defaultInterval,
         now: @escaping @MainActor () -> TimeInterval = AppLockController.continuousUptime,
         onLock: @escaping @MainActor (Reason) -> Void) {
        // Invalid configuration must not silently disable automatic locking.
        self.interval = interval.isFinite && (1...3600).contains(interval)
            ? interval : Self.defaultInterval
        self.now = now
        self.onLock = onLock
    }

    /// Synchronizes the store's state. Re-rendering or repeating an unchanged
    /// configuration never extends an existing lease.
    func configure(enabled: Bool, isUnlocked: Bool) {
        let hadLease = self.enabled && self.isUnlocked
        self.enabled = enabled
        guard enabled, isUnlocked else {
            self.isUnlocked = isUnlocked
            deadline = nil
            lastObservedTime = nil
            return
        }
        if hadLease {
            _ = checkDeadline()
            return
        }
        self.isUnlocked = true
        guard let instant = validatedTime() else { return }
        deadline = instant + interval
    }

    /// Checks expiration before extending the lease. A late click or keypress
    /// can never revive access that should already have expired. False means
    /// this event discovered expiration and must not reach its previous target.
    @discardableResult
    func recordActivity() -> Bool {
        guard enabled, isUnlocked else { return true }
        guard let instant = validatedTime() else { return false }
        guard let deadline, instant < deadline else {
            lockNow(reason: .inactivity)
            return false
        }
        self.deadline = instant + interval
        return true
    }

    /// Returns whether an enabled, unlocked lease is still valid.
    @discardableResult
    func checkDeadline() -> Bool {
        guard enabled, isUnlocked, let instant = validatedTime() else { return false }
        guard let deadline, instant < deadline else {
            lockNow(reason: .inactivity)
            return false
        }
        return true
    }

    /// Always notifies the owner, including while already locked or disabled.
    /// A sleep/lock/session event must also cancel a pending unlock operation.
    func lockNow(reason: Reason = .manual) {
        isUnlocked = false
        deadline = nil
        lastObservedTime = nil
        onLock(reason)
    }

    func startMonitoring() {
        guard !isMonitoring else { return }
        isMonitoring = true
        _ = checkDeadline()
        inputMonitor = NSEvent.addLocalMonitorForEvents(matching: [
            .keyDown, .keyUp, .flagsChanged,
            .leftMouseDown, .leftMouseUp, .rightMouseDown, .rightMouseUp, .otherMouseDown, .otherMouseUp,
            .leftMouseDragged, .rightMouseDragged, .otherMouseDragged, .scrollWheel, .mouseMoved,
        ]) { [weak self] event in
            let deliver = MainActor.assumeIsolated { self?.recordActivity() ?? true }
            return deliver ? event : nil
        }
        let timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { _ = self?.checkDeadline() }
        }
        self.timer = timer
        RunLoop.main.add(timer, forMode: .common)
        RunLoop.main.add(timer, forMode: .modalPanel)

        let workspace = NSWorkspace.shared.notificationCenter
        observe(workspace, NSWorkspace.willSleepNotification, reason: .sleep)
        observe(workspace, NSWorkspace.didWakeNotification, reason: .sleep)
        observe(workspace, NSWorkspace.screensDidSleepNotification, reason: .sleep)
        observe(workspace, NSWorkspace.sessionDidResignActiveNotification, reason: .userSwitch)
        observe(workspace, NSWorkspace.sessionDidBecomeActiveNotification, reason: .userSwitch)
        let activation = NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { _ = self?.checkDeadline() }
        }
        observers.append((NotificationCenter.default, activation))

        // These system notifications supplement the workspace lifecycle events.
        // The unlock notification is conservative catch-up if a lock was missed;
        // it never grants app access. Forging either notification only locks.
        let distributed = DistributedNotificationCenter.default()
        for name in ["com.apple.screenIsLocked", "com.apple.screenIsUnlocked"] {
            let token = distributed.addObserver(forName: Notification.Name(name), object: nil, queue: .main) {
                [weak self] _ in
                MainActor.assumeIsolated { self?.lockNow(reason: .screenLocked) }
            }
            distributedObservers.append(token)
        }
    }

    func stopMonitoring() {
        timer?.invalidate()
        timer = nil
        if let inputMonitor { NSEvent.removeMonitor(inputMonitor) }
        inputMonitor = nil
        for (center, token) in observers { center.removeObserver(token) }
        observers.removeAll()
        for token in distributedObservers { DistributedNotificationCenter.default().removeObserver(token) }
        distributedObservers.removeAll()
        isMonitoring = false
    }

    private func observe(_ center: NotificationCenter, _ name: Notification.Name, reason: Reason) {
        let token = center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.lockNow(reason: reason) }
        }
        observers.append((center, token))
    }

    private func validatedTime() -> TimeInterval? {
        let instant = now()
        guard instant.isFinite, instant >= 0,
              lastObservedTime.map({ instant >= $0 }) ?? true else {
            lockNow(reason: .inactivity)
            return nil
        }
        lastObservedTime = instant
        return instant
    }

    nonisolated static func continuousUptime() -> TimeInterval {
        var scale = mach_timebase_info_data_t()
        guard mach_timebase_info(&scale) == KERN_SUCCESS, scale.denom != 0 else { return .nan }
        return Double(mach_continuous_time()) * Double(scale.numer) / Double(scale.denom) / 1_000_000_000
    }

    deinit {
        timer?.invalidate()
        if let inputMonitor { NSEvent.removeMonitor(inputMonitor) }
        for (center, token) in observers { center.removeObserver(token) }
        for token in distributedObservers { DistributedNotificationCenter.default().removeObserver(token) }
    }
}
