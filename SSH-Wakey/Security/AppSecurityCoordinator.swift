import AppKit
import Foundation
import Observation

/// Coordinates the key's lifetime with all capabilities granted by an open vault.
/// View visibility is not the access boundary: the store and session manager
/// separately refuse work after their authorization has been revoked.
@MainActor
@Observable
final class AppSecurityCoordinator {
    let store: ConnectionStore
    let sessions: SSHSessionManager
    let inactivity: AppLockController
    private(set) var authenticationError: String?
    @ObservationIgnored private var started = false
    @ObservationIgnored private let unlockAttempt: UnlockAttempt

    private final class UnlockAttempt { var id: UUID? }

    init(store: ConnectionStore, sessions: SSHSessionManager) {
        self.store = store
        self.sessions = sessions
        let unlockAttempt = UnlockAttempt()
        self.unlockAttempt = unlockAttempt
        inactivity = AppLockController { [weak store, weak sessions] _ in
            guard let store, store.isAppLockEnabled || store.isAuthenticating else { return }
            unlockAttempt.id = nil
            // Revoke session capabilities first, including work awaiting a
            // network result. A cancelled unlock cannot publish after lock().
            sessions?.setAppLocked(true)
            store.lock()
            RecoveryClipboard.clearIfOwned()
            NotificationCenter.default.post(name: .wakeyDidLock, object: nil)
        }
    }

    func start() {
        refresh()
        guard !started else { return }
        started = true
        inactivity.startMonitoring()
    }

    func refresh() {
        sessions.setAppLocked(store.access != .open || store.isAuthenticating)
        inactivity.configure(enabled: store.isAppLockEnabled,
                             isUnlocked: store.access == .open)
    }

    func lockNow() {
        guard store.isAppLockEnabled || store.isAuthenticating else { return }
        authenticationError = nil
        inactivity.lockNow()
        refresh()
    }

    func unlock() async {
        guard !store.isAuthenticating else { return }
        let id = UUID()
        unlockAttempt.id = id
        authenticationError = nil
        do { try await store.unlockWithSystemAuthentication() }
        catch is CancellationError { }
        catch {
            if unlockAttempt.id == id { authenticationError = error.localizedDescription }
        }
        if unlockAttempt.id == id { unlockAttempt.id = nil }
        refresh()
    }

    /// Used before actions reached through menus as well as the main window.
    /// An event delivered after the deadline must never revive an expired lease.
    func authorizeCurrentAccess() -> Bool {
        inactivity.checkDeadline()
        return store.access == .open && !store.isAuthenticating
    }
}

extension Notification.Name {
    static let wakeyDidLock = Notification.Name("com.CadenGithubB.sshwakey.didLock")
}
