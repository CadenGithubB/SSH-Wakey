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
    let detailReveal: DetailRevealController
    private(set) var authenticationError: String?
    @ObservationIgnored private var started = false
    @ObservationIgnored private let unlockAttempt: UnlockAttempt

    private final class UnlockAttempt { var id: UUID? }

    init(store: ConnectionStore, sessions: SSHSessionManager,
         detailReveal providedDetailReveal: DetailRevealController? = nil) {
        let detailReveal = providedDetailReveal ?? DetailRevealController()
        self.store = store
        self.sessions = sessions
        self.detailReveal = detailReveal
        let unlockAttempt = UnlockAttempt()
        self.unlockAttempt = unlockAttempt
        inactivity = AppLockController { [weak store, weak sessions, weak detailReveal] _ in
            guard let store, store.isAppLockEnabled || store.isAuthenticating else { return }
            unlockAttempt.id = nil
            // Revoke session capabilities first, including work awaiting a
            // network result. A cancelled unlock cannot publish after lock().
            sessions?.setAppLocked(true)
            detailReveal?.revoke()
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
        sessions.setAppLocked(store.access != .open || (store.isAuthenticating && !store.isExporting))
        inactivity.configure(enabled: store.isAppLockEnabled,
                             isUnlocked: store.access == .open)
        if store.access != .open || !store.isEncrypted { detailReveal.revoke() }
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

    /// Plain-text stores retain the existing display behavior. Encrypted
    /// stores need a separate, brief proof of user presence before details can
    /// be shown, even when the vault key was read silently from the Keychain.
    func authorizeDetailReveal() async -> Bool {
        guard authorizeCurrentAccess() else { return false }
        guard store.isEncrypted else { return true }
        guard await detailReveal.authorize() else { return false }
        return authorizeCurrentAccess() && store.isEncrypted
    }

    func revokeDetailReveal() { detailReveal.revoke() }

    /// Credentials precede the save dialog. Recheck the inactivity deadline
    /// after each suspension; a modal dialog must never extend authorization.
    func export(_ prepared: ConnectionStore.ExportPreparation,
                chooseDestination: () async -> URL?) async throws -> URL? {
        defer { store.cancelExport(prepared); refresh() }
        try await store.authorizeExport(prepared, validateAccess: validateExportAccess)
        try Task.checkCancellation()
        guard let url = await chooseDestination() else { return nil }
        try store.export(prepared, to: url, validateAccess: validateExportAccess)
        return url
    }

    private func validateExportAccess() -> Bool {
        inactivity.checkDeadline()
        // isAuthenticating remains true while choosing the destination so
        // mutations and overlapping operations stay disabled until completion.
        return store.access == .open
    }
}

@MainActor
protocol OwnerAuthenticating: AnyObject {
    func authenticate(reason: String) async throws
    func cancel()
}

@MainActor
final class SystemOwnerAuthenticator: OwnerAuthenticating {
    private var authentication: AppLockAuthentication?

    func authenticate(reason: String) async throws {
        cancel()
        let attempt = AppLockAuthentication(reason: reason)
        authentication = attempt
        defer {
            attempt.invalidate()
            if authentication === attempt { authentication = nil }
        }
        try await attempt.authenticateOwner()
    }

    func cancel() {
        authentication?.invalidate()
        authentication = nil
    }
}

/// A deliberately short display lease. It never unwraps a vault key: macOS
/// authentication only permits already-open details to be rendered briefly.
@MainActor
@Observable
final class DetailRevealController {
    static let defaultInterval: TimeInterval = 60

    let interval: TimeInterval
    private let now: () -> TimeInterval
    private let authenticator: any OwnerAuthenticating
    private var generation: UInt64 = 0
    private var expiration: Task<Void, Never>?

    private(set) var isAuthorized = false
    private(set) var isAuthenticating = false
    private(set) var deadline: TimeInterval?
    private(set) var problem: String?

    init(
        interval: TimeInterval = 60,
        now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
        authenticator: (any OwnerAuthenticating)? = nil
    ) {
        self.interval = interval.isFinite && interval >= 1 && interval <= 300
            ? interval : DetailRevealController.defaultInterval
        self.now = now
        self.authenticator = authenticator ?? SystemOwnerAuthenticator()
    }

    func authorize() async -> Bool {
        if checkDeadline() { return true }
        guard !isAuthenticating else { return false }

        generation &+= 1
        let attempt = generation
        isAuthenticating = true
        problem = nil
        do {
            try await authenticator.authenticate(reason: "Show encrypted SSH-Wakey connection details")
            guard attempt == generation, !Task.isCancelled else { throw CancellationError() }
            let instant = now()
            guard instant.isFinite && instant >= 0 else { throw DetailRevealError.authenticationFailed }
            deadline = instant + interval
            isAuthorized = true
            isAuthenticating = false
            scheduleExpiration(generation: attempt)
            return true
        } catch is CancellationError {
            if attempt == generation { isAuthenticating = false }
            return false
        } catch {
            if attempt == generation {
                isAuthenticating = false
                problem = error.localizedDescription
            }
            return false
        }
    }

    @discardableResult
    func checkDeadline() -> Bool {
        guard isAuthorized, let deadline else { return false }
        let instant = now()
        guard instant.isFinite, instant >= 0, instant < deadline else {
            revoke()
            return false
        }
        return true
    }

    func revoke() {
        generation &+= 1
        authenticator.cancel()
        expiration?.cancel()
        expiration = nil
        isAuthorized = false
        isAuthenticating = false
        deadline = nil
        problem = nil
    }

    /// The LocalAuthentication password window can temporarily make the app
    /// resign active. Cancelling in that transition would dismiss the very
    /// system prompt the user is trying to complete. Every other deactivation
    /// still revokes an existing display lease immediately.
    @discardableResult
    func revokeForApplicationDeactivation() -> Bool {
        guard !isAuthenticating else { return false }
        revoke()
        return true
    }

    func clearProblem() { problem = nil }

    private func scheduleExpiration(generation expected: UInt64) {
        expiration?.cancel()
        let nanoseconds = UInt64(interval * 1_000_000_000)
        expiration = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: nanoseconds)
            guard !Task.isCancelled, let self, self.generation == expected else { return }
            self.revoke()
        }
    }
}

extension Notification.Name {
    static let wakeyDidLock = Notification.Name("com.CadenGithubB.sshwakey.didLock")
}
