import CryptoKit
import Darwin
import Foundation
import Observation

/// The in-memory connection list the UI binds to, backed by
/// `ConnectionFileStore` and, when encryption is on, by `ConnectionVault`.
@MainActor
@Observable
final class ConnectionStore {

    enum Access: Equatable {
        /// Readable. The file may or may not be encrypted.
        case open
        /// Encrypted, and no key has opened it yet.
        case locked
        /// A file is on disk but could not be read. The in-memory list is empty
        /// and must not be written back, or the original would be replaced.
        case unavailable
    }

    private(set) var connections: [SSHConnection] = []
    /// Set when loading or saving fails so the window can show it instead of
    /// failing silently.
    private(set) var storageError: String?
    private(set) var access: Access = .open
    private(set) var isEncrypted = false
    /// True for the IT binary. The Standard build never sets this.
    private(set) var isManagedBuild: Bool
    /// Forced `OrganizationName`, if IT supplied one.
    private(set) var organizationName: String?
    /// Save Diagnostics / Activity. Forced off only when IT says so.
    private(set) var allowsDiagnostics = true

    private let fileStore: ConnectionFileStore
    private let keychainAccount: String
    private let preferences: any ManagedPreferenceReading
    private let linkCache: LinkAddressCache
    /// Non-nil only when encryption is on and the file has been opened.
    private var dataKey: SymmetricKey?
    private var vault: ConnectionVault?
    private let appLockKeys: any AppLockKeyProviding
    private var authentication: AppLockAuthentication?
    private var authenticationGeneration: UInt64 = 0
    private let storeIdentity = UUID()
    private var pendingPreparation: AppLockPreparation?
    private var pendingExport: ExportPreparation?
    private let exportAuthenticator: any OwnerAuthenticating
    private let exportClock: () -> TimeInterval
    private(set) var isAuthenticating = false
    var isExporting: Bool { pendingExport != nil }
    var isAppLockEnabled: Bool { vault?.keyProtection.isAppLockEnabled == true }
    var canUnlockWithSystemAuthentication: Bool { isAppLockEnabled && isLocked }

    /// Digest of the exact file opened. Saves refuse a changed/replaced file,
    /// including concurrent edits from another app instance.
    private var loadedRevision: ProtectedFile.Revision = .missing

    var fileURL: URL { fileStore.fileURL }
    var isLocked: Bool { access == .locked }
    /// The file exists and failed to load. Distinct from `isLocked`: there is
    /// nothing to Unlock, and Settings must not call this plain text.
    var isUnavailable: Bool { access == .unavailable }
    private var recoveryWarning: String? {
        guard let vault, !vault.hasUsableRecoverySlot else { return nil }
        return "The local key opened your connections, but the recovery slot is damaged. Restore a known-good vault copy before relying on recovery."
    }

    init(
        fileStore: ConnectionFileStore = ConnectionFileStore(),
        keychainAccount: String = KeychainKeyStore.defaultAccount,
        isManagedBuild: Bool = AppDistribution.isManagedBuild,
        preferences: any ManagedPreferenceReading = SystemManagedPreferences(),
        linkCache: LinkAddressCache? = nil,
        appLockKeys: any AppLockKeyProviding = SecureEnclaveAppLockKeys(),
        exportAuthenticator: (any OwnerAuthenticating)? = nil,
        exportClock: @escaping () -> TimeInterval = AppLockController.continuousUptime
    ) {
        self.exportAuthenticator = exportAuthenticator ?? SystemOwnerAuthenticator()
        self.exportClock = exportClock
        self.appLockKeys = appLockKeys
        self.fileStore = fileStore
        self.keychainAccount = keychainAccount
        self.isManagedBuild = isManagedBuild
        self.preferences = preferences
        self.linkCache = linkCache ?? LinkAddressCache(directoryURL: fileStore.directoryURL)
        load()
    }

    /// The store the app should use on launch.
    ///
    /// Under XCTest the app is launched as the test host, and it must not read
    /// the real saved connections or the real Keychain item. A rebuilt ad-hoc
    /// binary has a different signature, so macOS puts up a modal Keychain
    /// prompt that nothing can answer, and the whole test run hangs behind it.
    /// Tests should not depend on what happens to be on the machine either.
    static func forCurrentEnvironment() -> ConnectionStore {
        guard ProcessInfo.processInfo.environment["XCTestConfigurationFilePath"] != nil else {
            return ConnectionStore()
        }
        let scratch = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("SSH-WakeyTestHost-\(UUID().uuidString)", isDirectory: true)
        return ConnectionStore(
            fileStore: ConnectionFileStore(directoryURL: scratch),
            keychainAccount: "test-host-\(UUID().uuidString)")
    }

    func load() {
        cancelAuthentication()
        if isManagedBuild {
            applyManagedCatalog()
            return
        }
        do {
            let snapshot = try fileStore.readSnapshot()
            loadedRevision = snapshot.revision
            switch snapshot.contents {
            case .empty:
                adopt(connections: [], vault: nil, dataKey: nil, encrypted: false)
                storageError = nil
            case .plain(let saved):
                adopt(connections: saved, vault: nil, dataKey: nil, encrypted: false)
                storageError = nil
            case .encrypted(let stored):
                // Older versions duplicated hosts/MACs in a plaintext cache.
                // Standard connections already carry their MAC inside the vault.
                try linkCache.remove()
                try openEncrypted(stored)
            }
        } catch {
            refuseLoad(error)
        }
    }

    /// Keeps the damaged file on disk. Adopting an empty open store would let
    /// Add or Turn On Encryption replace it.
    private func refuseLoad(_ error: Error) {
        connections = []
        vault = nil
        dataKey = nil
        isEncrypted = false
        access = .unavailable
        storageError = error.localizedDescription
    }

    /// Opens an encrypted file with the Keychain key when it is there.
    ///
    /// Missing Keychain material is ordinary lock, not an error. A Keychain key
    /// that is present but cannot open the seal, or a payload that fails its
    /// AES-GCM check, is treated as an integrity problem and shown as such —
    /// while still leaving the file locked so the recovery passphrase can be
    /// tried when that still makes sense.
    private func openEncrypted(_ stored: ConnectionVault) throws {
        try VaultCrypto.check(stored)
        if stored.keyProtection.isAppLockEnabled {
            adopt(connections: [], vault: stored, dataKey: nil, encrypted: true)
            storageError = nil
            return
        }
        guard let keychainKey = try? KeychainKeyStore.load(account: keychainAccount) else {
            adopt(connections: [], vault: stored, dataKey: nil, encrypted: true)
            storageError = nil
            return
        }

        do {
            let key = try VaultCrypto.dataKey(from: stored, keychainKey: keychainKey)
            let saved = try VaultCrypto.connections(in: stored, using: key)
            adopt(connections: saved, vault: stored, dataKey: key, encrypted: true)
            storageError = recoveryWarning
        } catch let error as VaultError where error.suggestsIntegrityProblem {
            adopt(connections: [], vault: stored, dataKey: nil, encrypted: true)
            storageError = error.localizedDescription
        } catch {
            adopt(connections: [], vault: stored, dataKey: nil, encrypted: true)
            storageError = error.localizedDescription
        }
    }

    private func adopt(
        connections: [SSHConnection], vault: ConnectionVault?,
        dataKey: SymmetricKey?, encrypted: Bool
    ) {
        self.connections = connections.map(\.normalized)
        self.vault = vault
        self.dataKey = dataKey
        self.isEncrypted = encrypted
        self.access = (encrypted && dataKey == nil) ? .locked : .open
    }

    /// Re-reads a Jamf profile without touching the personal connections file.
    func reloadManagedPolicy() {
        guard isManagedBuild else { return }
        applyManagedCatalog()
    }

    private func applyManagedCatalog() {
        let policy = ManagedPolicy.load(from: preferences, acceptsManagedPreferences: true)
        organizationName = policy.organizationName
        allowsDiagnostics = policy.allowsDiagnostics
        connections = policy.connections.map { row in
            var copy = row
            if copy.hardwareAddress == nil {
                copy.hardwareAddress = linkCache.address(for: copy.host)
            }
            return copy
        }
        vault = nil
        dataKey = nil
        isEncrypted = false
        access = .open
        storageError = nil
    }

    // MARK: - Editing

    func add(_ connection: SSHConnection) {
        guard access == .open, !isAuthenticating, !isManagedBuild else { return }
        var added = connection.normalized
        let now = Date.stamp()
        added.createdAt = now
        added.modifiedAt = now
        added.revisions = []
        connections.append(added)
        sortAndSave()
    }

    /// Keeps the original creation date, and records what changed.
    func update(_ connection: SSHConnection) {
        guard access == .open, !isAuthenticating, !isManagedBuild,
              let index = connections.firstIndex(where: { $0.id == connection.id }) else { return }
        let previous = connections[index]

        var updated = connection.normalized
        updated.createdAt = previous.createdAt
        updated.revisions = previous.revisions
        if updated.host != previous.host {
            updated.hardwareAddress = nil
        }

        let changes = updated.changes(from: previous)
        if changes.isEmpty {
            updated.modifiedAt = previous.modifiedAt
        } else {
            let now = Date.stamp()
            updated.modifiedAt = now
            updated.revisions.append(
                ConnectionRevision(date: now, summary: changes.joined(separator: ", ")))
            if updated.revisions.count > SSHConnection.maxRevisions {
                updated.revisions.removeFirst(updated.revisions.count - SSHConnection.maxRevisions)
            }
        }

        connections[index] = updated
        sortAndSave()
    }

    /// Writes a MAC learned from ARP after a successful connect, so the next
    /// Wake can send a magic packet. Not typed by the person.
    func rememberLinkAddress(_ address: String, for id: SSHConnection.ID) {
        guard var connection = connection(with: id),
              let mac = NetworkWake.MACAddress(parsing: address) else { return }
        let stored = mac.colonSeparated
        if isManagedBuild {
            linkCache.store(stored, for: connection.host)
            applyManagedCatalog()
            return
        }
        guard connection.hardwareAddress != stored else { return }
        connection.hardwareAddress = stored
        update(connection)
    }

    func remove(id: SSHConnection.ID) {
        remove(ids: [id])
    }

    /// Drops several connections in one save, for the multi-select Remove.
    func remove(ids: Set<SSHConnection.ID>) {
        guard access == .open, !isAuthenticating, !isManagedBuild, !ids.isEmpty else { return }
        connections.removeAll { ids.contains($0.id) }
        sortAndSave()
    }

    func connection(with id: SSHConnection.ID?) -> SSHConnection? {
        guard let id else { return nil }
        return connections.first { $0.id == id }
    }

    private func sortAndSave() {
        connections.sort { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        do {
            if let dataKey, let vault {
                let updated = try VaultCrypto.replacingConnections(
                    in: vault, dataKey: dataKey, with: connections)
                loadedRevision = try fileStore.save(updated, expectedRevision: loadedRevision)
                self.vault = updated
            } else {
                loadedRevision = try fileStore.save(connections, expectedRevision: loadedRevision)
            }
            storageError = recoveryWarning
        } catch {
            storageError = "Could not save connections: \(error.localizedDescription)"
        }
    }

    // MARK: - Encryption

    /// Encrypts the file. The data key is wrapped twice: once with a new key
    /// kept in the Keychain, and once with this passphrase.
    func enableEncryption(passphrase: String) throws {
        guard !isManagedBuild, !isAuthenticating, !isEncrypted, access == .open else { return }

        guard passphrase.count >= VaultCrypto.minimumPassphraseLength else {
            throw VaultError.passphraseTooShort(VaultCrypto.minimumPassphraseLength)
        }
        let dataKey = VaultCrypto.makeDataKey()
        try linkCache.remove()
        var sealed: ConnectionVault?
        loadedRevision = try fileStore.commit(expectedRevision: loadedRevision) {
            let keychainKey = try KeychainKeyStore.loadOrCreate(account: keychainAccount)
            let created = try VaultCrypto.seal(
                connections, dataKey: dataKey, keychainKey: keychainKey, passphrase: passphrase)
            sealed = created
            return ConnectionFileStore.Document(vault: created)
        }

        self.vault = sealed
        self.dataKey = dataKey
        self.isEncrypted = true
        self.storageError = nil
    }

    /// Writes the file back in plain text and removes the Keychain key.
    ///
    /// Asks for the passphrase, for the same reason changing it does. The
    /// Keychain key alone would be enough to turn encryption off, which would
    /// let a moment at an unlocked app quietly downgrade the file to plain text
    /// and leave it that way without the owner noticing.
    func disableEncryption(passphrase: String) throws {
        guard !isManagedBuild, !isAuthenticating, isEncrypted, access == .open, let sealed = vault else { return }

        guard !isAppLockEnabled else { throw AppLockError.invalidPreparation }

        // Verify the recovered key against the payload as well as its wrapper.
        try VaultCrypto.verifyPassphrase(in: sealed, passphrase: passphrase)

        loadedRevision = try fileStore.commit(
            expectedRevision: loadedRevision,
            afterWrite: { try? KeychainKeyStore.delete(account: self.keychainAccount) }
        ) { ConnectionFileStore.Document(connections: connections) }

        vault = nil
        dataKey = nil
        isEncrypted = false
        storageError = nil
    }

    /// Discards an encrypted vault when it cannot or should not be recovered.
    ///
    /// Unlike `disableEncryption`, this deliberately needs no passphrase: it
    /// never reveals or preserves the protected rows. The revision check keeps
    /// a stale app instance from erasing a vault that another instance changed.
    func clearEncryptionAndConnections() throws {
        guard !isManagedBuild, !isAuthenticating, isEncrypted,
              access == .open || access == .locked else { return }

        loadedRevision = try fileStore.commit(
            expectedRevision: loadedRevision,
            afterWrite: { try? KeychainKeyStore.delete(account: self.keychainAccount) }
        ) { ConnectionFileStore.Document(connections: []) }

        connections = []
        vault = nil
        dataKey = nil
        isEncrypted = false
        access = .open
        storageError = nil
    }

    /// Opens with recovery. Legacy vaults repair their login-Keychain wrapper;
    /// protected vaults retain App Lock and open only this in-memory session.
    func unlock(withPassphrase passphrase: String) throws {
        guard !isManagedBuild, !isAuthenticating, let stored = vault else { return }

        let key = try VaultCrypto.dataKey(from: stored, passphrase: passphrase)
        let saved = try VaultCrypto.connections(in: stored, using: key)
        if stored.keyProtection.isAppLockEnabled {
            // Recovery opens this session but never turns a protected hardware
            // slot into an automatically readable login-Keychain slot.
            guard try fileStore.readSnapshot().revision == loadedRevision else {
                throw AppLockError.invalidPreparation
            }
            adopt(connections: saved, vault: stored, dataKey: key, encrypted: true)
            storageError = nil
            return
        }

        var updated: ConnectionVault?
        loadedRevision = try fileStore.commit(expectedRevision: loadedRevision) {
            let replacement = try KeychainKeyStore.loadOrCreate(account: keychainAccount)
            let rewrapped = try VaultCrypto.replacingKeychainKey(
                in: stored, dataKey: key, with: replacement)
            updated = rewrapped
            return ConnectionFileStore.Document(vault: rewrapped)
        }

        adopt(connections: saved, vault: updated, dataKey: key, encrypted: true)
        storageError = nil
    }

    /// Retires the old data key as well as the recovery wrapper. An old vault
    /// snapshot plus its passphrase must not decrypt subsequently saved rows.
    func changePassphrase(from current: String, to replacement: String) throws {
        guard !isManagedBuild, !isAuthenticating, access == .open, let vault, dataKey != nil else { return }
        guard !isAppLockEnabled else { throw AppLockError.invalidPreparation }
        try VaultCrypto.verifyPassphrase(in: vault, passphrase: current)
        let replacementDataKey = VaultCrypto.makeDataKey()
        var updated: ConnectionVault?
        loadedRevision = try fileStore.commit(expectedRevision: loadedRevision) {
            // Reusing the existing Keychain key avoids invalidating the old
            // wrapper if sealing or the atomic file replacement fails.
            let keychainKey = try KeychainKeyStore.loadOrCreate(account: keychainAccount)
            let rotated = try VaultCrypto.seal(
                connections, dataKey: replacementDataKey, keychainKey: keychainKey,
                passphrase: replacement)
            updated = rotated
            return ConnectionFileStore.Document(vault: rotated)
        }
        self.vault = updated
        self.dataKey = replacementDataKey
        storageError = nil
    }

    // MARK: - App Lock

    /// Contains only a new data key and ciphertext, never a recovery String.
    /// It is bound to one store revision and consumed once. Locking destroys the
    /// store's preparation even if a caller still holds the object.
    @MainActor
    final class AppLockPreparation {
        fileprivate enum Operation { case enable, disable, changePassphrase }
        fileprivate let operation: Operation
        fileprivate let storeIdentity: UUID
        fileprivate let generation: UInt64
        fileprivate let revision: ProtectedFile.Revision
        fileprivate var key: SymmetricKey?
        fileprivate var sealed: ConnectionVault?

        fileprivate init(operation: Operation, storeIdentity: UUID, generation: UInt64,
                         revision: ProtectedFile.Revision, key: SymmetricKey, sealed: ConnectionVault) {
            self.operation = operation
            self.storeIdentity = storeIdentity
            self.generation = generation
            self.revision = revision
            self.key = key
            self.sealed = sealed
        }

        fileprivate func clear() { key = nil; sealed = nil }
    }

    private func cancelAuthentication() {
        authenticationGeneration &+= 1
        if pendingExport != nil { exportAuthenticator.cancel() }
        pendingExport = nil
        authentication?.invalidate()
        authentication = nil
        pendingPreparation?.clear()
        pendingPreparation = nil
        isAuthenticating = false
    }

    func lock() {
        cancelAuthentication()
        guard isAppLockEnabled else { return }
        connections = []
        dataKey = nil
        access = .locked
        storageError = nil
    }

    func prepareEnableAppLock(passphrase: String) throws -> AppLockPreparation {
        guard !isAppLockEnabled else { throw AppLockError.invalidPreparation }
        return try prepareSecurityChange(.enable, current: passphrase, replacement: passphrase)
    }

    func prepareDisableAppLock(passphrase: String) throws -> AppLockPreparation {
        guard isAppLockEnabled else { throw AppLockError.invalidPreparation }
        return try prepareSecurityChange(.disable, current: passphrase, replacement: passphrase)
    }

    func prepareChangePassphrase(from current: String, to replacement: String) throws -> AppLockPreparation {
        try prepareSecurityChange(.changePassphrase, current: current, replacement: replacement)
    }

    private func prepareSecurityChange(_ operation: AppLockPreparation.Operation,
                                       current: String, replacement: String) throws -> AppLockPreparation {
        guard !isManagedBuild, !isAuthenticating, access == .open,
              let stored = vault, dataKey != nil else { throw AppLockError.invalidPreparation }
        try VaultCrypto.verifyPassphrase(in: stored, passphrase: current)
        let protection: ConnectionVault.KeyProtection
        switch operation {
        case .enable: protection = try appLockKeys.makeProtection()
        case .disable: protection = .legacy
        case .changePassphrase: protection = stored.keyProtection
        }
        // Retiring the data key makes a retained pre-migration legacy wrapper
        // useless against all content saved after App Lock is enabled.
        let key = VaultCrypto.makeDataKey()
        var sealed = try VaultCrypto.seal(
            connections, dataKey: key, keychainKey: VaultCrypto.makeDataKey(),
            passphrase: replacement, keyProtection: protection)
        sealed.keychainWrappedKey = Data() // filled only after protected authentication
        cancelAuthentication()
        let prepared = AppLockPreparation(operation: operation, storeIdentity: storeIdentity,
                                          generation: authenticationGeneration, revision: loadedRevision,
                                          key: key, sealed: sealed)
        pendingPreparation = prepared
        isAuthenticating = true
        return prepared
    }

    func enableAppLock(_ prepared: AppLockPreparation) async throws {
        try await completeSecurityChange(prepared, operation: .enable)
    }

    func disableAppLock(_ prepared: AppLockPreparation) async throws {
        try await completeSecurityChange(prepared, operation: .disable)
    }

    func changePassphrase(_ prepared: AppLockPreparation) async throws {
        try await completeSecurityChange(prepared, operation: .changePassphrase)
    }

    private func validate(_ prepared: AppLockPreparation,
                          operation: AppLockPreparation.Operation) throws {
        guard prepared === pendingPreparation, prepared.operation == operation,
              prepared.storeIdentity == storeIdentity, prepared.generation == authenticationGeneration,
              prepared.revision == loadedRevision, prepared.key != nil, prepared.sealed != nil,
              isAuthenticating, access == .open else { throw AppLockError.invalidPreparation }
        try Task.checkCancellation()
    }

    private func completeSecurityChange(_ prepared: AppLockPreparation,
                                        operation: AppLockPreparation.Operation) async throws {
        try validate(prepared, operation: operation)
        let generation = authenticationGeneration
        defer {
            prepared.clear()
            if generation == authenticationGeneration { cancelAuthentication() }
        }
        guard let sealed = prepared.sealed else { throw AppLockError.invalidPreparation }
        var protectedWrappingKey: SymmetricKey?
        if sealed.keyProtection.isAppLockEnabled {
            let context = AppLockAuthentication(reason: "Authorize SSH-Wakey App Lock")
            authentication = context
            protectedWrappingKey = try await appLockKeys.wrappingKey(for: sealed.keyProtection, authentication: context)
            try context.check()
        }
        try validate(prepared, operation: operation)
        guard let key = prepared.key else { throw AppLockError.invalidPreparation }
        var updated: ConnectionVault?
        loadedRevision = try fileStore.commit(
            expectedRevision: prepared.revision,
            afterWrite: {
                if operation == .enable { try? KeychainKeyStore.delete(account: self.keychainAccount) }
            }
        ) {
            let wrapping = try protectedWrappingKey ?? KeychainKeyStore.loadOrCreate(account: keychainAccount)
            let rewrapped = try VaultCrypto.replacingKeychainKey(in: sealed, dataKey: key, with: wrapping)
            updated = rewrapped
            return ConnectionFileStore.Document(vault: rewrapped)
        }
        self.vault = updated
        self.dataKey = key
        storageError = recoveryWarning
    }

    func unlockWithSystemAuthentication() async throws {
        guard !isManagedBuild, !isAuthenticating, isLocked,
              let stored = vault, stored.keyProtection.isAppLockEnabled else {
            throw AppLockError.invalidPreparation
        }
        try stored.keyProtection.validate()
        cancelAuthentication()
        let generation = authenticationGeneration
        let revision = loadedRevision
        let context = AppLockAuthentication()
        authentication = context
        isAuthenticating = true
        defer {
            context.invalidate()
            if generation == authenticationGeneration { cancelAuthentication() }
        }
        let wrapping = try await appLockKeys.wrappingKey(for: stored.keyProtection, authentication: context)
        try context.check()
        try Task.checkCancellation()
        guard generation == authenticationGeneration, revision == loadedRevision,
              try fileStore.readSnapshot().revision == revision else {
            throw AppLockError.invalidPreparation
        }
        let key = try VaultCrypto.dataKey(from: stored, keychainKey: wrapping)
        let saved = try VaultCrypto.connections(in: stored, using: key)
        adopt(connections: saved, vault: stored, dataKey: key, encrypted: true)
        storageError = recoveryWarning
    }

    /// A single-use proof of recovery verification for one vault revision.
    /// Contains no passphrase, key, or serialized connections.
    /// Only this store can create it; a lock/reload/cancel makes it unusable.
    @MainActor
    final class ExportPreparation {
        fileprivate let generation: UInt64
        fileprivate let revision: ProtectedFile.Revision
        fileprivate let createdAt: TimeInterval
        fileprivate var started = false
        fileprivate var ownerAuthenticated = false

        fileprivate init(generation: UInt64,
                         revision: ProtectedFile.Revision, createdAt: TimeInterval) {
            self.generation = generation
            self.revision = revision
            self.createdAt = createdAt
        }
    }

    enum ExportError: LocalizedError {
        case invalidAuthorization, expired, activeStoreDestination

        var errorDescription: String? {
            switch self {
            case .invalidAuthorization:
                return "The export was cancelled or the saved connections changed. Start the export again."
            case .expired:
                return "Export authorization expired. Start the export again."
            case .activeStoreDestination:
                return "Choose a different destination. An export cannot replace the active saved connections file."
            }
        }
    }

    /// Verify recovery in the native field's synchronous scope, then discard
    /// the phrase before awaiting macOS. No readable output is created here.
    func prepareExport(passphrase: String? = nil) throws -> ExportPreparation {
        guard !isManagedBuild else { throw ConnectionFileStore.StoreError.encrypted }
        guard !isAuthenticating else { throw AppLockError.invalidPreparation }
        guard access == .open else {
            throw access == .unavailable
                ? ConnectionFileStore.StoreError.unreadable("the saved file could not be opened")
                : ConnectionFileStore.StoreError.encrypted
        }

        guard try fileStore.readSnapshot().revision == loadedRevision else {
            throw ExportError.invalidAuthorization
        }

        if let vault {
            guard let passphrase else { throw VaultError.wrongPassphrase }
            try VaultCrypto.verifyPassphrase(in: vault, passphrase: passphrase)
        }

        let instant = exportClock()
        guard instant.isFinite else { throw ExportError.expired }
        cancelAuthentication()
        let prepared = ExportPreparation(generation: authenticationGeneration,
                                         revision: loadedRevision, createdAt: instant)
        pendingExport = prepared
        isAuthenticating = true
        return prepared
    }

    func cancelExport(_ prepared: ExportPreparation? = nil) {
        if pendingExport != nil, prepared == nil || prepared === pendingExport {
            cancelAuthentication()
        }
    }

    private func validateExportDestination(_ url: URL) throws {
        guard url.isFileURL,
              url.resolvingSymlinksInPath().standardizedFileURL
                != fileURL.resolvingSymlinksInPath().standardizedFileURL else {
            throw ExportError.activeStoreDestination
        }
        // Case-insensitive volumes can name the same inode with different
        // spelling even when the normalized URLs do not compare equal.
        var source = stat()
        var destination = stat()
        if lstat(fileURL.path, &source) == 0, lstat(url.path, &destination) == 0,
           source.st_dev == destination.st_dev, source.st_ino == destination.st_ino {
            throw ExportError.activeStoreDestination
        }
    }

    private func validateExport(_ prepared: ExportPreparation) throws {
        try Task.checkCancellation()
        guard prepared === pendingExport, prepared.generation == authenticationGeneration,
              prepared.revision == loadedRevision, access == .open, isAuthenticating,
              !isManagedBuild else { throw ExportError.invalidAuthorization }
        let instant = exportClock()
        guard instant.isFinite, instant >= prepared.createdAt,
              instant - prepared.createdAt < 60 else { throw ExportError.expired }
    }

    /// Run before presenting a destination picker. Never accepts a prior
    /// unlock/display lease: every export creates a new system challenge.
    func authorizeExport(_ prepared: ExportPreparation, validateAccess: () -> Bool) async throws {
        guard prepared === pendingExport, !prepared.started else {
            throw ExportError.invalidAuthorization
        }
        prepared.started = true
        defer {
            if prepared === pendingExport, !prepared.ownerAuthenticated { cancelAuthentication() }
        }
        try validateExport(prepared)
        try await exportAuthenticator.authenticate(reason: "Export a readable copy of your SSH-Wakey connections")
        guard validateAccess() else { throw ExportError.invalidAuthorization }
        try validateExport(prepared)
        guard try fileStore.readSnapshot().revision == prepared.revision else {
            throw ExportError.invalidAuthorization
        }
        prepared.ownerAuthenticated = true
    }

    /// The only export writer. Both checks must still authorize this exact
    /// revision after the save dialog closes. Success and failure both consume
    /// the authorization; no retry or second destination can reuse it.
    func export(_ prepared: ExportPreparation, to url: URL, validateAccess: () -> Bool) throws {
        defer {
            if prepared === pendingExport { cancelAuthentication() }
        }
        guard prepared.ownerAuthenticated, validateAccess() else {
            throw ExportError.invalidAuthorization
        }
        try validateExport(prepared)
        guard try fileStore.readSnapshot().revision == prepared.revision else {
            throw ExportError.invalidAuthorization
        }
        try validateExportDestination(url)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(ConnectionFileStore.Document(connections: connections))
        try validateExport(prepared)
        try ProtectedFile.write(data, to: url)
    }
}
