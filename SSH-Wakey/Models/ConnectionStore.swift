import CryptoKit
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
    }

    private(set) var connections: [SSHConnection] = []
    /// Set when loading or saving fails so the window can show it instead of
    /// failing silently.
    private(set) var storageError: String?
    private(set) var access: Access = .open
    private(set) var isEncrypted = false

    private let fileStore: ConnectionFileStore
    private let keychainAccount: String
    /// Non-nil only when encryption is on and the file has been opened.
    private var dataKey: SymmetricKey?
    private var vault: ConnectionVault?

    var fileURL: URL { fileStore.fileURL }
    var isLocked: Bool { access == .locked }

    init(
        fileStore: ConnectionFileStore = ConnectionFileStore(),
        keychainAccount: String = KeychainKeyStore.defaultAccount
    ) {
        self.fileStore = fileStore
        self.keychainAccount = keychainAccount
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
        do {
            switch try fileStore.read() {
            case .empty:
                adopt(connections: [], vault: nil, dataKey: nil, encrypted: false)
            case .plain(let saved):
                adopt(connections: saved, vault: nil, dataKey: nil, encrypted: false)
            case .encrypted(let stored):
                // The Keychain slot is the silent path. When it is missing the
                // file is not lost, it is locked, and the recovery passphrase
                // opens it.
                if let keychainKey = try? KeychainKeyStore.load(account: keychainAccount),
                   let key = try? VaultCrypto.dataKey(from: stored, keychainKey: keychainKey),
                   let saved = try? VaultCrypto.connections(in: stored, using: key) {
                    adopt(connections: saved, vault: stored, dataKey: key, encrypted: true)
                } else {
                    adopt(connections: [], vault: stored, dataKey: nil, encrypted: true)
                }
            }
            storageError = nil
        } catch {
            adopt(connections: [], vault: nil, dataKey: nil, encrypted: false)
            storageError = error.localizedDescription
        }
    }

    private func adopt(
        connections: [SSHConnection], vault: ConnectionVault?,
        dataKey: SymmetricKey?, encrypted: Bool
    ) {
        self.connections = connections
        self.vault = vault
        self.dataKey = dataKey
        self.isEncrypted = encrypted
        self.access = (encrypted && dataKey == nil) ? .locked : .open
    }

    // MARK: - Editing

    func add(_ connection: SSHConnection) {
        guard access == .open else { return }
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
        guard access == .open,
              let index = connections.firstIndex(where: { $0.id == connection.id }) else { return }
        let previous = connections[index]

        var updated = connection.normalized
        updated.createdAt = previous.createdAt
        updated.revisions = previous.revisions

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

    func remove(id: SSHConnection.ID) {
        guard access == .open else { return }
        connections.removeAll { $0.id == id }
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
                try fileStore.save(updated)
                self.vault = updated
            } else {
                try fileStore.save(connections)
            }
            storageError = nil
        } catch {
            storageError = "Could not save connections: \(error.localizedDescription)"
        }
    }

    // MARK: - Encryption

    /// Encrypts the file. The data key is wrapped twice: once with a new key
    /// kept in the Keychain, and once with this passphrase.
    func enableEncryption(passphrase: String) throws {
        guard !isEncrypted, access == .open else { return }

        let dataKey = VaultCrypto.makeDataKey()
        let keychainKey = KeychainKeyStore.makeKey()
        let sealed = try VaultCrypto.seal(
            connections, dataKey: dataKey, keychainKey: keychainKey, passphrase: passphrase)

        try KeychainKeyStore.save(keychainKey, account: keychainAccount)
        try fileStore.save(sealed)

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
        guard isEncrypted, access == .open, let sealed = vault else { return }

        // Throws .wrongPassphrase if it does not open the recovery slot.
        _ = try VaultCrypto.dataKey(from: sealed, passphrase: passphrase)

        try fileStore.save(connections)
        try? KeychainKeyStore.delete(account: keychainAccount)

        vault = nil
        dataKey = nil
        isEncrypted = false
        storageError = nil
    }

    /// Opens a locked file with the recovery passphrase, then puts a fresh key
    /// in the Keychain so the next launch is silent again.
    func unlock(withPassphrase passphrase: String) throws {
        guard let stored = vault else { return }

        let key = try VaultCrypto.dataKey(from: stored, passphrase: passphrase)
        let saved = try VaultCrypto.connections(in: stored, using: key)

        let replacement = KeychainKeyStore.makeKey()
        let updated = try VaultCrypto.replacingKeychainKey(
            in: stored, dataKey: key, with: replacement)
        try KeychainKeyStore.save(replacement, account: keychainAccount)
        try fileStore.save(updated)

        adopt(connections: saved, vault: updated, dataKey: key, encrypted: true)
        storageError = nil
    }

    /// Swaps the recovery passphrase, after proving the current one is known.
    ///
    /// The app already holds the data key, so it could change the passphrase
    /// without asking. It asks anyway: otherwise anyone who reached an unlocked
    /// app for a moment could set a passphrase of their own and read the file
    /// at leisure later, turning a brief lapse into lasting access.
    ///
    /// The contents are not re-encrypted. Only the wrapping of the data key
    /// changes.
    func changePassphrase(from current: String, to replacement: String) throws {
        guard let vault, dataKey != nil else { return }

        // Throws .wrongPassphrase if it does not open the recovery slot.
        let verified = try VaultCrypto.dataKey(from: vault, passphrase: current)

        let updated = try VaultCrypto.replacingPassphrase(
            in: vault, dataKey: verified, with: replacement)
        try fileStore.save(updated)
        self.vault = updated
    }

    /// Writes a readable copy, in the same format as an unencrypted file, so it
    /// can be read by eye or put straight back.
    ///
    /// Asks for the passphrase when the file is encrypted, so that producing a
    /// permanent plain-text copy needs the same proof as the other two ways of
    /// ending up with one. The passphrase is verified immediately before the
    /// write, so it is held for as short a time as possible.
    func export(to url: URL, passphrase: String? = nil) throws {
        guard access == .open else { throw ConnectionFileStore.StoreError.encrypted }

        if let vault {
            guard let passphrase else { throw VaultError.wrongPassphrase }
            _ = try VaultCrypto.dataKey(from: vault, passphrase: passphrase)
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(ConnectionFileStore.Document(connections: connections))
        try ProtectedFile.write(data, to: url)
    }
}
