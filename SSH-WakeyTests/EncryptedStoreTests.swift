import CryptoKit
import Darwin
import XCTest
@testable import SSH_Wakey

/// The whole encryption lifecycle through the store: turning it on, reopening
/// it, losing the Keychain key, recovering, and turning it off again.
@MainActor
final class EncryptedStoreTests: XCTestCase {

    private var directory: URL!
    private var account: String!
    private var store: ConnectionStore!
    private let appLockKeys = TestAppLockKeys()

    private let passphrase = "a-long-enough-passphrase"

    override func setUp() async throws {
        directory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("SSH-WakeyVault-\(UUID().uuidString)", isDirectory: true)
        account = "test-\(UUID().uuidString)"
        store = makeStore()
        store.add(SSHConnection(name: "Studio Mac", username: "admin", host: "192.168.1.24"))
    }

    override func tearDown() async throws {
        try? KeychainKeyStore.delete(account: account)
        try? FileManager.default.removeItem(at: directory)
    }

    private func makeStore() -> ConnectionStore {
        ConnectionStore(
            fileStore: ConnectionFileStore(directoryURL: directory), keychainAccount: account, isManagedBuild: false, appLockKeys: appLockKeys)
    }

    private var fileText: String {
        (try? String(contentsOf: ConnectionFileStore(directoryURL: directory).fileURL,
                     encoding: .utf8)) ?? ""
    }

    // MARK: - Turning it on

    func testItStartsUnencrypted() {
        XCTAssertFalse(store.isEncrypted)
        XCTAssertFalse(store.isLocked)
        XCTAssertTrue(fileText.contains("192.168.1.24"))
    }

    func testTurningItOnPutsNothingReadableOnDisk() throws {
        try store.enableEncryption(passphrase: passphrase)

        XCTAssertTrue(store.isEncrypted)
        XCTAssertFalse(store.isLocked)
        XCTAssertEqual(store.connections.count, 1)

        let written = fileText
        XCTAssertFalse(written.contains("192.168.1.24"), written)
        XCTAssertFalse(written.contains("Studio Mac"))
        XCTAssertFalse(written.contains("admin"))
        XCTAssertFalse(written.contains(passphrase))
        XCTAssertTrue(written.contains("vault"))
    }

    func testAShortPassphraseIsRefusedAndChangesNothing() {
        XCTAssertThrowsError(try store.enableEncryption(passphrase: "short"))
        XCTAssertFalse(store.isEncrypted)
        XCTAssertTrue(fileText.contains("192.168.1.24"), "the file must be left alone")
    }

    // MARK: - Reopening

    func testReopeningWithTheKeychainKeyIsSilent() throws {
        try store.enableEncryption(passphrase: passphrase)

        let reopened = makeStore()
        XCTAssertFalse(reopened.isLocked)
        XCTAssertTrue(reopened.isEncrypted)
        XCTAssertEqual(reopened.connections.first?.host, "192.168.1.24")
    }

    func testLosingTheKeychainKeyLocksRatherThanLoses() throws {
        try store.enableEncryption(passphrase: passphrase)
        try KeychainKeyStore.delete(account: account)

        let reopened = makeStore()
        XCTAssertTrue(reopened.isLocked)
        XCTAssertTrue(reopened.connections.isEmpty, "nothing is shown while locked")
        XCTAssertNil(reopened.storageError, "being locked is not an error")
    }

    func testATamperedVaultWarnsAboutIntegrityWhileStayingLocked() throws {
        try store.enableEncryption(passphrase: passphrase)

        let fileURL = ConnectionFileStore(directoryURL: directory).fileURL
        var document = try JSONDecoder().decode(
            ConnectionFileStore.Document.self, from: try Data(contentsOf: fileURL))
        var vault = try XCTUnwrap(document.vault)
        vault.payload[vault.payload.count - 1] ^= 0xFF
        document = ConnectionFileStore.Document(vault: vault)
        try ProtectedFile.write(try JSONEncoder().encode(document), to: fileURL)

        let reopened = makeStore()
        XCTAssertTrue(reopened.isLocked)
        XCTAssertFalse(reopened.isUnavailable)
        XCTAssertTrue(reopened.connections.isEmpty)
        let warning = try XCTUnwrap(reopened.storageError)
        XCTAssertTrue(
            warning.localizedCaseInsensitiveContains("damaged or altered"),
            warning)
    }

    func testTheRecoveryPassphraseOpensItAndRestoresSilentOpening() throws {
        try store.enableEncryption(passphrase: passphrase)
        try KeychainKeyStore.delete(account: account)

        let locked = makeStore()
        XCTAssertTrue(locked.isLocked)

        try locked.unlock(withPassphrase: passphrase)
        XCTAssertFalse(locked.isLocked)
        XCTAssertEqual(locked.connections.first?.host, "192.168.1.24")

        // A fresh Keychain key was stored, so the next launch needs no passphrase.
        XCTAssertNotNil(try KeychainKeyStore.load(account: account))
        XCTAssertFalse(makeStore().isLocked)
    }

    func testAWrongRecoveryPassphraseLeavesItLocked() throws {
        try store.enableEncryption(passphrase: passphrase)
        try KeychainKeyStore.delete(account: account)

        let locked = makeStore()
        XCTAssertThrowsError(try locked.unlock(withPassphrase: "not-the-passphrase")) {
            XCTAssertEqual($0 as? VaultError, .wrongPassphrase)
        }
        XCTAssertTrue(locked.isLocked)
    }

    // MARK: - Editing

    func testEditsAreSavedBackEncrypted() throws {
        try store.enableEncryption(passphrase: passphrase)
        store.add(SSHConnection(name: "Build box", username: "ci", host: "10.0.0.7"))

        XCTAssertFalse(fileText.contains("10.0.0.7"))
        XCTAssertEqual(makeStore().connections.count, 2)
    }

    func testNothingCanBeChangedWhileLocked() throws {
        try store.enableEncryption(passphrase: passphrase)
        try KeychainKeyStore.delete(account: account)

        let locked = makeStore()
        locked.add(SSHConnection(name: "Sneaky", username: "x", host: "10.0.0.1"))
        XCTAssertTrue(locked.connections.isEmpty)

        // The real list is still intact behind the lock.
        try locked.unlock(withPassphrase: passphrase)
        XCTAssertEqual(locked.connections.count, 1)
        XCTAssertEqual(locked.connections.first?.name, "Studio Mac")
    }

    // MARK: - Changing and turning off

    func testChangingThePassphraseRetiresTheOldOne() throws {
        try store.enableEncryption(passphrase: passphrase)
        try store.changePassphrase(from: passphrase, to: "a-different-long-passphrase")
        try KeychainKeyStore.delete(account: account)

        let locked = makeStore()
        XCTAssertThrowsError(try locked.unlock(withPassphrase: passphrase))
        XCTAssertNoThrow(try locked.unlock(withPassphrase: "a-different-long-passphrase"))
        XCTAssertEqual(locked.connections.count, 1)
    }

    /// The app holds the data key, so it could change the passphrase without
    /// asking. Asking stops a moment at an unlocked app becoming lasting access.
    func testChangingThePassphraseNeedsTheCurrentOne() throws {
        try store.enableEncryption(passphrase: passphrase)

        XCTAssertThrowsError(
            try store.changePassphrase(from: "not-the-passphrase", to: "a-new-long-passphrase")
        ) {
            XCTAssertEqual($0 as? VaultError, .wrongPassphrase)
        }

        // The old one still works, so nothing was changed on the way out.
        try KeychainKeyStore.delete(account: account)
        XCTAssertNoThrow(try makeStore().unlock(withPassphrase: passphrase))
    }

    func testAShortReplacementPassphraseIsRefused() throws {
        try store.enableEncryption(passphrase: passphrase)
        XCTAssertThrowsError(try store.changePassphrase(from: passphrase, to: "short")) {
            XCTAssertEqual($0 as? VaultError,
                           .passphraseTooShort(VaultCrypto.minimumPassphraseLength))
        }
    }

    func testTurningItOffRestoresAPlainFileAndRemovesTheKey() throws {
        try store.enableEncryption(passphrase: passphrase)
        try store.disableEncryption(passphrase: passphrase)

        XCTAssertFalse(store.isEncrypted)
        XCTAssertTrue(fileText.contains("192.168.1.24"))
        XCTAssertNil(try KeychainKeyStore.load(account: account))
        XCTAssertEqual(makeStore().connections.count, 1)
    }

    /// Turning encryption off rewrites the file in plain text and leaves it
    /// that way. The Keychain key alone would let a moment at an unlocked app
    /// do that quietly.
    func testTurningItOffNeedsThePassphrase() throws {
        try store.enableEncryption(passphrase: passphrase)

        XCTAssertThrowsError(try store.disableEncryption(passphrase: "not-the-passphrase")) {
            XCTAssertEqual($0 as? VaultError, .wrongPassphrase)
        }

        XCTAssertTrue(store.isEncrypted)
        XCTAssertFalse(fileText.contains("192.168.1.24"), "the file must still be sealed")
        XCTAssertNotNil(try KeychainKeyStore.load(account: account), "the key must still be there")
    }

    // MARK: - Export

    func testExportWritesAReadableCopyOnlyYouCanRead() throws {
        try store.enableEncryption(passphrase: passphrase)

        let destination = directory.appendingPathComponent("export.json")
        try store.export(to: destination, passphrase: passphrase)

        let exported = try String(contentsOf: destination, encoding: .utf8)
        XCTAssertTrue(exported.contains("192.168.1.24"))
        XCTAssertTrue(exported.contains("Studio Mac"))

        let permissions = try FileManager.default
            .attributesOfItem(atPath: destination.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(permissions?.int16Value, 0o600)

        // And it is the same shape as an ordinary file, so it can go straight back.
        let copy = directory.appendingPathComponent("restored", isDirectory: true)
        try FileManager.default.createDirectory(at: copy, withIntermediateDirectories: true)
        let restored = ConnectionFileStore(directoryURL: copy)
        try FileManager.default.copyItem(at: destination, to: restored.fileURL)
        XCTAssertEqual(try restored.load().first?.host, "192.168.1.24")
    }

    func testExportNeedsThePassphraseOnceEncrypted() throws {
        try store.enableEncryption(passphrase: passphrase)
        let destination = directory.appendingPathComponent("export.json")

        XCTAssertThrowsError(try store.export(to: destination)) {
            XCTAssertEqual($0 as? VaultError, .wrongPassphrase)
        }
        XCTAssertThrowsError(try store.export(to: destination, passphrase: "wrong-passphrase-here"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path),
                       "a refused export must not leave a file behind")

        XCTAssertNoThrow(try store.export(to: destination, passphrase: passphrase))
        XCTAssertTrue(FileManager.default.fileExists(atPath: destination.path))
    }

    func testExportNeedsNoPassphraseWhenNothingIsEncrypted() throws {
        let destination = directory.appendingPathComponent("plain-export.json")
        try store.export(to: destination)

        XCTAssertTrue(try String(contentsOf: destination, encoding: .utf8).contains("192.168.1.24"))
    }

    func testExportIsRefusedWhileLocked() throws {
        try store.enableEncryption(passphrase: passphrase)
        try KeychainKeyStore.delete(account: account)

        let locked = makeStore()
        XCTAssertThrowsError(try locked.export(to: directory.appendingPathComponent("x.json")))
    }

    // MARK: - A file that cannot be read

    private var connectionsFile: URL {
        ConnectionFileStore(directoryURL: directory).fileURL
    }

    private func reopenAfterPlanting(_ contents: Data) throws -> ConnectionStore {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try ProtectedFile.write(contents, to: connectionsFile)
        return makeStore()
    }

    private func assertFileUnchanged(_ original: Data, after work: () throws -> Void) throws {
        try work()
        XCTAssertEqual(try Data(contentsOf: connectionsFile), original)
    }

    func testAMissingFileIsAnOrdinaryEmptyStore() throws {
        let scratch = directory.deletingLastPathComponent()
            .appendingPathComponent("SSH-Wakey-missing-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: scratch) }
        let fresh = ConnectionStore(
            fileStore: ConnectionFileStore(directoryURL: scratch),
            keychainAccount: "missing-\(UUID().uuidString)", isManagedBuild: false)

        XCTAssertFalse(fresh.isUnavailable)
        XCTAssertFalse(fresh.isLocked)
        XCTAssertEqual(fresh.access, .open)
        XCTAssertTrue(fresh.connections.isEmpty)
        XCTAssertNil(fresh.storageError)

        fresh.add(SSHConnection(name: "Studio", username: "admin", host: "10.0.0.4"))
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: ConnectionFileStore(directoryURL: scratch).fileURL.path))
        XCTAssertEqual(fresh.connections.count, 1)
    }

    func testGarbageJSONIsUnavailableAndIsNotOverwritten() throws {
        let original = Data("this is not json".utf8)
        let reopened = try reopenAfterPlanting(original)

        XCTAssertTrue(reopened.isUnavailable)
        XCTAssertFalse(reopened.isLocked)
        XCTAssertFalse(reopened.isEncrypted)
        XCTAssertTrue(reopened.connections.isEmpty)
        XCTAssertEqual(reopened.access, .unavailable)
        let warning = try XCTUnwrap(reopened.storageError)
        XCTAssertTrue(warning.localizedCaseInsensitiveContains("damaged or altered"), warning)

        try assertFileUnchanged(original) {
            reopened.add(SSHConnection(name: "Studio", username: "admin", host: "10.0.0.4"))
            try reopened.enableEncryption(passphrase: passphrase)
        }
        XCTAssertTrue(reopened.connections.isEmpty)
        XCTAssertFalse(reopened.isEncrypted)
    }

    func testAnExistingEmptyFileIsUnavailableAndIsNotOverwritten() throws {
        let original = Data()
        let reopened = try reopenAfterPlanting(original)

        XCTAssertTrue(reopened.isUnavailable)
        XCTAssertEqual(reopened.access, .unavailable)
        try assertFileUnchanged(original) {
            reopened.add(SSHConnection(name: "Studio", username: "admin", host: "10.0.0.4"))
        }
    }

    func testANewerFormatIsUnavailableAndSaysTheAppIsTooOld() throws {
        let original = Data("""
        {"version":99,"connections":[]}
        """.utf8)
        let reopened = try reopenAfterPlanting(original)

        XCTAssertTrue(reopened.isUnavailable)
        XCTAssertFalse(reopened.isLocked)
        let warning = try XCTUnwrap(reopened.storageError)
        XCTAssertTrue(warning.localizedCaseInsensitiveContains("too old"), warning)
        XCTAssertFalse(warning.localizedCaseInsensitiveContains("damaged or altered"), warning)

        try assertFileUnchanged(original) {
            reopened.add(SSHConnection(name: "Studio", username: "admin", host: "10.0.0.4"))
        }
    }

    func testExportIsRefusedWhileUnavailable() throws {
        let reopened = try reopenAfterPlanting(Data("this is not json".utf8))
        let destination = directory.appendingPathComponent("should-not-exist.json")

        XCTAssertThrowsError(try reopened.export(to: destination))
        XCTAssertFalse(FileManager.default.fileExists(atPath: destination.path))
    }

    func testASaveFailureDoesNotMarkTheStoreUnavailable() throws {
        XCTAssertEqual(store.access, .open)
        // A directory standing where the file should be makes the atomic
        // replace fail, without relying on POSIX permissions in /tmp.
        try FileManager.default.removeItem(at: connectionsFile)
        try FileManager.default.createDirectory(
            at: connectionsFile, withIntermediateDirectories: false)

        store.add(SSHConnection(name: "Other", username: "ci", host: "10.0.0.8"))

        XCTAssertFalse(store.isUnavailable)
        XCTAssertFalse(store.isLocked)
        XCTAssertEqual(store.access, .open)
        XCTAssertNotNil(store.storageError)
        XCTAssertEqual(store.connections.count, 2)
    }

    func testInaccessibleParentCannotLaterOverwriteOriginal() throws {
        let original = try Data(contentsOf: connectionsFile)
        XCTAssertEqual(chmod(directory.path, 0), 0)
        let unavailable = makeStore()
        XCTAssertEqual(chmod(directory.path, 0o700), 0)
        XCTAssertTrue(unavailable.isUnavailable)
        unavailable.add(SSHConnection(name: "Replacement", username: "audit", host: "replacement.invalid"))
        XCTAssertEqual(try Data(contentsOf: connectionsFile), original)
    }

    func testConcurrentStoreDoesNotOverwriteChangedFileOrKeychainKey() throws {
        let stale = makeStore()
        try store.enableEncryption(passphrase: passphrase)
        let original = try Data(contentsOf: connectionsFile)
        let key = try KeychainKeyStore.load(account: account)
        XCTAssertThrowsError(try stale.enableEncryption(passphrase: "another-recovery-passphrase"))
        XCTAssertEqual(try Data(contentsOf: connectionsFile), original)
        XCTAssertEqual(try KeychainKeyStore.load(account: account), key)
        XCTAssertFalse(makeStore().isLocked)
    }

    func testPassphraseChangeRotatesKeyAgainstOldSnapshot() throws {
        try store.enableEncryption(passphrase: passphrase)
        guard case .encrypted(let oldVault) = try ConnectionFileStore(directoryURL: directory).read() else {
            return XCTFail("expected vault")
        }
        let oldKey = try VaultCrypto.dataKey(from: oldVault, passphrase: passphrase)
        try store.changePassphrase(from: passphrase, to: "a-new-recovery-passphrase")
        store.add(SSHConnection(name: "Future", username: "audit", host: "future.invalid"))
        guard case .encrypted(let updated) = try ConnectionFileStore(directoryURL: directory).read() else {
            return XCTFail("expected vault")
        }
        XCTAssertThrowsError(try VaultCrypto.connections(in: updated, using: oldKey))
        let newKey = try VaultCrypto.dataKey(from: updated, passphrase: "a-new-recovery-passphrase")
        XCTAssertEqual(try VaultCrypto.connections(in: updated, using: newKey).count, 2)
        XCTAssertFalse(makeStore().isLocked, "both wrappers must rotate with the new payload")
    }

    func testEncryptedMACMetadataHasNoPlaintextSidecar() throws {
        let id = try XCTUnwrap(store.connections.first?.id)
        let cache = LinkAddressCache(directoryURL: directory)
        cache.store("aa:bb:cc:dd:ee:ff", for: "legacy.invalid")
        XCTAssertTrue(FileManager.default.fileExists(atPath: cache.fileURL.path))
        try store.enableEncryption(passphrase: passphrase)
        store.rememberLinkAddress("aa:bb:cc:dd:ee:ff", for: id)
        XCTAssertFalse(FileManager.default.fileExists(atPath: cache.fileURL.path))
        XCTAssertEqual(makeStore().connections.first?.hardwareAddress, "aa:bb:cc:dd:ee:ff")
        XCTAssertFalse(fileText.contains("192.168.1.24"))
    }

    func testOpeningExistingVaultRemovesLegacySidecar() throws {
        try store.enableEncryption(passphrase: passphrase)
        let cache = LinkAddressCache(directoryURL: directory)
        cache.store("aa:bb:cc:dd:ee:ff", for: "legacy.invalid")
        XCTAssertFalse(makeStore().isLocked)
        XCTAssertFalse(FileManager.default.fileExists(atPath: cache.fileURL.path))
    }

    func testMalformedSerializedRecoverySlotDoesNotBlockKeychainOpening() throws {
        try store.enableEncryption(passphrase: passphrase)
        var document = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: connectionsFile)) as? [String: Any])
        var vault = try XCTUnwrap(document["vault"] as? [String: Any])
        vault["passphraseSlot"] = ["derivation": "PBKDF2-HMAC-SHA256", "salt": "not base64!", "rounds": "broken"]
        document["vault"] = vault
        try ProtectedFile.write(JSONSerialization.data(withJSONObject: document), to: connectionsFile)
        let reopened = makeStore()
        XCTAssertEqual(reopened.access, .open)
        XCTAssertEqual(reopened.connections.count, 1)
        XCTAssertTrue(reopened.storageError?.contains("recovery slot is damaged") == true)
    }


    func testLegacyAutomaticTrustFlagIsUpgradedOnLoad() throws {
        try ConnectionFileStore(directoryURL: directory).save([
            SSHConnection(name: "Legacy", username: "audit", host: "legacy.invalid", strictHostKeyChecking: false)
        ])
        let reopened = makeStore()
        XCTAssertTrue(try XCTUnwrap(reopened.connections.first).strictHostKeyChecking)
    }

    // MARK: - App Lock (injected keys; no biometric prompts)

    private func storedVault() throws -> ConnectionVault {
        guard case .encrypted(let result) = try ConnectionFileStore(directoryURL: directory).read() else {
            throw AppLockError.invalidPreparation
        }
        return result
    }

    private func enableAppLock() async throws {
        try store.enableEncryption(passphrase: passphrase)
        let prepared = try store.prepareEnableAppLock(passphrase: passphrase)
        XCTAssertTrue(store.isAuthenticating)
        try await store.enableAppLock(prepared)
    }

    func testAppLockRotatesKeyAndRequiresFreshAuthenticationAfterEveryLock() async throws {
        try store.enableEncryption(passphrase: passphrase)
        let oldVault = try storedVault()
        let oldKey = try VaultCrypto.dataKey(from: oldVault, passphrase: passphrase)
        try await store.enableAppLock(store.prepareEnableAppLock(passphrase: passphrase))
        XCTAssertTrue(store.isAppLockEnabled)
        XCTAssertNil(try KeychainKeyStore.load(account: account))
        XCTAssertThrowsError(try VaultCrypto.connections(in: storedVault(), using: oldKey))
        let reopened = makeStore()
        XCTAssertTrue(reopened.isLocked)
        XCTAssertTrue(reopened.connections.isEmpty)
        let before = await appLockKeys.callCount
        try await reopened.unlockWithSystemAuthentication()
        XCTAssertEqual(reopened.connections.count, 1)
        reopened.lock()
        XCTAssertTrue(reopened.connections.isEmpty)
        try await reopened.unlockWithSystemAuthentication()
        let after = await appLockKeys.callCount
        let distinct = await appLockKeys.distinctContextCount
        XCTAssertEqual(after, before + 2)
        XCTAssertEqual(after, distinct, "a previous LAContext must never be reused")
    }

    func testProtectedRecoveryPreservesModeAndDoesNotCreateLoginKey() async throws {
        try await enableAppLock()
        let original = try Data(contentsOf: connectionsFile)
        store.lock()
        try store.unlock(withPassphrase: passphrase)
        XCTAssertTrue(store.isAppLockEnabled)
        XCTAssertFalse(store.isLocked)
        XCTAssertEqual(try Data(contentsOf: connectionsFile), original)
        XCTAssertNil(try KeychainKeyStore.load(account: account))
        XCTAssertThrowsError(try store.disableEncryption(passphrase: passphrase))
    }

    func testLockInvalidatesPreparedEnableBeforeAuthenticationStarts() async throws {
        try store.enableEncryption(passphrase: passphrase)
        let original = try Data(contentsOf: connectionsFile)
        let prepared = try store.prepareEnableAppLock(passphrase: passphrase)
        store.lock()
        do { try await store.enableAppLock(prepared); XCTFail("expired preparation accepted") }
        catch { }
        XCTAssertFalse(store.isAuthenticating)
        XCTAssertFalse(store.isAppLockEnabled)
        XCTAssertEqual(try Data(contentsOf: connectionsFile), original)
        XCTAssertNotNil(try KeychainKeyStore.load(account: account))
    }

    func testLateAuthenticationSuccessCannotUnlockAfterLock() async throws {
        try await enableAppLock()
        store.lock()
        await appLockKeys.pauseNextCall()
        let task = Task { try await self.store.unlockWithSystemAuthentication() }
        await appLockKeys.waitUntilPaused()
        XCTAssertTrue(store.isAuthenticating)
        store.lock()
        await appLockKeys.resume()
        do { try await task.value; XCTFail("late success unlocked store") }
        catch { }
        XCTAssertTrue(store.isLocked)
        XCTAssertFalse(store.isAuthenticating)
        XCTAssertTrue(store.connections.isEmpty)
    }

    func testCancelledEnableCannotCommitAfterLateAuthentication() async throws {
        try store.enableEncryption(passphrase: passphrase)
        let original = try Data(contentsOf: connectionsFile)
        let prepared = try store.prepareEnableAppLock(passphrase: passphrase)
        await appLockKeys.pauseNextCall()
        let task = Task { try await self.store.enableAppLock(prepared) }
        await appLockKeys.waitUntilPaused()
        store.lock()
        await appLockKeys.resume()
        do { try await task.value; XCTFail("cancelled setup committed") }
        catch { }
        XCTAssertFalse(store.isAppLockEnabled)
        XCTAssertEqual(try Data(contentsOf: connectionsFile), original)
        XCTAssertNotNil(try KeychainKeyStore.load(account: account))
    }

    func testPendingPreparationBlocksMutationsAndExport() async throws {
        try store.enableEncryption(passphrase: passphrase)
        let original = try Data(contentsOf: connectionsFile)
        let prepared = try store.prepareEnableAppLock(passphrase: passphrase)
        let row = try XCTUnwrap(store.connections.first)
        store.add(SSHConnection(name: "Unexpected", username: "test", host: "example.invalid"))
        store.remove(id: row.id)
        var changed = row
        changed.name = "Changed"
        store.update(changed)
        store.rememberLinkAddress("aa:bb:cc:dd:ee:ff", for: row.id)
        try store.disableEncryption(passphrase: passphrase)
        XCTAssertThrowsError(try store.export(to: directory.appendingPathComponent("export.json"), passphrase: passphrase))
        XCTAssertEqual(store.connections, [row])
        XCTAssertEqual(try Data(contentsOf: connectionsFile), original)
        try await store.enableAppLock(prepared)
        do { try await store.enableAppLock(prepared); XCTFail("preparation reused") }
        catch { }
    }

    func testConcurrentFileChangeWhileAuthenticatingPreservesOldKey() async throws {
        try store.enableEncryption(passphrase: passphrase)
        let other = makeStore()
        let prepared = try store.prepareEnableAppLock(passphrase: passphrase)
        await appLockKeys.pauseNextCall()
        let task = Task { try await self.store.enableAppLock(prepared) }
        await appLockKeys.waitUntilPaused()
        other.add(SSHConnection(name: "New", username: "test", host: "new.invalid"))
        let changed = try Data(contentsOf: connectionsFile)
        await appLockKeys.resume()
        do { try await task.value; XCTFail("stale setup committed") }
        catch { }
        XCTAssertEqual(try Data(contentsOf: connectionsFile), changed)
        XCTAssertNotNil(try KeychainKeyStore.load(account: account))
        XCTAssertFalse(store.isAppLockEnabled)
    }

    func testProtectedPassphraseChangeRotatesBothWrappersWithoutDowngrade() async throws {
        try await enableAppLock()
        let oldKey = try VaultCrypto.dataKey(from: storedVault(), passphrase: passphrase)
        let replacement = "a-new-protected-recovery-passphrase"
        try await store.changePassphrase(store.prepareChangePassphrase(from: passphrase, to: replacement))
        let changed = try storedVault()
        XCTAssertTrue(changed.keyProtection.isAppLockEnabled)
        XCTAssertThrowsError(try VaultCrypto.connections(in: changed, using: oldKey))
        XCTAssertThrowsError(try VaultCrypto.dataKey(from: changed, passphrase: passphrase))
        XCTAssertNoThrow(try VaultCrypto.verifyPassphrase(in: changed, passphrase: replacement))
        store.lock()
        try await store.unlockWithSystemAuthentication()
        XCTAssertFalse(store.isLocked)
        XCTAssertNil(try KeychainKeyStore.load(account: account))
    }

    func testDisableAppLockNeedsRecoveryAndRotatesToLoginKeychain() async throws {
        try await enableAppLock()
        let oldKey = try VaultCrypto.dataKey(from: storedVault(), passphrase: passphrase)
        XCTAssertThrowsError(try store.prepareDisableAppLock(passphrase: "wrong-password"))
        let before = await appLockKeys.callCount
        try await store.disableAppLock(store.prepareDisableAppLock(passphrase: passphrase))
        let after = await appLockKeys.callCount
        XCTAssertEqual(before, after, "explicit recovery-authorized downgrade needs no enclave prompt")
        XCTAssertFalse(store.isAppLockEnabled)
        XCTAssertFalse(makeStore().isLocked)
        XCTAssertThrowsError(try VaultCrypto.connections(in: storedVault(), using: oldKey))
        try store.disableEncryption(passphrase: passphrase)
        XCTAssertFalse(store.isEncrypted)
    }

    func testForgedRecoverySlotCannotAuthorizeSecurityActionsOrExport() throws {
        try store.enableEncryption(passphrase: passphrase)
        let file = ConnectionFileStore(directoryURL: directory)
        var original = try storedVault()
        let chosen = "attacker-chosen-recovery-passphrase"
        let forged = try VaultCrypto.seal([], dataKey: VaultCrypto.makeDataKey(),
                                          keychainKey: VaultCrypto.makeDataKey(), passphrase: chosen,
                                          rounds: 1000, keyProtection: original.keyProtection)
        original.passphraseSlot = forged.passphraseSlot
        try file.save(original)
        let victim = makeStore()
        XCTAssertFalse(victim.isLocked, "the genuine Keychain wrapper still opens the real payload")
        XCTAssertEqual(victim.connections.count, 1)
        XCTAssertThrowsError(try victim.export(to: directory.appendingPathComponent("forged-export.json"), passphrase: chosen))
        XCTAssertThrowsError(try victim.disableEncryption(passphrase: chosen))
        XCTAssertThrowsError(try victim.changePassphrase(from: chosen, to: passphrase))
        XCTAssertThrowsError(try victim.prepareEnableAppLock(passphrase: chosen))
        XCTAssertThrowsError(try victim.prepareChangePassphrase(from: chosen, to: passphrase))
        XCTAssertTrue(victim.isEncrypted)
    }

    func testDamagedHardwareSlotRecoveryKeepsAppLockAndAllowsExplicitRepair() async throws {
        try await enableAppLock()
        var document = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: connectionsFile)) as? [String: Any])
        var vault = try XCTUnwrap(document["vault"] as? [String: Any])
        vault["keyProtection"] = ["kind": ConnectionVault.KeyProtection.enclaveKind, "keyRepresentation": false]
        document["vault"] = vault
        try ProtectedFile.write(JSONSerialization.data(withJSONObject: document), to: connectionsFile)
        let reopened = makeStore()
        XCTAssertTrue(reopened.isLocked)
        XCTAssertTrue(reopened.isAppLockEnabled)
        try reopened.unlock(withPassphrase: passphrase)
        XCTAssertTrue(reopened.isAppLockEnabled)
        XCTAssertEqual(reopened.connections.count, 1)
        XCTAssertNil(try KeychainKeyStore.load(account: account))
        try await reopened.disableAppLock(reopened.prepareDisableAppLock(passphrase: passphrase))
        XCTAssertFalse(reopened.isAppLockEnabled)
        XCTAssertFalse(makeStore().isLocked)
    }

}

/// Returns only synthetic keys. A paused request deliberately returns success
/// after cancellation so the store must reject it independently of the backend.
private actor TestAppLockKeys: AppLockKeyProviding {
    nonisolated private let key = SymmetricKey(size: .bits256)
    private(set) var callCount = 0
    private var contexts: [AppLockAuthentication] = []
    var distinctContextCount: Int { Set(contexts.map(ObjectIdentifier.init)).count }
    private var pause = false
    private var pending: CheckedContinuation<Void, Never>?
    private var started: CheckedContinuation<Void, Never>?

    nonisolated func makeProtection() throws -> ConnectionVault.KeyProtection {
        .init(kind: ConnectionVault.KeyProtection.enclaveKind,
              keyRepresentation: Data([1]), peerPublicKey: Data(repeating: 2, count: 65),
              salt: Data(repeating: 3, count: 32))
    }

    func wrappingKey(for protection: ConnectionVault.KeyProtection,
                     authentication: AppLockAuthentication) async throws -> SymmetricKey {
        callCount += 1
        contexts.append(authentication)
        if pause {
            pause = false
            await withCheckedContinuation { pending = $0; started?.resume(); started = nil }
        }
        return key
    }

    func pauseNextCall() { pause = true }
    func waitUntilPaused() async {
        guard pending == nil else { return }
        await withCheckedContinuation { started = $0 }
    }
    func resume() { pending?.resume(); pending = nil }
}
