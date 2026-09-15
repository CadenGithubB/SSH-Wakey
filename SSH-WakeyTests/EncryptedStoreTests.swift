import XCTest
@testable import SSH_Wakey

/// The whole encryption lifecycle through the store: turning it on, reopening
/// it, losing the Keychain key, recovering, and turning it off again.
@MainActor
final class EncryptedStoreTests: XCTestCase {

    private var directory: URL!
    private var account: String!
    private var store: ConnectionStore!

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
            fileStore: ConnectionFileStore(directoryURL: directory), keychainAccount: account)
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
}
