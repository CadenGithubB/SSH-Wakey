import CryptoKit
import XCTest
@testable import SSH_Wakey

final class ConnectionVaultTests: XCTestCase {

    /// Real derivation is deliberately slow, so most tests use a small round
    /// count. One test below checks the shipping value.
    private let testRounds = 1_000
    private let passphrase = "correct-horse-battery-staple"

    private let connections = [
        SSHConnection(name: "Studio Mac", username: "admin", host: "192.168.1.24",
                      port: 22, createdAt: Date.stamp()),
        SSHConnection(name: "Build box", username: "ci", host: "build.example.internal", port: 2222),
    ]

    private func makeVault(
        _ list: [SSHConnection]? = nil,
        dataKey: SymmetricKey = VaultCrypto.makeDataKey(),
        keychainKey: SymmetricKey = KeychainKeyStore.makeKey(),
        passphrase: String? = nil
    ) throws -> ConnectionVault {
        try VaultCrypto.seal(
            list ?? connections, dataKey: dataKey, keychainKey: keychainKey,
            passphrase: passphrase ?? self.passphrase, rounds: testRounds)
    }

    // MARK: - Both ways in

    func testTheKeychainKeyOpensIt() throws {
        let keychainKey = KeychainKeyStore.makeKey()
        let vault = try makeVault(keychainKey: keychainKey)

        let dataKey = try VaultCrypto.dataKey(from: vault, keychainKey: keychainKey)
        XCTAssertEqual(try VaultCrypto.connections(in: vault, using: dataKey), connections)
    }

    func testTheRecoveryPassphraseOpensIt() throws {
        let vault = try makeVault()

        let dataKey = try VaultCrypto.dataKey(from: vault, passphrase: passphrase)
        XCTAssertEqual(try VaultCrypto.connections(in: vault, using: dataKey), connections)
    }

    /// The point of the whole design: either slot alone is enough.
    func testLosingTheKeychainKeyDoesNotLoseTheData() throws {
        let vault = try makeVault()

        XCTAssertThrowsError(try VaultCrypto.dataKey(from: vault, keychainKey: KeychainKeyStore.makeKey())) {
            XCTAssertEqual($0 as? VaultError, .keychainKeyDoesNotFit)
        }

        let recovered = try VaultCrypto.dataKey(from: vault, passphrase: passphrase)
        XCTAssertEqual(try VaultCrypto.connections(in: vault, using: recovered), connections)
    }

    func testAWrongPassphraseIsRefusedCleanly() throws {
        let vault = try makeVault()
        XCTAssertThrowsError(try VaultCrypto.dataKey(from: vault, passphrase: "not-the-passphrase")) {
            XCTAssertEqual($0 as? VaultError, .wrongPassphrase)
        }
    }

    // MARK: - What ends up on disk

    func testTheFileRevealsNothingAboutTheConnections() throws {
        let vault = try makeVault()
        let written = String(decoding: try JSONEncoder().encode(vault), as: UTF8.self)

        for secret in ["Studio Mac", "admin", "192.168.1.24", "build.example.internal", passphrase] {
            XCTAssertFalse(written.contains(secret), secret)
        }
    }

    func testTheSameConnectionsSealTwiceToDifferentBytes() throws {
        let first = try makeVault()
        let second = try makeVault()
        XCTAssertNotEqual(first.payload, second.payload)
        XCTAssertNotEqual(first.passphraseSlot.salt, second.passphraseSlot.salt)
    }

    func testTheVaultSurvivesBeingWrittenAndReadBack() throws {
        let keychainKey = KeychainKeyStore.makeKey()
        let vault = try makeVault(keychainKey: keychainKey)

        let reloaded = try JSONDecoder().decode(
            ConnectionVault.self, from: try JSONEncoder().encode(vault))

        XCTAssertEqual(reloaded, vault)
        let dataKey = try VaultCrypto.dataKey(from: reloaded, keychainKey: keychainKey)
        XCTAssertEqual(try VaultCrypto.connections(in: reloaded, using: dataKey), connections)
    }

    func testTamperingWithThePayloadIsDetected() throws {
        let keychainKey = KeychainKeyStore.makeKey()
        var vault = try makeVault(keychainKey: keychainKey)
        vault.payload[vault.payload.count - 1] ^= 0xFF

        let dataKey = try VaultCrypto.dataKey(from: vault, keychainKey: keychainKey)
        XCTAssertThrowsError(try VaultCrypto.connections(in: vault, using: dataKey)) {
            guard case .corrupted = $0 as? VaultError else {
                return XCTFail("expected .corrupted, got \($0)")
            }
        }
    }

    func testAFileFromANewerFormatIsRefused() throws {
        var vault = try makeVault()
        vault.format = 99
        XCTAssertThrowsError(try VaultCrypto.dataKey(from: vault, passphrase: passphrase)) {
            XCTAssertEqual($0 as? VaultError, .unsupportedFormat(99))
        }
    }

    // MARK: - Changing the keys

    func testThePassphraseCanBeChangedWithoutReEncryptingTheFile() throws {
        let keychainKey = KeychainKeyStore.makeKey()
        let vault = try makeVault(keychainKey: keychainKey)
        let dataKey = try VaultCrypto.dataKey(from: vault, keychainKey: keychainKey)

        let updated = try VaultCrypto.replacingPassphrase(
            in: vault, dataKey: dataKey, with: "a-brand-new-passphrase", rounds: testRounds)

        XCTAssertEqual(updated.payload, vault.payload, "the contents are not re-encrypted")
        XCTAssertEqual(try VaultCrypto.connections(
            in: updated,
            using: try VaultCrypto.dataKey(from: updated, passphrase: "a-brand-new-passphrase")),
            connections)
        XCTAssertThrowsError(try VaultCrypto.dataKey(from: updated, passphrase: passphrase),
                             "the old passphrase must stop working")
        XCTAssertNoThrow(try VaultCrypto.dataKey(from: updated, keychainKey: keychainKey),
                         "the Keychain slot is untouched")
    }

    func testANewKeychainKeyCanBeAdoptedAfterRecovery() throws {
        let vault = try makeVault()
        let dataKey = try VaultCrypto.dataKey(from: vault, passphrase: passphrase)
        let replacement = KeychainKeyStore.makeKey()

        let updated = try VaultCrypto.replacingKeychainKey(
            in: vault, dataKey: dataKey, with: replacement)

        XCTAssertEqual(try VaultCrypto.connections(
            in: updated, using: try VaultCrypto.dataKey(from: updated, keychainKey: replacement)),
            connections)
        XCTAssertNoThrow(try VaultCrypto.dataKey(from: updated, passphrase: passphrase),
                         "the recovery slot still works")
    }

    // MARK: - Passphrase rules

    func testAShortPassphraseIsRefused() {
        XCTAssertThrowsError(try makeVault(passphrase: "short")) {
            XCTAssertEqual($0 as? VaultError,
                           .passphraseTooShort(VaultCrypto.minimumPassphraseLength))
        }
    }

    func testDerivationIsDeterministicAndSaltDependent() {
        let salt = VaultCrypto.randomBytes(16)
        let first = VaultCrypto.derive(passphrase, salt: salt, rounds: testRounds)
        let second = VaultCrypto.derive(passphrase, salt: salt, rounds: testRounds)
        let other = VaultCrypto.derive(passphrase, salt: VaultCrypto.randomBytes(16), rounds: testRounds)

        XCTAssertEqual(first, second)
        XCTAssertNotEqual(first, other)
    }

    /// Slow on purpose, but it has to stay usable.
    func testTheShippingRoundCountIsSlowButNotUnbearable() {
        let started = Date()
        _ = VaultCrypto.derive(passphrase, salt: VaultCrypto.randomBytes(16),
                               rounds: ConnectionVault.defaultRounds)
        let elapsed = Date().timeIntervalSince(started)

        XCTAssertGreaterThan(elapsed, 0.02, "too fast to be doing real work")
        XCTAssertLessThan(elapsed, 5, "a person is waiting for this")
    }

    // MARK: - The suggested passphrase

    func testAGeneratedPassphraseIsLongEnoughToAccept() {
        let suggestion = VaultCrypto.suggestedPassphrase()
        XCTAssertGreaterThanOrEqual(suggestion.count, VaultCrypto.minimumPassphraseLength)
        XCTAssertNoThrow(try makeVault(passphrase: suggestion))
    }

    func testAGeneratedPassphraseHasNoAmbiguousCharacters() {
        let allowed = Set("ABCDEFGHJKLMNPQRSTUVWXYZ23456789-")
        for _ in 0..<50 {
            let suggestion = VaultCrypto.suggestedPassphrase()
            XCTAssertTrue(suggestion.allSatisfy(allowed.contains), suggestion)
            // I, O, 0 and 1 are the ones people mistype when reading it back.
            XCTAssertFalse(suggestion.contains(where: "IO01".contains), suggestion)
        }
    }

    func testAGeneratedPassphraseIsGroupedForReading() {
        let suggestion = VaultCrypto.suggestedPassphrase()
        let groups = suggestion.split(separator: "-")
        XCTAssertEqual(groups.count, 5)
        XCTAssertTrue(groups.allSatisfy { $0.count == 4 }, suggestion)
    }

    func testEveryGeneratedPassphraseIsDifferent() {
        let suggestions = Set((0..<200).map { _ in VaultCrypto.suggestedPassphrase() })
        XCTAssertEqual(suggestions.count, 200)
    }

    func testEveryVaultErrorExplainsItself() {
        let errors: [VaultError] = [
            .unsupportedFormat(2), .wrongPassphrase, .keychainKeyDoesNotFit,
            .corrupted("why"), .passphraseTooShort(12),
        ]
        for error in errors {
            XCTAssertFalse(error.errorDescription?.isEmpty ?? true, "\(error)")
        }
    }

    func testIntegrityFailuresSayTheFileMayHaveBeenAltered() {
        let corrupted = VaultError.corrupted("the contents did not decrypt")
        XCTAssertTrue(corrupted.suggestsIntegrityProblem)
        XCTAssertTrue(
            corrupted.errorDescription?.localizedCaseInsensitiveContains("damaged or altered") == true,
            corrupted.errorDescription ?? "")

        XCTAssertTrue(VaultError.keychainKeyDoesNotFit.suggestsIntegrityProblem)
        XCTAssertFalse(VaultError.wrongPassphrase.suggestsIntegrityProblem)
    }
}
