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

    func testDerivationIsDeterministicAndSaltDependent() throws {
        let salt = VaultCrypto.randomBytes(ConnectionVault.saltSize)
        let first = try VaultCrypto.derive(passphrase, salt: salt, rounds: testRounds)
        let second = try VaultCrypto.derive(passphrase, salt: salt, rounds: testRounds)
        let other = try VaultCrypto.derive(
            passphrase, salt: VaultCrypto.randomBytes(ConnectionVault.saltSize), rounds: testRounds)

        XCTAssertEqual(first, second)
        XCTAssertNotEqual(first, other)
    }

    /// Slow on purpose, but it has to stay usable.
    func testTheShippingRoundCountIsSlowButNotUnbearable() throws {
        let started = Date()
        _ = try VaultCrypto.derive(passphrase, salt: VaultCrypto.randomBytes(ConnectionVault.saltSize),
                                   rounds: ConnectionVault.defaultRounds)
        let elapsed = Date().timeIntervalSince(started)

        XCTAssertGreaterThan(elapsed, 0.02, "too fast to be doing real work")
        XCTAssertLessThan(elapsed, 5, "a person is waiting for this")
    }

    // MARK: - Hostile recovery metadata

    private func assertCorrupted(_ work: () throws -> Void, _ message: String = "") {
        XCTAssertThrowsError(try work(), message) { error in
            guard case .corrupted = error as? VaultError else {
                XCTFail("expected .corrupted, got \(error)")
                return
            }
        }
    }

    func testNegativeRoundsAreRefusedWithoutCrashing() throws {
        var vault = try makeVault()
        vault.passphraseSlot.rounds = -1
        assertCorrupted {
            _ = try VaultCrypto.dataKey(from: vault, passphrase: passphrase)
        }
    }

    func testOversizedRoundsAreRefusedWithoutCrashing() throws {
        var vault = try makeVault()
        vault.passphraseSlot.rounds = Int.max
        assertCorrupted {
            _ = try VaultCrypto.dataKey(from: vault, passphrase: passphrase)
        }
    }

    func testRoundsAboveTheMaximumAreRefused() throws {
        var vault = try makeVault()
        vault.passphraseSlot.rounds = ConnectionVault.maximumRounds + 1
        assertCorrupted {
            _ = try VaultCrypto.dataKey(from: vault, passphrase: passphrase)
        }
    }

    func testADamagedPassphraseSlotDoesNotBlockTheKeychainSlot() throws {
        let keychainKey = KeychainKeyStore.makeKey()
        var vault = try makeVault(keychainKey: keychainKey)
        vault.passphraseSlot.rounds = -1

        let dataKey = try VaultCrypto.dataKey(from: vault, keychainKey: keychainKey)
        XCTAssertEqual(try VaultCrypto.connections(in: vault, using: dataKey), connections)

        assertCorrupted {
            _ = try VaultCrypto.dataKey(from: vault, passphrase: passphrase)
        }
    }

    func testAnEmptySaltIsRefused() throws {
        var vault = try makeVault()
        vault.passphraseSlot.salt = Data()
        assertCorrupted {
            _ = try VaultCrypto.dataKey(from: vault, passphrase: passphrase)
        }
        XCTAssertThrowsError(try VaultCrypto.derive(passphrase, salt: Data(), rounds: testRounds)) {
            guard case .corrupted = $0 as? VaultError else {
                return XCTFail("expected .corrupted, got \($0)")
            }
        }
    }

    func testAnEmptyPassphraseDoesNotCrashDerivation() throws {
        XCTAssertThrowsError(try VaultCrypto.derive(
            "", salt: VaultCrypto.randomBytes(ConnectionVault.saltSize), rounds: testRounds)) {
            guard case .corrupted = $0 as? VaultError else {
                return XCTFail("expected .corrupted, got \($0)")
            }
        }
        let vault = try makeVault()
        XCTAssertThrowsError(try VaultCrypto.dataKey(from: vault, passphrase: "")) {
            XCTAssertEqual($0 as? VaultError, .wrongPassphrase)
        }
    }

    func testZeroRoundsAreRefusedWithoutCrashing() {
        XCTAssertThrowsError(try VaultCrypto.derive(
            passphrase, salt: VaultCrypto.randomBytes(ConnectionVault.saltSize), rounds: 0)) {
            guard case .corrupted = $0 as? VaultError else {
                return XCTFail("expected .corrupted, got \($0)")
            }
        }
    }

    // MARK: - The suggested passphrase

    func testAGeneratedPassphraseIsLongEnoughToAccept() throws {
        let suggestion = try VaultCrypto.suggestedPassphrase()
        XCTAssertGreaterThanOrEqual(suggestion.count, VaultCrypto.minimumPassphraseLength)
        XCTAssertNoThrow(try makeVault(passphrase: suggestion))
    }

    func testAGeneratedPassphraseHasNoAmbiguousCharacters() throws {
        let allowed = Set("ABCDEFGHJKLMNPQRSTUVWXYZ23456789-")
        for _ in 0..<50 {
            let suggestion = try VaultCrypto.suggestedPassphrase()
            XCTAssertTrue(suggestion.allSatisfy(allowed.contains), suggestion)
            // I, O, 0 and 1 are the ones people mistype when reading it back.
            XCTAssertFalse(suggestion.contains(where: "IO01".contains), suggestion)
        }
    }

    func testAGeneratedPassphraseIsGroupedForReading() throws {
        let suggestion = try VaultCrypto.suggestedPassphrase()
        let groups = suggestion.split(separator: "-")
        XCTAssertEqual(groups.count, 5)
        XCTAssertTrue(groups.allSatisfy { $0.count == 4 }, suggestion)
    }

    func testEveryGeneratedPassphraseIsDifferent() throws {
        let suggestions = Set(try (0..<200).map { _ in try VaultCrypto.suggestedPassphrase() })
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

    func testSealingAndOpeningRequireTheSameSaltSize() throws {
        for count in [0, 1, 15, 17, 1024] {
            XCTAssertThrowsError(try VaultCrypto.seal(
                connections, dataKey: VaultCrypto.makeDataKey(), keychainKey: KeychainKeyStore.makeKey(),
                passphrase: passphrase, salt: Data(repeating: 1, count: count), rounds: testRounds))
        }
    }

    func testMalformedRecoverySerializationPreservesIndependentKeychainSlot() throws {
        let keychainKey = KeychainKeyStore.makeKey()
        let vault = try makeVault(keychainKey: keychainKey)
        let encoded = try JSONEncoder().encode(vault)
        for damaged: Any in [NSNull(), "broken", ["salt": "invalid base64!", "rounds": "NaN"]] {
            var object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
            object["passphraseSlot"] = damaged
            let decoded = try JSONDecoder().decode(ConnectionVault.self, from: JSONSerialization.data(withJSONObject: object))
            XCTAssertFalse(decoded.hasUsableRecoverySlot)
            let key = try VaultCrypto.dataKey(from: decoded, keychainKey: keychainKey)
            XCTAssertEqual(try VaultCrypto.connections(in: decoded, using: key), connections)
            XCTAssertThrowsError(try VaultCrypto.dataKey(from: decoded, passphrase: passphrase))
        }
    }

    func testMalformedKeychainSerializationPreservesRecoverySlot() throws {
        let vault = try makeVault()
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(vault)) as? [String: Any])
        object["keychainWrappedKey"] = "invalid base64!"
        let decoded = try JSONDecoder().decode(ConnectionVault.self, from: JSONSerialization.data(withJSONObject: object))
        let key = try VaultCrypto.dataKey(from: decoded, passphrase: passphrase)
        XCTAssertEqual(try VaultCrypto.connections(in: decoded, using: key), connections)
    }

    func testUnknownCipherAndDerivationAreRejected() throws {
        var vault = try makeVault()
        vault.cipher = "unknown"
        XCTAssertThrowsError(try VaultCrypto.dataKey(from: vault, passphrase: passphrase))
        vault.cipher = ConnectionVault.cipherName
        vault.passphraseSlot.derivation = "unknown"
        XCTAssertThrowsError(try VaultCrypto.dataKey(from: vault, passphrase: passphrase))
    }


    func testOversizedPassphraseIsRejectedBeforeDerivation() throws {
        let excessive = String(repeating: "x", count: VaultCrypto.maximumPassphraseBytes + 1)
        XCTAssertThrowsError(try VaultCrypto.derive(
            excessive, salt: Data(repeating: 1, count: ConnectionVault.saltSize), rounds: testRounds))
        // The bound applies to bytes, including multibyte Unicode input.
        XCTAssertThrowsError(try VaultCrypto.derive(
            String(repeating: "🔒", count: 1025),
            salt: Data(repeating: 1, count: ConnectionVault.saltSize), rounds: testRounds))
    }

    func testFormatOneVaultWithoutProtectionMetadataStillOpens() throws {
        let dataKey = VaultCrypto.makeDataKey()
        let wrapping = VaultCrypto.makeDataKey()
        let salt = VaultCrypto.randomBytes(ConnectionVault.saltSize)
        let recovery = try VaultCrypto.derive(passphrase, salt: salt, rounds: testRounds)
        let old = ConnectionVault(format: 1, cipher: ConnectionVault.cipherName,
                                  payload: try XCTUnwrap(AES.GCM.seal(VaultCrypto.encoder().encode(connections), using: dataKey).combined),
                                  keychainWrappedKey: try dataKey.withUnsafeBytes { try XCTUnwrap(AES.GCM.seal($0, using: wrapping).combined) },
                                  passphraseSlot: .init(derivation: ConnectionVault.derivationName, salt: salt, rounds: testRounds,
                                                       wrappedKey: try dataKey.withUnsafeBytes { try XCTUnwrap(AES.GCM.seal($0, using: recovery).combined) }))
        let encoded = try JSONEncoder().encode(old)
        XCTAssertFalse(String(decoding: encoded, as: UTF8.self).contains("keyProtection"))
        let decoded = try JSONDecoder().decode(ConnectionVault.self, from: encoded)
        XCTAssertEqual(try VaultCrypto.connections(in: decoded, using: VaultCrypto.dataKey(from: decoded, keychainKey: wrapping)), connections)
        XCTAssertNoThrow(try VaultCrypto.verifyPassphrase(in: decoded, passphrase: passphrase))
    }

    func testAppLockModeBindsEveryCiphertextButHardwareDamageAllowsRecovery() throws {
        let dataKey = VaultCrypto.makeDataKey()
        let wrapping = VaultCrypto.makeDataKey()
        let protection = ConnectionVault.KeyProtection(kind: ConnectionVault.KeyProtection.enclaveKind,
                                                       keyRepresentation: Data([1, 2]), peerPublicKey: Data(repeating: 4, count: 65),
                                                       salt: Data(repeating: 3, count: 32))
        let original = try VaultCrypto.seal(connections, dataKey: dataKey, keychainKey: wrapping,
                                            passphrase: passphrase, rounds: testRounds, keyProtection: protection)
        var downgraded = original
        downgraded.keyProtection = .legacy
        XCTAssertThrowsError(try VaultCrypto.dataKey(from: downgraded, keychainKey: wrapping))
        XCTAssertThrowsError(try VaultCrypto.dataKey(from: downgraded, passphrase: passphrase))
        XCTAssertThrowsError(try VaultCrypto.connections(in: downgraded, using: dataKey))
        var changed = original
        changed.keyProtection.keyRepresentation = Data([2, 1])
        XCTAssertThrowsError(try VaultCrypto.dataKey(from: changed, keychainKey: wrapping))
        XCTAssertNoThrow(try VaultCrypto.verifyPassphrase(in: changed, passphrase: passphrase))
        XCTAssertEqual(try VaultCrypto.connections(in: changed, using: dataKey), connections)
        var oldFormat = original
        oldFormat.format = 1
        XCTAssertThrowsError(try VaultCrypto.dataKey(from: oldFormat, keychainKey: wrapping))
    }

    func testMissingUnknownAndMalformedProtectionMetadataFailClosed() throws {
        let vault = try makeVault()
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(vault)) as? [String: Any])
        var missing = json
        missing.removeValue(forKey: "keyProtection")
        XCTAssertThrowsError(try JSONDecoder().decode(ConnectionVault.self, from: JSONSerialization.data(withJSONObject: missing)))
        for protection: [String: Any] in [
            ["kind": "unknown-protection"],
            ["kind": ConnectionVault.KeyProtection.legacyKind, "salt": Data([1]).base64EncodedString()]
        ] {
            var malformed = json
            malformed["keyProtection"] = protection
            XCTAssertThrowsError(try JSONDecoder().decode(ConnectionVault.self, from: JSONSerialization.data(withJSONObject: malformed)))
        }
        var legacyWithMetadata = json
        legacyWithMetadata["format"] = 1
        XCTAssertThrowsError(try JSONDecoder().decode(ConnectionVault.self, from: JSONSerialization.data(withJSONObject: legacyWithMetadata)))
    }

    func testRecoveryProofAuthenticatesRecoveredKeyAgainstPayload() throws {
        let wrapping = VaultCrypto.makeDataKey()
        var vault = try makeVault(keychainKey: wrapping)
        let forged = try makeVault(passphrase: "attacker-chosen-passphrase")
        vault.passphraseSlot = forged.passphraseSlot
        XCTAssertNoThrow(try VaultCrypto.dataKey(from: vault, keychainKey: wrapping))
        XCTAssertNoThrow(try VaultCrypto.dataKey(from: vault, passphrase: "attacker-chosen-passphrase"))
        XCTAssertThrowsError(try VaultCrypto.verifyPassphrase(in: vault, passphrase: "attacker-chosen-passphrase"))
    }

    func testMalformedKnownHardwareSlotDoesNotInvalidateIndependentRecovery() throws {
        let protection = ConnectionVault.KeyProtection(kind: ConnectionVault.KeyProtection.enclaveKind,
                                                       keyRepresentation: Data([1]), peerPublicKey: Data(repeating: 2, count: 65),
                                                       salt: Data(repeating: 3, count: 32))
        let original = try VaultCrypto.seal(connections, dataKey: VaultCrypto.makeDataKey(), keychainKey: VaultCrypto.makeDataKey(),
                                           passphrase: passphrase, rounds: testRounds, keyProtection: protection)
        var json = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(original)) as? [String: Any])
        json["keyProtection"] = ["kind": protection.kind, "keyRepresentation": "not-base64!", "peerPublicKey": 1, "salt": [1, 2]]
        let damaged = try JSONDecoder().decode(ConnectionVault.self, from: JSONSerialization.data(withJSONObject: json))
        XCTAssertTrue(damaged.keyProtection.isAppLockEnabled)
        XCTAssertThrowsError(try damaged.keyProtection.validate())
        XCTAssertNoThrow(try VaultCrypto.verifyPassphrase(in: damaged, passphrase: passphrase))
        let key = try VaultCrypto.dataKey(from: damaged, passphrase: passphrase)
        XCTAssertEqual(try VaultCrypto.connections(in: damaged, using: key), connections)
    }

}
