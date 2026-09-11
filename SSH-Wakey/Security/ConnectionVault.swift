import CommonCrypto
import CryptoKit
import Foundation
import Security

/// The encrypted form of the saved connections file.
///
/// One random data key encrypts the connection list. That key is then wrapped
/// twice, so there are two independent ways in:
///
///  * a random key kept in the Keychain, used silently every time the app opens
///    the file, and
///  * a key derived from a recovery passphrase, used only when the Keychain
///    copy has gone.
///
/// Losing one does not lose the data. This is the same idea as a disk
/// encryption recovery key: the passphrase does not decrypt the file directly,
/// it decrypts the key that does, which is what allows a passphrase to be
/// changed without re-encrypting everything.
struct ConnectionVault: Codable, Equatable {

    static let currentFormat = 1
    static let cipherName = "AES-GCM-256"
    static let derivationName = "PBKDF2-HMAC-SHA256"
    /// OWASP's current floor for PBKDF2-HMAC-SHA256.
    static let defaultRounds = 600_000

    /// The recovery half: a data key wrapped with a key stretched from a
    /// passphrase.
    struct PassphraseSlot: Codable, Equatable {
        var derivation: String
        var salt: Data
        var rounds: Int
        var wrappedKey: Data
    }

    var format: Int
    var cipher: String
    /// The connection list, sealed with the data key.
    var payload: Data
    /// The data key, sealed with the key held in the Keychain.
    var keychainWrappedKey: Data
    var passphraseSlot: PassphraseSlot
}

enum VaultError: LocalizedError, Equatable {
    case unsupportedFormat(Int)
    case wrongPassphrase
    case keychainKeyDoesNotFit
    case corrupted(String)
    case passphraseTooShort(Int)

    var errorDescription: String? {
        switch self {
        case .unsupportedFormat(let format):
            return "The encrypted file uses format \(format), which this version cannot read."
        case .wrongPassphrase:
            return "That recovery passphrase is not correct."
        case .keychainKeyDoesNotFit:
            return "The key in the Keychain does not open this file. It may belong to a different "
                + "copy of your connections. Use the recovery passphrase instead."
        case .corrupted(let detail):
            return "The encrypted file could not be read: \(detail)"
        case .passphraseTooShort(let minimum):
            return "The recovery passphrase must be at least \(minimum) characters."
        }
    }
}

enum VaultCrypto {

    /// Short enough not to be a nuisance, long enough that it is not guessed.
    /// It is written down in a password manager, not memorised.
    static let minimumPassphraseLength = 12

    // MARK: - Sealing

    static func makeDataKey() -> SymmetricKey { SymmetricKey(size: .bits256) }

    /// Builds a vault around a fresh or existing data key.
    static func seal(
        _ connections: [SSHConnection],
        dataKey: SymmetricKey,
        keychainKey: SymmetricKey,
        passphrase: String,
        salt: Data = randomBytes(16),
        rounds: Int = ConnectionVault.defaultRounds
    ) throws -> ConnectionVault {
        guard passphrase.count >= minimumPassphraseLength else {
            throw VaultError.passphraseTooShort(minimumPassphraseLength)
        }

        let plaintext = try encoder().encode(connections)
        let payload = try box(plaintext, with: dataKey)
        let keyBytes = dataKey.withUnsafeBytes { Data($0) }

        return ConnectionVault(
            format: ConnectionVault.currentFormat,
            cipher: ConnectionVault.cipherName,
            payload: payload,
            keychainWrappedKey: try box(keyBytes, with: keychainKey),
            passphraseSlot: ConnectionVault.PassphraseSlot(
                derivation: ConnectionVault.derivationName,
                salt: salt,
                rounds: rounds,
                wrappedKey: try box(keyBytes, with: derive(passphrase, salt: salt, rounds: rounds))))
    }

    // MARK: - Opening

    static func dataKey(from vault: ConnectionVault, keychainKey: SymmetricKey) throws -> SymmetricKey {
        try check(vault)
        guard let opened = try? unbox(vault.keychainWrappedKey, with: keychainKey) else {
            throw VaultError.keychainKeyDoesNotFit
        }
        return SymmetricKey(data: opened)
    }

    static func dataKey(from vault: ConnectionVault, passphrase: String) throws -> SymmetricKey {
        try check(vault)
        let slot = vault.passphraseSlot
        let wrapping = derive(passphrase, salt: slot.salt, rounds: slot.rounds)
        guard let opened = try? unbox(slot.wrappedKey, with: wrapping) else {
            throw VaultError.wrongPassphrase
        }
        return SymmetricKey(data: opened)
    }

    static func connections(in vault: ConnectionVault, using dataKey: SymmetricKey) throws -> [SSHConnection] {
        guard let plaintext = try? unbox(vault.payload, with: dataKey) else {
            throw VaultError.corrupted("the contents did not decrypt")
        }
        do {
            return try decoder().decode([SSHConnection].self, from: plaintext)
        } catch {
            throw VaultError.corrupted(error.localizedDescription)
        }
    }

    /// Re-seals the contents with the same data key, for an ordinary edit.
    static func replacingConnections(
        in vault: ConnectionVault,
        dataKey: SymmetricKey,
        with connections: [SSHConnection]
    ) throws -> ConnectionVault {
        var updated = vault
        updated.payload = try box(try encoder().encode(connections), with: dataKey)
        return updated
    }

    /// Replaces the recovery passphrase without touching the data key, so the
    /// file itself does not have to be re-encrypted.
    static func replacingPassphrase(
        in vault: ConnectionVault,
        dataKey: SymmetricKey,
        with passphrase: String,
        salt: Data = randomBytes(16),
        rounds: Int = ConnectionVault.defaultRounds
    ) throws -> ConnectionVault {
        guard passphrase.count >= minimumPassphraseLength else {
            throw VaultError.passphraseTooShort(minimumPassphraseLength)
        }
        var updated = vault
        let keyBytes = dataKey.withUnsafeBytes { Data($0) }
        updated.passphraseSlot = ConnectionVault.PassphraseSlot(
            derivation: ConnectionVault.derivationName,
            salt: salt,
            rounds: rounds,
            wrappedKey: try box(keyBytes, with: derive(passphrase, salt: salt, rounds: rounds)))
        return updated
    }

    /// Points the Keychain slot at a new Keychain key, for the case where the
    /// old one was lost and the file was opened with the passphrase.
    static func replacingKeychainKey(
        in vault: ConnectionVault,
        dataKey: SymmetricKey,
        with keychainKey: SymmetricKey
    ) throws -> ConnectionVault {
        var updated = vault
        updated.keychainWrappedKey = try box(dataKey.withUnsafeBytes { Data($0) }, with: keychainKey)
        return updated
    }

    // MARK: - Primitives

    static func randomBytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        if SecRandomCopyBytes(kSecRandomDefault, count, &bytes) != errSecSuccess {
            for index in bytes.indices { bytes[index] = UInt8.random(in: 0...255) }
        }
        return Data(bytes)
    }

    /// PBKDF2-HMAC-SHA256. CryptoKit has no password-based derivation, because
    /// none of its primitives are deliberately slow, which is the whole point
    /// when the input is something a person chose.
    static func derive(_ passphrase: String, salt: Data, rounds: Int) -> SymmetricKey {
        var derived = [UInt8](repeating: 0, count: 32)
        let passphraseBytes = Array(passphrase.utf8)

        _ = derived.withUnsafeMutableBufferPointer { output in
            salt.withUnsafeBytes { saltBytes in
                passphraseBytes.withUnsafeBufferPointer { input in
                    input.baseAddress!.withMemoryRebound(to: CChar.self, capacity: input.count) { password in
                        CCKeyDerivationPBKDF(
                            CCPBKDFAlgorithm(kCCPBKDF2),
                            password, input.count,
                            saltBytes.bindMemory(to: UInt8.self).baseAddress, salt.count,
                            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                            UInt32(rounds),
                            output.baseAddress, output.count)
                    }
                }
            }
        }

        let key = SymmetricKey(data: Data(derived))
        derived.withUnsafeMutableBytes { buffer in
            if let address = buffer.baseAddress { memset_s(address, buffer.count, 0, buffer.count) }
        }
        return key
    }

    private static func box(_ plaintext: Data, with key: SymmetricKey) throws -> Data {
        guard let combined = try AES.GCM.seal(plaintext, using: key).combined else {
            throw VaultError.corrupted("the cipher produced nothing")
        }
        return combined
    }

    private static func unbox(_ ciphertext: Data, with key: SymmetricKey) throws -> Data {
        try AES.GCM.open(try AES.GCM.SealedBox(combined: ciphertext), using: key)
    }

    private static func check(_ vault: ConnectionVault) throws {
        guard vault.format <= ConnectionVault.currentFormat else {
            throw VaultError.unsupportedFormat(vault.format)
        }
    }

    /// The same settings the plain file uses, so the two forms hold identical
    /// data and can be converted either way without loss.
    static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}
