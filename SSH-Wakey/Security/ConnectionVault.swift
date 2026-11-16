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
    /// OWASP's current floor for PBKDF2-HMAC-SHA256. New vaults use this.
    static let defaultRounds = 600_000
    /// Lowest count we will stretch. Tests seal with this so the suite stays
    /// fast; production writes `defaultRounds`. Invalid values are refused,
    /// never clamped.
    static let minimumRounds = 1_000
    /// Highest count we will stretch. Above this, Unlock would stall on a
    /// hostile file. Still well below `UInt32.max`.
    static let maximumRounds = 2_000_000
    /// Salt size this app writes. Empty or huge salts are refused.
    static let saltSize = 16

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

    /// True when the sealed file itself failed its checks, rather than the
    /// person presenting the wrong passphrase or no Keychain item.
    var suggestsIntegrityProblem: Bool {
        switch self {
        case .corrupted, .keychainKeyDoesNotFit: return true
        case .unsupportedFormat, .wrongPassphrase, .passphraseTooShort: return false
        }
    }

    var errorDescription: String? {
        switch self {
        case .unsupportedFormat(let format):
            return "The encrypted file uses format \(format), which this version cannot read."
        case .wrongPassphrase:
            return "That recovery passphrase is not correct."
        case .keychainKeyDoesNotFit:
            return "The key in your Keychain could not open the encrypted file. "
                + "The file may have been altered, or this key may belong to a different copy. "
                + "Try the recovery passphrase."
        case .corrupted(let detail):
            return "The encrypted connections file looks damaged or altered — its seal no longer "
                + "checks out (\(detail)). Do not trust this copy; restore from an export if you "
                + "have one."
        case .passphraseTooShort(let minimum):
            return "The recovery passphrase must be at least \(minimum) characters."
        }
    }
}

enum VaultCrypto {

    /// Short enough not to be a nuisance, long enough that it is not guessed.
    /// It is written down in a password manager, not memorised.
    static let minimumPassphraseLength = 12

    /// A passphrase worth storing in a password manager: 100 bits of entropy,
    /// in an alphabet with no characters that can be confused for each other.
    ///
    /// Random characters rather than words, because this is meant to be pasted
    /// and never typed from memory, and because a short word list would be
    /// weaker than it looks.
    static func suggestedPassphrase() -> String {
        // 32 symbols, so a byte maps onto them with no bias. I, O, 0 and 1 are
        // left out so the result can be read back without ambiguity.
        let alphabet = Array("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        let bytes = randomBytes(20)
        let characters = bytes.map { alphabet[Int($0) % alphabet.count] }
        return stride(from: 0, to: characters.count, by: 4)
            .map { String(characters[$0..<min($0 + 4, characters.count)]) }
            .joined(separator: "-")
    }

    // MARK: - Sealing

    static func makeDataKey() -> SymmetricKey { SymmetricKey(size: .bits256) }

    /// Builds a vault around a fresh or existing data key.
    static func seal(
        _ connections: [SSHConnection],
        dataKey: SymmetricKey,
        keychainKey: SymmetricKey,
        passphrase: String,
        salt: Data = randomBytes(ConnectionVault.saltSize),
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
                wrappedKey: try box(keyBytes, with: try derive(passphrase, salt: salt, rounds: rounds))))
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
        try checkPassphraseSlot(vault.passphraseSlot)
        guard !passphrase.isEmpty else { throw VaultError.wrongPassphrase }
        let slot = vault.passphraseSlot
        let wrapping = try derive(passphrase, salt: slot.salt, rounds: slot.rounds)
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
        salt: Data = randomBytes(ConnectionVault.saltSize),
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
            wrappedKey: try box(keyBytes, with: try derive(passphrase, salt: salt, rounds: rounds)))
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
    ///
    /// Rounds and salt are also checked on the passphrase opener before this
    /// runs. The guards here are so a direct call cannot trap on `UInt32` or
    /// dereference an empty buffer.
    static func derive(_ passphrase: String, salt: Data, rounds: Int) throws -> SymmetricKey {
        guard let roundCount = UInt32(exactly: rounds),
              (ConnectionVault.minimumRounds...ConnectionVault.maximumRounds).contains(rounds) else {
            throw VaultError.corrupted("key derivation failed")
        }
        guard !salt.isEmpty else {
            throw VaultError.corrupted("key derivation failed")
        }

        var passphraseBytes = Array(passphrase.utf8)
        var derived = [UInt8](repeating: 0, count: 32)
        defer {
            derived.withUnsafeMutableBytes { buffer in
                if let address = buffer.baseAddress {
                    memset_s(address, buffer.count, 0, buffer.count)
                }
            }
            passphraseBytes.withUnsafeMutableBytes { buffer in
                if let address = buffer.baseAddress, buffer.count > 0 {
                    memset_s(address, buffer.count, 0, buffer.count)
                }
            }
            passphraseBytes.removeAll(keepingCapacity: false)
        }
        guard !passphraseBytes.isEmpty else {
            throw VaultError.corrupted("key derivation failed")
        }

        let status = derived.withUnsafeMutableBufferPointer { output -> Int32 in
            salt.withUnsafeBytes { saltBytes -> Int32 in
                passphraseBytes.withUnsafeBufferPointer { input -> Int32 in
                    guard let outputBase = output.baseAddress,
                          let saltBase = saltBytes.baseAddress,
                          let inputBase = input.baseAddress else {
                        return Int32(kCCParamError)
                    }
                    return inputBase.withMemoryRebound(to: CChar.self, capacity: input.count) { password in
                        CCKeyDerivationPBKDF(
                            CCPBKDFAlgorithm(kCCPBKDF2),
                            password, input.count,
                            saltBase.assumingMemoryBound(to: UInt8.self), salt.count,
                            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                            roundCount,
                            outputBase, output.count)
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw VaultError.corrupted("key derivation failed")
        }
        return SymmetricKey(data: Data(derived))
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
        guard vault.cipher == ConnectionVault.cipherName else {
            throw VaultError.corrupted("unrecognised cipher")
        }
    }

    /// Passphrase-slot fields only. The Keychain opener must not call this:
    /// a vandalised recovery slot must not block the other way in.
    private static func checkPassphraseSlot(_ slot: ConnectionVault.PassphraseSlot) throws {
        guard slot.derivation == ConnectionVault.derivationName else {
            throw VaultError.corrupted("unrecognised key derivation")
        }
        guard slot.salt.count == ConnectionVault.saltSize else {
            throw VaultError.corrupted("the recovery slot is damaged")
        }
        guard (ConnectionVault.minimumRounds...ConnectionVault.maximumRounds).contains(slot.rounds) else {
            throw VaultError.corrupted("the recovery slot is damaged")
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
