import CommonCrypto
import CryptoKit
import Foundation
import Security

/// The encrypted form of the saved connections file.
///
/// One random data key encrypts the connection list. A login-Keychain key or
/// user-presence-protected Secure Enclave operation wraps it for ordinary use;
/// a recovery-passphrase-derived key provides an independent recovery wrapper.
/// Security-mode and passphrase changes rotate the data key and both wrappers.
struct ConnectionVault: Codable, Equatable {

    static let currentFormat = 2
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

        init(derivation: String, salt: Data, rounds: Int, wrappedKey: Data) {
            self.derivation = derivation
            self.salt = salt
            self.rounds = rounds
            self.wrappedKey = wrappedKey
        }

        /// A broken recovery field must not prevent decoding the independently
        /// usable Keychain slot. Invalid fields become an explicitly unusable
        /// recovery slot and are rejected before key derivation.
        init(from decoder: Decoder) throws {
            let fields = try? decoder.container(keyedBy: CodingKeys.self)
            derivation = (try? fields?.decode(String.self, forKey: .derivation)) ?? ""
            salt = (try? fields?.decode(Data.self, forKey: .salt)) ?? Data()
            rounds = (try? fields?.decode(Int.self, forKey: .rounds)) ?? 0
            wrappedKey = (try? fields?.decode(Data.self, forKey: .wrappedKey)) ?? Data()
        }

        private enum CodingKeys: String, CodingKey { case derivation, salt, rounds, wrappedKey }
        static var damaged: Self { Self(derivation: "", salt: Data(), rounds: 0, wrappedKey: Data()) }
    }

    /// The mode is authenticated with every format-2 GCM box. Hardware-slot
    /// fields additionally bind its own wrapper, preserving independent recovery
    /// if that slot is damaged. The representation is an opaque, device-bound
    /// encrypted key blob, never an exported private key.
    struct KeyProtection: Codable, Equatable, Sendable {
        static let legacyKind = "login-keychain"
        static let enclaveKind = "secure-enclave-user-presence-v1"
        var kind: String
        var keyRepresentation: Data?
        var peerPublicKey: Data?
        var salt: Data?

        init(kind: String, keyRepresentation: Data? = nil, peerPublicKey: Data? = nil, salt: Data? = nil) {
            self.kind = kind
            self.keyRepresentation = keyRepresentation
            self.peerPublicKey = peerPublicKey
            self.salt = salt
        }

        init(from decoder: Decoder) throws {
            let fields = try decoder.container(keyedBy: CodingKeys.self)
            kind = try fields.decode(String.self, forKey: .kind)
            keyRepresentation = try? fields.decode(Data.self, forKey: .keyRepresentation)
            peerPublicKey = try? fields.decode(Data.self, forKey: .peerPublicKey)
            salt = try? fields.decode(Data.self, forKey: .salt)
            if kind == Self.legacyKind,
               fields.contains(.keyRepresentation) || fields.contains(.peerPublicKey) || fields.contains(.salt) {
                throw VaultError.corrupted("unexpected key protection metadata")
            }
            try validateMode()
        }

        private enum CodingKeys: String, CodingKey { case kind, keyRepresentation, peerPublicKey, salt }
        static let legacy = Self(kind: legacyKind)
        var isAppLockEnabled: Bool { kind == Self.enclaveKind }

        func validateMode() throws {
            switch kind {
            case Self.legacyKind:
                guard keyRepresentation == nil, peerPublicKey == nil, salt == nil else {
                    throw VaultError.corrupted("unexpected key protection metadata")
                }
            case Self.enclaveKind: break
            default: throw VaultError.corrupted("unsupported key protection")
            }
        }

        func validate() throws {
            try validateMode()
            if isAppLockEnabled {
                guard let keyRepresentation, (1...16384).contains(keyRepresentation.count),
                      peerPublicKey?.count == 65, salt?.count == 32 else {
                    throw VaultError.corrupted("invalid App Lock metadata")
                }
            }
        }
    }

    var format: Int
    var cipher: String
    /// The connection list, sealed with the data key.
    var payload: Data
    /// The data key, sealed with the login-Keychain or protected hardware-derived
    /// wrapping key. The serialized field name is retained for compatibility.
    var keychainWrappedKey: Data
    var passphraseSlot: PassphraseSlot
    var keyProtection: KeyProtection

    var hasUsableRecoverySlot: Bool {
        passphraseSlot.derivation == Self.derivationName
            && passphraseSlot.salt.count == Self.saltSize
            && (Self.minimumRounds...Self.maximumRounds).contains(passphraseSlot.rounds)
            && passphraseSlot.wrappedKey.count == 60
    }

    init(format: Int, cipher: String, payload: Data, keychainWrappedKey: Data, passphraseSlot: PassphraseSlot, keyProtection: KeyProtection = .legacy) {
        self.format = format
        self.cipher = cipher
        self.payload = payload
        self.keychainWrappedKey = keychainWrappedKey
        self.passphraseSlot = passphraseSlot
        self.keyProtection = keyProtection
    }

    init(from decoder: Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        format = try fields.decode(Int.self, forKey: .format)
        cipher = try fields.decode(String.self, forKey: .cipher)
        payload = try fields.decode(Data.self, forKey: .payload)
        keychainWrappedKey = (try? fields.decode(Data.self, forKey: .keychainWrappedKey)) ?? Data()
        passphraseSlot = (try? fields.decode(PassphraseSlot.self, forKey: .passphraseSlot)) ?? .damaged
        if format == 1 {
            // An older envelope cannot claim an unauthenticated protection mode.
            guard !fields.contains(.keyProtection) else {
                throw VaultError.corrupted("unexpected protection metadata in a legacy vault")
            }
            keyProtection = .legacy
        } else {
            keyProtection = try fields.decode(KeyProtection.self, forKey: .keyProtection)
            try keyProtection.validateMode()
        }
    }

    func encode(to encoder: Encoder) throws {
        var fields = encoder.container(keyedBy: CodingKeys.self)
        try fields.encode(format, forKey: .format)
        try fields.encode(cipher, forKey: .cipher)
        try fields.encode(payload, forKey: .payload)
        try fields.encode(keychainWrappedKey, forKey: .keychainWrappedKey)
        try fields.encode(passphraseSlot, forKey: .passphraseSlot)
        if format != 1 { try fields.encode(keyProtection, forKey: .keyProtection) }
    }

    private enum CodingKeys: String, CodingKey { case format, cipher, payload, keychainWrappedKey, passphraseSlot, keyProtection }
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
    static let maximumPassphraseBytes = 4096

    /// A passphrase worth storing in a password manager: 100 bits of entropy,
    /// in an alphabet with no characters that can be confused for each other.
    ///
    /// Random characters rather than words, because this is meant to be pasted
    /// and never typed from memory, and because a short word list would be
    /// weaker than it looks.
    static func suggestedPassphrase() throws -> String {
        let alphabet = Array("ABCDEFGHJKLMNPQRSTUVWXYZ23456789".utf8) // public alphabet
        let random = try SecureBuffer(capacity: 20)
        defer { random.wipe() }
        let status = random.withFreeSpace { bytes in
            SecRandomCopyBytes(kSecRandomDefault, bytes.count, bytes.baseAddress!)
        }
        guard status == errSecSuccess else { throw VaultError.corrupted("secure random generation failed") }
        random.advance(by: 20)
        guard let result = random.withBytes({ bytes in
            String(unsafeUninitializedCapacity: 24) { destination in
                var offset = 0
                for index in 0..<bytes.count {
                    if index > 0 && index % 4 == 0 { destination[offset] = 45; offset += 1 }
                    destination[offset] = alphabet[Int(bytes[index]) % alphabet.count]
                    offset += 1
                }
                return offset
            }
        }) else { throw VaultError.corrupted("secure random generation failed") }
        return result
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
        rounds: Int = ConnectionVault.defaultRounds,
        keyProtection: ConnectionVault.KeyProtection = .legacy
    ) throws -> ConnectionVault {
        guard passphrase.count >= minimumPassphraseLength else {
            throw VaultError.passphraseTooShort(minimumPassphraseLength)
        }

        try keyProtection.validate()
        let recoveryKey = try derive(passphrase, salt: salt, rounds: rounds)
        var plaintext = try encoder().encode(connections)
        defer { erase(&plaintext) }
        let payload = try box(plaintext, with: dataKey, authenticating: authenticationData(format: ConnectionVault.currentFormat, protection: keyProtection, purpose: .payload))

        return ConnectionVault(
            format: ConnectionVault.currentFormat,
            cipher: ConnectionVault.cipherName,
            payload: payload,
            keychainWrappedKey: try wrap(dataKey, with: keychainKey, authenticating: authenticationData(format: ConnectionVault.currentFormat, protection: keyProtection, purpose: .keychain)),
            passphraseSlot: ConnectionVault.PassphraseSlot(
                derivation: ConnectionVault.derivationName,
                salt: salt,
                rounds: rounds,
                wrappedKey: try wrap(dataKey, with: recoveryKey, authenticating: authenticationData(format: ConnectionVault.currentFormat, protection: keyProtection, purpose: .recovery))),
            keyProtection: keyProtection)
    }

    // MARK: - Opening

    static func dataKey(from vault: ConnectionVault, keychainKey: SymmetricKey) throws -> SymmetricKey {
        try check(vault)
        guard var opened = try? unbox(vault.keychainWrappedKey, with: keychainKey, authenticating: authenticationData(vault, purpose: .keychain)) else {
            throw VaultError.keychainKeyDoesNotFit
        }
        defer { erase(&opened) }
        guard opened.count == 32 else { throw VaultError.corrupted("invalid data key size") }
        return opened.withUnsafeBytes { SymmetricKey(data: $0) }
    }

    static func dataKey(from vault: ConnectionVault, passphrase: String) throws -> SymmetricKey {
        try check(vault)
        try checkPassphraseSlot(vault.passphraseSlot)
        guard !passphrase.isEmpty else { throw VaultError.wrongPassphrase }
        let slot = vault.passphraseSlot
        let wrapping = try derive(passphrase, salt: slot.salt, rounds: slot.rounds)
        guard var opened = try? unbox(slot.wrappedKey, with: wrapping, authenticating: authenticationData(vault, purpose: .recovery)) else {
            throw VaultError.wrongPassphrase
        }
        defer { erase(&opened) }
        guard opened.count == 32 else { throw VaultError.corrupted("invalid data key size") }
        return opened.withUnsafeBytes { SymmetricKey(data: $0) }
    }

    /// A recovery wrapper is an independent slot. Successfully opening it is
    /// not sufficient authorization: it could have been replaced with a wrapper
    /// for an unrelated key. Verify its key against the authentic payload too.
    static func verifyPassphrase(in vault: ConnectionVault, passphrase: String) throws {
        let key = try dataKey(from: vault, passphrase: passphrase)
        guard var plaintext = try? unbox(vault.payload, with: key, authenticating: authenticationData(vault, purpose: .payload)) else {
            throw VaultError.wrongPassphrase
        }
        erase(&plaintext)
    }

    static func connections(in vault: ConnectionVault, using dataKey: SymmetricKey) throws -> [SSHConnection] {
        try check(vault)
        guard var plaintext = try? unbox(vault.payload, with: dataKey, authenticating: authenticationData(vault, purpose: .payload)) else {
            throw VaultError.corrupted("the contents did not decrypt")
        }
        defer { erase(&plaintext) }
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
        var plaintext = try encoder().encode(connections)
        defer { erase(&plaintext) }
        updated.payload = try box(plaintext, with: dataKey, authenticating: authenticationData(vault, purpose: .payload))
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
        let recoveryKey = try derive(passphrase, salt: salt, rounds: rounds)
        updated.passphraseSlot = ConnectionVault.PassphraseSlot(
            derivation: ConnectionVault.derivationName,
            salt: salt,
            rounds: rounds,
            wrappedKey: try wrap(dataKey, with: recoveryKey, authenticating: authenticationData(vault, purpose: .recovery)))
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
        updated.keychainWrappedKey = try wrap(dataKey, with: keychainKey, authenticating: authenticationData(vault, purpose: .keychain))
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
        guard salt.count == ConnectionVault.saltSize else {
            throw VaultError.corrupted("key derivation failed")
        }

        guard !passphrase.isEmpty, passphrase.utf8.count <= maximumPassphraseBytes else {
            throw VaultError.corrupted("the recovery passphrase has an unsupported size")
        }
        let input = try SecureBuffer(passphrase)
        defer { input.wipe() }
        let output = try SecureBuffer(capacity: 32)
        defer { output.wipe() }
        let status = input.withBytes { passwordBytes in
            output.withFreeSpace { derivedBytes in
                salt.withUnsafeBytes { saltBytes -> Int32 in
                    guard let password = passwordBytes.baseAddress,
                          let derived = derivedBytes.baseAddress,
                          let saltBase = saltBytes.baseAddress else {
                        return Int32(kCCParamError)
                    }
                    return CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        password.assumingMemoryBound(to: CChar.self), passwordBytes.count,
                        saltBase.assumingMemoryBound(to: UInt8.self), saltBytes.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), roundCount,
                        derived.assumingMemoryBound(to: UInt8.self), derivedBytes.count)
                }
            }
        }
        guard let result = status.flatMap({ $0 }), result == Int32(kCCSuccess) else {
            throw VaultError.corrupted("key derivation failed")
        }
        output.advance(by: 32)
        guard let key = output.withBytes({ SymmetricKey(data: $0) }) else {
            throw VaultError.corrupted("key derivation failed")
        }
        return key
    }

    /// No ordinary Data allocation containing the raw data key is needed.
    private static func wrap(_ dataKey: SymmetricKey, with wrappingKey: SymmetricKey, authenticating authentication: Data) throws -> Data {
        try dataKey.withUnsafeBytes { bytes in
            guard let combined = try AES.GCM.seal(bytes, using: wrappingKey, authenticating: authentication).combined else {
                throw VaultError.corrupted("the cipher produced nothing")
            }
            return combined
        }
    }

    /// Clears the mutable Data values owned here. CryptoKit/Foundation may have
    /// internal copies; this is not a promise to erase framework-owned memory.
    private static func erase(_ data: inout Data) {
        data.withUnsafeMutableBytes { bytes in
            if let base = bytes.baseAddress, !bytes.isEmpty {
                memset_s(base, bytes.count, 0, bytes.count)
            }
        }
        data.removeAll(keepingCapacity: false)
    }

    private static func box(_ plaintext: Data, with key: SymmetricKey, authenticating authentication: Data) throws -> Data {
        guard let combined = try AES.GCM.seal(plaintext, using: key, authenticating: authentication).combined else {
            throw VaultError.corrupted("the cipher produced nothing")
        }
        return combined
    }

    private static func unbox(_ ciphertext: Data, with key: SymmetricKey, authenticating authentication: Data) throws -> Data {
        try AES.GCM.open(try AES.GCM.SealedBox(combined: ciphertext), using: key, authenticating: authentication)
    }

    private enum BoxPurpose: String { case payload, keychain, recovery }

    private static func authenticationData(_ vault: ConnectionVault, purpose: BoxPurpose) throws -> Data {
        try check(vault)
        return try authenticationData(format: vault.format, protection: vault.keyProtection, purpose: purpose)
    }

    private static func authenticationData(format: Int, protection: ConnectionVault.KeyProtection,
                                           purpose: BoxPurpose) throws -> Data {
        guard format != 1 else { return Data() }
        var data = Data("SSH-Wakey vault format 2\0\(purpose.rawValue)\0".utf8)
        if purpose == .keychain {
            data.append(try encoder().encode(protection))
        } else {
            data.append(try encoder().encode(protection.kind))
        }
        return data
    }

    static func check(_ vault: ConnectionVault) throws {
        guard (1...ConnectionVault.currentFormat).contains(vault.format) else {
            throw VaultError.unsupportedFormat(vault.format)
        }
        try vault.keyProtection.validateMode()
        guard vault.format != 1 || vault.keyProtection == .legacy else {
            throw VaultError.corrupted("a legacy vault cannot carry App Lock metadata")
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
        guard slot.salt.count == ConnectionVault.saltSize, slot.wrappedKey.count == 60 else {
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
