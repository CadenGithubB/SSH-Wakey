import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Holds the everyday key for the encrypted connections file in the login
/// keychain.
///
/// This is the slot that makes encryption invisible in normal use: the app
/// reads the key, opens the file and gets on with it. The recovery passphrase
/// exists precisely because this slot can go away, when a keychain is reset, a
/// machine is replaced, or an item is deleted by hand.
enum KeychainKeyStore {

    static let service = "com.CadenGithubB.sshwakey"
    static let defaultAccount = "connections-encryption-key"

    enum KeychainError: LocalizedError, Equatable {
        case failed(String, OSStatus)

        var errorDescription: String? {
            switch self {
            case .failed(let action, let status):
                let detail = SecCopyErrorMessageString(status, nil) as String? ?? "status \(status)"
                return "The Keychain could not \(action): \(detail)"
            }
        }
    }

    /// Nil when there is no key stored, which is the normal state until
    /// encryption is switched on.
    static func load(account: String = defaultAccount) throws -> SymmetricKey? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        defer { item = nil }
        switch status {
        case errSecSuccess:
            guard let item, CFGetTypeID(item) == CFDataGetTypeID() else { return nil }
            let data = unsafeBitCast(item, to: CFData.self)
            guard CFDataGetLength(data) == 32, let bytes = CFDataGetBytePtr(data) else { return nil }
            // Borrow Security's returned CFData directly; do not create another
            // Swift Data containing the raw key. Security owns its buffer.
            return SymmetricKey(data: UnsafeRawBufferPointer(start: bytes, count: 32))
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.failed("read the encryption key", status)
        }
    }

    /// Atomically creates a key only if absent. Competing app instances must
    /// reuse the winning key, not invalidate one another's vault wrappers.
    static func loadOrCreate(account: String = defaultAccount) throws -> SymmetricKey {
        if let existing = try load(account: account) { return existing }
        let key = makeKey()
        let status = try withBorrowedKeyData(key) { data in
            var query = baseQuery(account: account)
            query[kSecValueData as String] = data
            query[kSecAttrDescription as String] = "SSH-Wakey saved connections"
            return SecItemAdd(query as CFDictionary, nil)
        }
        if status == errSecSuccess { return key }
        if status == errSecDuplicateItem, let existing = try load(account: account) { return existing }
        throw KeychainError.failed("create the encryption key", status)
    }

    /// Writes the key, replacing any existing one for the same account.
    static func save(_ key: SymmetricKey, account: String = defaultAccount) throws {
        try withBorrowedKeyData(key) { data in
            var query = baseQuery(account: account)
            let attributes: [String: Any] = [kSecValueData as String: data]
            let updated = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            if updated == errSecSuccess { return }
            guard updated == errSecItemNotFound else {
                throw KeychainError.failed("update the encryption key", updated)
            }
            query[kSecValueData as String] = data
            query[kSecAttrDescription as String] = "SSH-Wakey saved connections"
            let added = SecItemAdd(query as CFDictionary, nil)
            guard added == errSecSuccess else {
                throw KeychainError.failed("store the encryption key", added)
            }
        }
    }

    /// Security requires CFData. Borrow SymmetricKey's storage for the duration
    /// of synchronous SecItem calls without allocating a plaintext Data copy.
    /// Security may copy the value internally; that platform boundary remains.
    private static func withBorrowedKeyData<T>(
        _ key: SymmetricKey, _ operation: (CFData) throws -> T
    ) throws -> T {
        try key.withUnsafeBytes { bytes in
            guard bytes.count == 32, let base = bytes.baseAddress,
                  let data = CFDataCreateWithBytesNoCopy(
                    kCFAllocatorDefault, base.assumingMemoryBound(to: UInt8.self), bytes.count,
                    kCFAllocatorNull) else {
                throw KeychainError.failed("prepare the encryption key", errSecParam)
            }
            return try operation(data)
        }
    }

    /// Removing the key does not destroy the data: the recovery passphrase
    /// still opens the file.
    static func delete(account: String = defaultAccount) throws {
        let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.failed("remove the encryption key", status)
        }
    }

    static func makeKey() -> SymmetricKey { SymmetricKey(size: .bits256) }

    private static func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }
}

// MARK: - App Lock

/// Kept behind an interface so vault state-machine tests never trigger biometric
/// prompts or depend on the test host's hardware or signing identity.
protocol AppLockKeyProviding: Sendable {
    func makeProtection() throws -> ConnectionVault.KeyProtection
    func wrappingKey(for protection: ConnectionVault.KeyProtection,
                     authentication: AppLockAuthentication) async throws -> SymmetricKey
}

enum AppLockError: LocalizedError, Equatable {
    case unavailable
    case invalidPreparation
    case authenticationFailed

    var errorDescription: String? {
        switch self {
        case .unavailable:
            return "App Lock requires a Mac with an available Secure Enclave and a Mac login password. This Mac could not create its protected key."
        case .invalidPreparation:
            return "This security change expired or the connections file changed. Please unlock and try again."
        case .authenticationFailed:
            return "Your Mac could not authenticate access to the protected connections key. Try again or use your recovery passphrase."
        }
    }
}

/// A context belongs to exactly one operation. Invalidation cancels the system
/// prompt and prevents a late success from becoming an unlocked store.
final class AppLockAuthentication: @unchecked Sendable {
    let context: LAContext
    private let mutex = NSLock()
    private var invalidated = false

    init(reason: String = "Unlock your SSH-Wakey connections") {
        context = LAContext()
        context.localizedReason = reason
        context.touchIDAuthenticationAllowableReuseDuration = 0
    }

    func invalidate() {
        mutex.lock()
        let alreadyInvalidated = invalidated
        invalidated = true
        mutex.unlock()
        if !alreadyInvalidated { context.invalidate() }
    }

    func check() throws {
        mutex.lock()
        let cancelled = invalidated
        mutex.unlock()
        if cancelled { throw CancellationError() }
    }

    deinit { invalidate() }
}

/// The private key never leaves the Secure Enclave. Its public, opaque keyblob
/// can be saved in the vault without a permanent Data Protection Keychain item
/// or a provisioning entitlement. Each ECDH use is gated by userPresence.
struct SecureEnclaveAppLockKeys: AppLockKeyProviding {
    func makeProtection() throws -> ConnectionVault.KeyProtection {
        guard SecureEnclave.isAvailable else { throw AppLockError.unavailable }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence], &error) else {
            throw AppLockError.unavailable
        }
        do {
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
            // Only the public half survives. The wrapping key can subsequently
            // be derived only by a user-presence-authorized enclave operation.
            let peer = P256.KeyAgreement.PrivateKey().publicKey
            return .init(kind: ConnectionVault.KeyProtection.enclaveKind,
                         keyRepresentation: key.dataRepresentation,
                         peerPublicKey: peer.x963Representation,
                         salt: VaultCrypto.randomBytes(32))
        } catch { throw AppLockError.unavailable }
    }

    func wrappingKey(for protection: ConnectionVault.KeyProtection,
                     authentication: AppLockAuthentication) async throws -> SymmetricKey {
        try protection.validate()
        guard protection.isAppLockEnabled,
              let representation = protection.keyRepresentation,
              let publicKey = protection.peerPublicKey, let salt = protection.salt else {
            throw AppLockError.authenticationFailed
        }
        return try await withTaskCancellationHandler {
            try await Task.detached(priority: .userInitiated) {
                try authentication.check()
                let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                    dataRepresentation: representation, authenticationContext: authentication.context)
                let peer = try P256.KeyAgreement.PublicKey(x963Representation: publicKey)
                let shared = try key.sharedSecretFromKeyAgreement(with: peer)
                try authentication.check()
                return shared.hkdfDerivedSymmetricKey(
                    using: SHA256.self, salt: salt,
                    sharedInfo: Data("SSH-Wakey App Lock wrapping key v1".utf8), outputByteCount: 32)
            }.value
        } onCancel: { authentication.invalidate() }
    }
}
