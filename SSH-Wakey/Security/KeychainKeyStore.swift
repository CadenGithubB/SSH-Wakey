import CryptoKit
import Foundation
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
        switch status {
        case errSecSuccess:
            guard let data = item as? Data, data.count == 32 else { return nil }
            return SymmetricKey(data: data)
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainError.failed("read the encryption key", status)
        }
    }

    /// Writes the key, replacing any existing one for the same account.
    static func save(_ key: SymmetricKey, account: String = defaultAccount) throws {
        let data = key.withUnsafeBytes { Data($0) }

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
