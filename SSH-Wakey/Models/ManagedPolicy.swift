import CryptoKit
import Foundation

/// Reads keys from a configuration profile. Tests inject a snapshot so they
/// never touch the real domain.
protocol ManagedPreferenceReading: Sendable {
    func object(forKey key: String) -> Any?
    func isForced(_ key: String) -> Bool
}

/// Live Managed Preferences for the Managed build's bundle id.
struct SystemManagedPreferences: ManagedPreferenceReading {
    var domain: String = AppDistribution.managedPreferenceDomain

    func object(forKey key: String) -> Any? {
        CFPreferencesCopyAppValue(key as CFString, domain as CFString)
    }

    func isForced(_ key: String) -> Bool {
        CFPreferencesAppValueIsForced(key as CFString, domain as CFString)
    }
}

/// In-memory preferences for tests.
struct SnapshotPreferences: ManagedPreferenceReading {
    var values: [String: Any] = [:]
    var forced: Set<String> = []

    func object(forKey key: String) -> Any? { values[key] }
    func isForced(_ key: String) -> Bool { forced.contains(key) }
}

/// Catalog and IT switches taken from a forced configuration profile.
///
/// Unforced keys are ignored, so a local `defaults write` cannot impersonate
/// IT. The Standard build never calls this with `acceptsManagedPreferences`.
struct ManagedPolicy: Equatable, Sendable {

    static let connectionsKey = "Connections"
    static let organizationNameKey = "OrganizationName"
    static let allowDiagnosticsKey = "AllowDiagnostics"

    var connections: [SSHConnection]
    var organizationName: String?
    /// Save Diagnostics and Activity. Default on; IT can force it off.
    var allowsDiagnostics: Bool

    static func empty(allowsDiagnostics: Bool = true) -> ManagedPolicy {
        ManagedPolicy(connections: [], organizationName: nil, allowsDiagnostics: allowsDiagnostics)
    }

    /// When `acceptsManagedPreferences` is false, `reader` is not touched.
    static func load(
        from reader: some ManagedPreferenceReading,
        acceptsManagedPreferences: Bool
    ) -> ManagedPolicy {
        guard acceptsManagedPreferences else { return .empty() }

        let organizationName: String?
        if reader.isForced(organizationNameKey),
           let raw = reader.object(forKey: organizationNameKey) as? String {
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            organizationName = trimmed.isEmpty ? nil : trimmed
        } else {
            organizationName = nil
        }

        let allowsDiagnostics: Bool
        if reader.isForced(allowDiagnosticsKey) {
            allowsDiagnostics = bool(from: reader.object(forKey: allowDiagnosticsKey)) ?? true
        } else {
            allowsDiagnostics = true
        }

        let connections: [SSHConnection]
        if reader.isForced(connectionsKey) {
            connections = parseConnections(reader.object(forKey: connectionsKey))
        } else {
            connections = []
        }

        return ManagedPolicy(
            connections: connections,
            organizationName: organizationName,
            allowsDiagnostics: allowsDiagnostics)
    }

    /// Stable across profile reloads so Activity and table selection survive.
    static func stableID(username: String, host: String, port: Int) -> UUID {
        let material = "\(username.lowercased())|\(host.lowercased())|\(port)"
        let digest = SHA256.hash(data: Data(material.utf8))
        var bytes = Array(digest.prefix(16))
        bytes[6] = (bytes[6] & 0x0F) | 0x50
        bytes[8] = (bytes[8] & 0x3F) | 0x80
        return UUID(uuid: (
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]
        ))
    }

    static func parseConnections(_ raw: Any?) -> [SSHConnection] {
        let rows: [[String: Any]]
        if let array = raw as? [[String: Any]] {
            rows = array
        } else if let array = raw as? [Any] {
            rows = array.compactMap { $0 as? [String: Any] }
        } else {
            return []
        }

        var parsed: [SSHConnection] = []
        parsed.reserveCapacity(rows.count)
        for row in rows {
            guard let username = string(row, "Username"),
                  let host = string(row, "Host"),
                  !username.isEmpty, !host.isEmpty else { continue }
            let port = int(row, "Port") ?? SSHConnection.defaultPort
            guard (1...65535).contains(port) else { continue }
            let name = string(row, "Name").flatMap { $0.isEmpty ? nil : $0 } ?? host
            parsed.append(SSHConnection(
                id: stableID(username: username, host: host, port: port),
                name: name,
                username: username,
                host: host,
                port: port,
                extraArguments: "",
                strictHostKeyChecking: true,
                connectMode: .unlock))
        }
        return parsed
    }

    private static func string(_ row: [String: Any], _ key: String) -> String? {
        if let value = row[key] as? String {
            return value.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return nil
    }

    private static func int(_ row: [String: Any], _ key: String) -> Int? {
        if let value = row[key] as? Int { return value }
        if let value = row[key] as? NSNumber { return value.intValue }
        if let value = row[key] as? String { return Int(value) }
        return nil
    }

    private static func bool(from raw: Any?) -> Bool? {
        if let value = raw as? Bool { return value }
        if let value = raw as? NSNumber { return value.boolValue }
        return nil
    }
}
