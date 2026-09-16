import Foundation

/// Host → Ethernet address learned after a successful connect.
///
/// The MDM catalog is not writable, so Wake still needs somewhere to keep a
/// MAC. The same cache is used in Standard as a backup next to the field on
/// the connection itself.
struct LinkAddressCache: Sendable {

    let fileURL: URL

    init(directoryURL: URL) {
        self.fileURL = directoryURL.appendingPathComponent("link-addresses.json", isDirectory: false)
    }

    func address(for host: String) -> String? {
        table()[normalized(host)]
    }

    func store(_ mac: String, for host: String) {
        guard let parsed = NetworkWake.MACAddress(parsing: mac) else { return }
        var current = table()
        current[normalized(host)] = parsed.colonSeparated
        save(current)
    }

    private func normalized(_ host: String) -> String {
        host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    private func table() -> [String: String] {
        guard let data = try? Data(contentsOf: fileURL),
              let decoded = try? JSONDecoder().decode([String: String].self, from: data)
        else { return [:] }
        return decoded
    }

    private func save(_ table: [String: String]) {
        do {
            try FileManager.default.createDirectory(
                at: fileURL.deletingLastPathComponent(),
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            let data = try JSONEncoder().encode(table)
            try ProtectedFile.write(data, to: fileURL)
        } catch {
            return
        }
    }
}
