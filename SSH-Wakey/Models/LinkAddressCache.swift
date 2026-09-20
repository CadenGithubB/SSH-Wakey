import Foundation

/// Host → Ethernet address learned after a successful connect.
///
/// The MDM catalog is not writable, so Wake still needs somewhere to keep a
/// MAC. Standard connections keep this value only in their connection record,
/// so encrypted stores do not leave a plaintext hostname sidecar.
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
        guard let data = try? ProtectedFile.read(from: fileURL),
              let decoded = try? JSONDecoder().decode([String: String].self, from: data)
        else { return [:] }
        return decoded
    }

    /// Removes legacy Standard metadata when encryption is enabled or opened.
    /// This cannot erase copies already retained by backups or APFS snapshots.
    func remove() throws { try ProtectedFile.remove(at: fileURL) }

    private func save(_ table: [String: String]) {
        do {
            try ProtectedFile.createPrivateDirectory(at: fileURL.deletingLastPathComponent())
            let data = try JSONEncoder().encode(table)
            try ProtectedFile.write(data, to: fileURL)
        } catch {
            return
        }
    }
}
