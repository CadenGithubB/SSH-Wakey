import Foundation

/// Reads and writes the saved connection list.
///
/// The file holds connection metadata only. It lives in Application Support,
/// in a directory created `0700`, and the file itself is written `0600`, so it
/// is readable only by the account that created it.
struct ConnectionFileStore: Sendable {

    /// Wrapper written to disk so a future format change can be detected
    /// instead of being misread.
    struct Document: Codable, Sendable {
        static let currentVersion = 1
        var version: Int
        var connections: [SSHConnection]

        init(connections: [SSHConnection], version: Int = Document.currentVersion) {
            self.version = version
            self.connections = connections
        }
    }

    enum StoreError: LocalizedError, Equatable {
        case unsupportedVersion(Int)
        case unreadable(String)

        var errorDescription: String? {
            switch self {
            case .unsupportedVersion(let version):
                return "The saved connections file uses format version \(version), which this version of SSH-Wakey cannot read."
            case .unreadable(let reason):
                return "The saved connections file could not be read: \(reason)"
            }
        }
    }

    /// `~/Library/Application Support/SSH-Wakey`
    static var defaultDirectory: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support", isDirectory: true)
        return base.appendingPathComponent("SSH-Wakey", isDirectory: true)
    }

    let directoryURL: URL

    var fileURL: URL { directoryURL.appendingPathComponent("connections.json", isDirectory: false) }

    init(directoryURL: URL = ConnectionFileStore.defaultDirectory) {
        self.directoryURL = directoryURL
    }

    /// An empty list when the file does not exist yet, which is the normal
    /// first-launch case.
    func load() throws -> [SSHConnection] {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return [] }
        let data: Data
        do {
            data = try Data(contentsOf: fileURL)
        } catch {
            throw StoreError.unreadable(error.localizedDescription)
        }
        guard !data.isEmpty else { return [] }

        let document: Document
        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            document = try decoder.decode(Document.self, from: data)
        } catch {
            throw StoreError.unreadable(error.localizedDescription)
        }
        guard document.version <= Document.currentVersion else {
            throw StoreError.unsupportedVersion(document.version)
        }
        return document.connections
    }

    /// Writes atomically, then tightens permissions on both the directory and
    /// the file. Permissions are reapplied on every save because an atomic
    /// write replaces the inode.
    func save(_ connections: [SSHConnection]) throws {
        try createDirectoryIfNeeded()

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        // ISO-8601 so the dates in the file are readable if you open it.
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(Document(connections: connections))

        try data.write(to: fileURL, options: [.atomic])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
    }

    func createDirectoryIfNeeded() throws {
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: directoryURL.path, isDirectory: &isDirectory) {
            if !isDirectory.boolValue {
                throw StoreError.unreadable("\(directoryURL.path) exists but is not a folder.")
            }
        } else {
            try FileManager.default.createDirectory(
                at: directoryURL,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directoryURL.path)
    }
}
