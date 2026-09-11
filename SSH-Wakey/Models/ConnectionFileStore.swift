import Darwin
import Foundation

/// Writes a file that is never readable by anyone else, not even briefly.
///
/// `Data.write(options: .atomic)` creates its temporary file using the process
/// umask, normally leaving it mode 0644, and only a later `chmod` narrows it.
/// That is a window in which the contents are world readable. Creating the
/// temporary file with the mode it should already have, then renaming it into
/// place, closes the window without giving up atomicity.
enum ProtectedFile {

    enum WriteError: LocalizedError {
        case failed(String, String)

        var errorDescription: String? {
            switch self {
            case .failed(let action, let reason):
                return "Could not \(action): \(reason)"
            }
        }
    }

    static func write(_ data: Data, to url: URL, mode: mode_t = 0o600) throws {
        let temporary = url.deletingLastPathComponent()
            .appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString.prefix(8))")

        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL, mode)
        guard descriptor >= 0 else {
            throw WriteError.failed("create \(url.lastPathComponent)", String(cString: strerror(errno)))
        }

        var complete = true
        var failure = ""
        data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let written = Darwin.write(
                    descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if written > 0 {
                    offset += written
                    continue
                }
                if written < 0 && errno == EINTR { continue }
                complete = false
                failure = String(cString: strerror(errno))
                break
            }
        }
        // On disk before the rename, so a crash cannot leave an empty file
        // standing where the real one used to be.
        if complete, fsync(descriptor) != 0 {
            complete = false
            failure = String(cString: strerror(errno))
        }
        close(descriptor)

        guard complete else {
            unlink(temporary.path)
            throw WriteError.failed("write \(url.lastPathComponent)", failure)
        }
        guard rename(temporary.path, url.path) == 0 else {
            let reason = String(cString: strerror(errno))
            unlink(temporary.path)
            throw WriteError.failed("replace \(url.lastPathComponent)", reason)
        }
        chmod(url.path, mode)
    }
}

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
        /// Present when the file is not encrypted.
        var connections: [SSHConnection]?
        /// Present when it is.
        var vault: ConnectionVault?

        init(connections: [SSHConnection], version: Int = Document.currentVersion) {
            self.version = version
            self.connections = connections
        }

        init(vault: ConnectionVault, version: Int = Document.currentVersion) {
            self.version = version
            self.vault = vault
        }
    }

    /// What the file turned out to hold.
    enum Contents: Equatable {
        case empty
        case plain([SSHConnection])
        case encrypted(ConnectionVault)
    }

    enum StoreError: LocalizedError, Equatable {
        case unsupportedVersion(Int)
        case unreadable(String)
        case encrypted

        var errorDescription: String? {
            switch self {
            case .unsupportedVersion(let version):
                return "The saved connections file uses format version \(version), which this version of SSH-Wakey cannot read."
            case .unreadable(let reason):
                return "The saved connections file could not be read: \(reason)"
            case .encrypted:
                return "The saved connections file is encrypted and has not been unlocked."
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

    /// Reads whichever form the file is in. Empty when it does not exist yet,
    /// which is the normal first-launch case.
    func read() throws -> Contents {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return .empty }
        let data: Data
        do {
            data = try Data(contentsOf: fileURL)
        } catch {
            throw StoreError.unreadable(error.localizedDescription)
        }
        guard !data.isEmpty else { return .empty }

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
        if let vault = document.vault { return .encrypted(vault) }
        return .plain(document.connections ?? [])
    }

    /// The plain-text path. Throws if the file turns out to be encrypted.
    func load() throws -> [SSHConnection] {
        switch try read() {
        case .empty: return []
        case .plain(let connections): return connections
        case .encrypted: throw StoreError.encrypted
        }
    }

    /// Writes atomically, then tightens permissions on both the directory and
    /// the file. Permissions are reapplied on every save because an atomic
    /// write replaces the inode.
    func save(_ connections: [SSHConnection]) throws {
        try write(Document(connections: connections))
    }

    func save(_ vault: ConnectionVault) throws {
        try write(Document(vault: vault))
    }

    private func write(_ document: Document) throws {
        try createDirectoryIfNeeded()

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        // ISO-8601 so the dates in the file are readable if you open it.
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(document)

        try ProtectedFile.write(data, to: fileURL)
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
