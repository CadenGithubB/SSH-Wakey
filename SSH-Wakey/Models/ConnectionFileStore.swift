import CryptoKit
import Darwin
import Foundation

/// Descriptor-based private-file access. No application-controlled path component
/// may be a symlink. ACLs are checked as well as POSIX modes; new files have their
/// inherited ACL removed before any content is written.
enum ProtectedFile {
    enum WriteError: LocalizedError {
        case failed(String, String)
        var errorDescription: String? {
            switch self {
            case .failed(let action, let reason): return "Could not \(action): \(reason)"
            }
        }
    }

    enum Revision: Equatable {
        case missing
        case contents(Data)
        fileprivate init(_ data: Data?) {
            self = data.map { .contents(Data(SHA256.hash(data: $0))) } ?? .missing
        }
    }

    static let maximumFileBytes = 16 * 1024 * 1024

    static func createPrivateDirectory(at url: URL) throws {
        let descriptor = try directory(at: url, create: true, privateLeaf: true)
        close(descriptor)
    }

    /// Nil means verified absence, never a permissions or pathname error.
    static func read(from url: URL, maximumBytes: Int = maximumFileBytes) throws -> Data? {
        guard let parent = try parentDirectory(of: url, allowMissing: true) else { return nil }
        defer { close(parent) }
        return try read(name: url.lastPathComponent, parent: parent, maximumBytes: maximumBytes)
    }

    static func revision(of data: Data?) -> Revision { Revision(data) }

    static func write(
        _ data: Data, to url: URL, mode: mode_t = 0o600,
        expectedRevision: Revision? = nil
    ) throws {
        let parent = try requiredParent(of: url)
        defer { close(parent) }
        try locked(parent) {
            if let expectedRevision {
                let existing = try read(name: url.lastPathComponent, parent: parent, maximumBytes: maximumFileBytes)
                guard Revision(existing) == expectedRevision else {
                    throw WriteError.failed("save \(url.lastPathComponent)", "the file changed after it was opened; reopen it before saving")
                }
            } else {
                try validateDestination(name: url.lastPathComponent, parent: parent)
            }
            try write(data, name: url.lastPathComponent, parent: parent, mode: mode)
        }
    }

    /// Serializes read-modify-write operations across cooperating app instances.
    static func update(
        at url: URL, maximumBytes: Int = maximumFileBytes,
        afterWrite: (() -> Void)? = nil,
        _ transform: (Data?) throws -> Data
    ) throws {
        let parent = try requiredParent(of: url)
        defer { close(parent) }
        try locked(parent) {
            let previous = try read(name: url.lastPathComponent, parent: parent, maximumBytes: maximumBytes)
            let replacement = try transform(previous)
            guard replacement.count <= maximumBytes else { throw failure("update file", "the file is too large") }
            try write(replacement, name: url.lastPathComponent, parent: parent, mode: 0o600)
            afterWrite?()
        }
    }

    static func remove(at url: URL) throws {
        guard let parent = try parentDirectory(of: url, allowMissing: true) else { return }
        defer { close(parent) }
        try locked(parent) {
            try validateDestination(name: url.lastPathComponent, parent: parent)
            guard unlinkat(parent, url.lastPathComponent, 0) == 0 || errno == ENOENT else {
                throw failure("remove \(url.lastPathComponent)")
            }
        }
    }

    private static func locked<T>(_ descriptor: Int32, _ body: () throws -> T) throws -> T {
        while flock(descriptor, LOCK_EX) != 0 {
            if errno == EINTR { continue }
            throw failure("lock the containing directory")
        }
        defer { flock(descriptor, LOCK_UN) }
        return try body()
    }

    private static func requiredParent(of url: URL) throws -> Int32 {
        guard let descriptor = try parentDirectory(of: url, allowMissing: false) else {
            throw failure("open containing directory", "the directory is missing")
        }
        return descriptor
    }

    private static func parentDirectory(of url: URL, allowMissing: Bool) throws -> Int32? {
        guard url.isFileURL, !url.lastPathComponent.isEmpty,
              url.lastPathComponent != ".", url.lastPathComponent != ".." else {
            throw failure("open file", "invalid pathname")
        }
        return try walkDirectory(at: url.deletingLastPathComponent(), create: false,
                                 privateLeaf: false, allowMissing: allowMissing)
    }

    private static func directory(at url: URL, create: Bool, privateLeaf: Bool) throws -> Int32 {
        guard let descriptor = try walkDirectory(at: url, create: create, privateLeaf: privateLeaf, allowMissing: false) else {
            throw failure("open directory", "the directory is missing")
        }
        return descriptor
    }

    private static func walkDirectory(
        at url: URL, create: Bool, privateLeaf: Bool, allowMissing: Bool
    ) throws -> Int32? {
        guard url.isFileURL else { throw failure("open directory", "invalid pathname") }
        // macOS publishes these two root-owned system aliases. Canonicalize only
        // these fixed aliases, never arbitrary user-controlled symlinks.
        var path = url.path
        for (alias, canonical) in [("/tmp", "/private/tmp"), ("/var", "/private/var")] {
            if path == alias || path.hasPrefix(alias + "/") {
                path = canonical + path.dropFirst(alias.count)
                break
            }
        }
        let components = path.split(separator: "/").map(String.init)
        guard path.hasPrefix("/"), !components.contains(".."), !components.contains(".") else {
            throw failure("open directory", "relative path components are not permitted")
        }
        var current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard current >= 0 else { throw failure("open root directory") }
        do {
            try validateDirectory(current, privateLeaf: components.isEmpty && privateLeaf)
            for (index, component) in components.enumerated() {
                let isLeaf = index == components.count - 1
                var created = false
                var next = openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                if next < 0 && errno == ENOENT && create {
                    if mkdirat(current, component, 0o700) == 0 { created = true }
                    else if errno != EEXIST { throw failure("create private directory") }
                    next = openat(current, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                }
                if next < 0 {
                    if errno == ENOENT && allowMissing { close(current); return nil }
                    throw failure("open protected directory")
                }
                do {
                    if created {
                        try setPrivatePermissions(next, mode: 0o700)
                    }
                    try validateDirectory(next, privateLeaf: false)
                    if isLeaf && privateLeaf {
                        // Existing owner-controlled directories may have been
                        // created 0755 by an older version. Tighten only after
                        // ownership, write access and ACL validation succeeds.
                        var info = stat()
                        guard fstat(next, &info) == 0, info.st_uid == geteuid() else {
                            throw failure("secure private directory", "the directory is not owned by this account")
                        }
                        try rejectACLGrants(next, allGrants: true)
                        guard fchmod(next, 0o700) == 0 else { throw failure("secure private directory") }
                        try validateDirectory(next, privateLeaf: true)
                    }
                } catch { close(next); throw error }
                close(current)
                current = next
            }
            return current
        } catch { close(current); throw error }
    }

    private static func validateDirectory(_ descriptor: Int32, privateLeaf: Bool) throws {
        var info = stat()
        guard fstat(descriptor, &info) == 0 else { throw failure("inspect directory") }
        guard info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == geteuid() || (!privateLeaf && info.st_uid == 0) else {
            throw failure("inspect directory", "unsafe directory owner or type")
        }
        let trustedStickyAncestor = !privateLeaf && info.st_uid == 0 && info.st_mode & S_ISVTX != 0
        guard info.st_mode & (privateLeaf ? 0o077 : 0o022) == 0 || trustedStickyAncestor else {
            throw failure("inspect directory", "the directory grants unsafe access to another account")
        }
        try rejectACLGrants(descriptor, allGrants: privateLeaf)
    }

    private static func rejectACLGrants(_ descriptor: Int32, allGrants: Bool) throws {
        guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            if errno == ENOENT { return } // Darwin: this inode has no extended ACL.
            throw failure("inspect file access control")
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        guard acl_valid(acl) == 0 else { throw failure("inspect file access control") }
        var entry: acl_entry_t?
        var selector = ACL_FIRST_ENTRY
        while true {
            let status = acl_get_entry(acl, selector.rawValue, &entry)
            if status == -1 && errno == EINVAL { break } // Darwin uses EINVAL for end-of-list.
            guard status == 0, let entry else { throw failure("inspect file access control") }
            selector = ACL_NEXT_ENTRY
            var tag = ACL_UNDEFINED_TAG
            guard acl_get_tag_type(entry, &tag) == 0 else { throw failure("inspect file access control") }
            guard tag == ACL_EXTENDED_ALLOW else { continue }
            if allGrants { throw failure("inspect file access control", "an ACL grants access beyond the private file policy") }
            var permissions: acl_permset_t?
            guard acl_get_permset(entry, &permissions) == 0, let permissions else { throw failure("inspect file access control") }
            let writes: [acl_perm_t] = [ACL_WRITE_DATA, ACL_APPEND_DATA, ACL_DELETE, ACL_DELETE_CHILD,
                                       ACL_WRITE_ATTRIBUTES, ACL_WRITE_EXTATTRIBUTES, ACL_WRITE_SECURITY, ACL_CHANGE_OWNER]
            if writes.contains(where: { acl_get_perm_np(permissions, $0) != 0 }) {
                throw failure("inspect directory access control", "an ACL permits changes by another principal")
            }
        }
    }

    private static func setPrivatePermissions(_ descriptor: Int32, mode: mode_t) throws {
        guard let acl = acl_init(0) else { throw failure("create private access control") }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        guard acl_set_fd_np(descriptor, acl, ACL_TYPE_EXTENDED) == 0,
              fchmod(descriptor, mode) == 0 else { throw failure("set private file access") }
    }

    private static func validateFile(_ descriptor: Int32, requirePrivate: Bool = true) throws -> stat {
        var info = stat()
        guard fstat(descriptor, &info) == 0 else { throw failure("inspect file") }
        guard info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(), info.st_nlink == 1,
              !requirePrivate || info.st_mode & 0o077 == 0 else {
            throw failure("inspect file", "unsafe file owner, permissions, type or hard links")
        }
        try rejectACLGrants(descriptor, allGrants: true)
        return info
    }

    private static func validateDestination(name: String, parent: Int32) throws {
        let descriptor = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if descriptor < 0 && errno == ENOENT { return }
        guard descriptor >= 0 else { throw failure("inspect destination") }
        defer { close(descriptor) }
        // Replacing an owner-owned regular 0644 export safely is allowed; reads
        // of application state remain private-only. Symlinks/ACLs are refused.
        _ = try validateFile(descriptor, requirePrivate: false)
    }

    private static func read(name: String, parent: Int32, maximumBytes: Int) throws -> Data? {
        guard maximumBytes >= 0 else { throw failure("read file", "invalid size limit") }
        let descriptor = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if descriptor < 0 && errno == ENOENT { return nil }
        guard descriptor >= 0 else { throw failure("open private file") }
        defer { close(descriptor) }
        let before = try validateFile(descriptor)
        guard before.st_size >= 0, before.st_size <= maximumBytes else { throw failure("read file", "the file is too large") }
        var data = Data(count: Int(before.st_size))
        var offset = 0
        try data.withUnsafeMutableBytes { bytes in
            while offset < bytes.count {
                let count = Darwin.read(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw failure("read file", "the file changed or could not be read completely") }
                offset += count
            }
        }
        var extra: UInt8 = 0
        var count: Int
        repeat { count = Darwin.read(descriptor, &extra, 1) } while count < 0 && errno == EINTR
        let after = try validateFile(descriptor)
        guard count == 0, before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec else {
            throw failure("read file", "the file changed while being read")
        }
        return data
    }

    private static func write(_ data: Data, name: String, parent: Int32, mode: mode_t) throws {
        guard mode & 0o077 == 0, data.count <= maximumFileBytes else { throw failure("write private file", "unsafe mode or excessive file size") }
        // Establish a private containing directory before creating the data
        // inode. Creating directly in an ACL-inheriting export folder and then
        // stripping its ACL would let another account open it in that interval
        // and retain a readable descriptor after the ACL was removed.
        let temporary = ".SSH-Wakey-\(UUID().uuidString)"
        guard mkdirat(parent, temporary, 0o700) == 0 else { throw failure("create private staging directory") }
        let staging = openat(parent, temporary, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard staging >= 0 else {
            unlinkat(parent, temporary, AT_REMOVEDIR)
            throw failure("open private staging directory")
        }
        defer { close(staging); unlinkat(parent, temporary, AT_REMOVEDIR) }
        try setPrivatePermissions(staging, mode: 0o700)
        try validateDirectory(staging, privateLeaf: true)
        let descriptor = openat(staging, "data", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw failure("create private temporary file") }
        defer { close(descriptor); unlinkat(staging, "data", 0) }
        try setPrivatePermissions(descriptor, mode: mode)
        _ = try validateFile(descriptor)
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw failure("write private file") }
                offset += count
            }
        }
        guard fsync(descriptor) == 0 else { throw failure("flush private file") }
        guard renameat(staging, "data", parent, name) == 0 else { throw failure("replace private file") }
        guard fsync(parent) == 0 else { throw failure("flush containing directory") }
    }

    private static func failure(_ action: String, _ detail: String? = nil) -> WriteError {
        .failed(action, detail ?? String(cString: strerror(errno)))
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
        /// The bytes are present but are not a valid connections document —
        /// truncated, edited into nonsense, or replaced with something else.
        case damagedOrAltered(String)
        case encrypted

        /// True when the file on disk failed a structural or cryptographic
        /// check, rather than merely being absent or still locked.
        var suggestsIntegrityProblem: Bool {
            switch self {
            case .damagedOrAltered: return true
            case .unsupportedVersion, .unreadable, .encrypted: return false
            }
        }

        var errorDescription: String? {
            switch self {
            case .unsupportedVersion(let version):
                return "The saved connections file uses format version \(version), which this copy of SSH-Wakey is too old to read. Update the app rather than replacing the file."
            case .unreadable(let reason):
                return "The saved connections file could not be read: \(reason)"
            case .damagedOrAltered(let reason):
                return "The saved connections file looks damaged or altered — it is not valid "
                    + "SSH-Wakey data (\(reason)). Do not trust this copy; restore from an export "
                    + "if you have one."
            case .encrypted:
                return "The saved connections file is encrypted and has not been unlocked."
            }
        }
    }

    /// `~/Library/Application Support/SSH-Wakey`
    static var defaultDirectory: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support", isDirectory: true)
        return base.appendingPathComponent(AppDistribution.supportFolderName, isDirectory: true)
    }

    let directoryURL: URL

    var fileURL: URL { directoryURL.appendingPathComponent("connections.json", isDirectory: false) }

    init(directoryURL: URL = ConnectionFileStore.defaultDirectory) {
        self.directoryURL = directoryURL
    }

    /// Reads whichever form the file is in. Empty when it does not exist yet,
    /// which is the normal first-launch case. A file that exists but holds no
    /// bytes is not first launch — this app never writes an empty file — and is
    /// refused so it cannot be overwritten by a new list.
    struct Snapshot {
        let contents: Contents
        let revision: ProtectedFile.Revision
    }

    func read() throws -> Contents { try readSnapshot().contents }

    func readSnapshot() throws -> Snapshot {
        let data: Data?
        do {
            data = try ProtectedFile.read(from: fileURL)
        } catch {
            throw StoreError.unreadable(error.localizedDescription)
        }
        guard let data else { return Snapshot(contents: .empty, revision: .missing) }
        guard !data.isEmpty else {
            throw StoreError.damagedOrAltered("the file is empty")
        }

        let document: Document
        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            document = try decoder.decode(Document.self, from: data)
        } catch {
            throw StoreError.damagedOrAltered(error.localizedDescription)
        }
        guard document.version <= Document.currentVersion else {
            throw StoreError.unsupportedVersion(document.version)
        }
        guard document.version == Document.currentVersion else {
            throw StoreError.damagedOrAltered("invalid format version")
        }
        // Each document has exactly one representation.
        guard (document.vault != nil) != (document.connections != nil) else {
            throw StoreError.damagedOrAltered("it must contain exactly one connection list or vault")
        }
        let contents: Contents
        if let vault = document.vault { contents = .encrypted(vault) }
        else { contents = .plain(document.connections ?? []) }
        return Snapshot(contents: contents, revision: ProtectedFile.revision(of: data))
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
    @discardableResult
    func save(_ connections: [SSHConnection], expectedRevision: ProtectedFile.Revision? = nil) throws -> ProtectedFile.Revision {
        try write(Document(connections: connections), expectedRevision: expectedRevision)
    }

    @discardableResult
    func save(_ vault: ConnectionVault, expectedRevision: ProtectedFile.Revision? = nil) throws -> ProtectedFile.Revision {
        try write(Document(vault: vault), expectedRevision: expectedRevision)
    }

    /// Keeps vault/keychain transitions inside the same directory lock as the
    /// compare-and-replace. A concurrent disable must not delete a key after a
    /// new vault has already adopted it.
    func commit(
        expectedRevision: ProtectedFile.Revision,
        afterWrite: (() -> Void)? = nil,
        _ document: () throws -> Document
    ) throws -> ProtectedFile.Revision {
        try createDirectoryIfNeeded()
        var result = ProtectedFile.Revision.missing
        try ProtectedFile.update(at: fileURL, afterWrite: afterWrite) { current in
            guard ProtectedFile.revision(of: current) == expectedRevision else {
                throw StoreError.unreadable("the file changed after it was opened; reopen it before saving")
            }
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(document())
            result = ProtectedFile.revision(of: data)
            return data
        }
        return result
    }

    private func write(_ document: Document, expectedRevision: ProtectedFile.Revision?) throws -> ProtectedFile.Revision {
        try createDirectoryIfNeeded()

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        // ISO-8601 so the dates in the file are readable if you open it.
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(document)

        try ProtectedFile.write(data, to: fileURL, expectedRevision: expectedRevision)
        return ProtectedFile.revision(of: data)
    }

    func createDirectoryIfNeeded() throws {
        try ProtectedFile.createPrivateDirectory(at: directoryURL)
    }
}
