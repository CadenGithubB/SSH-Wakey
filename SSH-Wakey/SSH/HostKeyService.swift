import Darwin
import Foundation

/// One public key offered by a server, with the fingerprint a person can read
/// out loud and compare.
struct HostKeyCandidate: Identifiable, Equatable, Sendable {
    let id = UUID()
    /// The exact line that would be appended to `known_hosts`.
    let knownHostsLine: String
    let algorithm: String
    let bits: String
    let fingerprint: String
}

/// Fetches and records host keys for the strict checking flow.
///
/// Fetching a fingerprint over the network proves nothing on its own: whatever
/// answers the address supplies it. The point of showing it is that the user
/// can compare it with the value printed on the machine itself. The UI says so.
enum HostKeyService {

    enum HostKeyError: LocalizedError {
        case scanFailed(String)
        case noKeysOffered(String)
        case notWritten(String)

        var errorDescription: String? {
            switch self {
            case .scanFailed(let reason):
                return "The host key could not be fetched: \(reason)"
            case .noKeysOffered(let host):
                var text = "\(host) did not answer with a host key. It may not be running an SSH "
                    + "server yet, or it may not be reachable from here."
                if NetworkScope.isLocal(host) {
                    text += " The first approach to a machine on your own network is also the one "
                        + "macOS interrupts with its permission prompt, and that attempt fails "
                        + "while the prompt is on screen. If you have just answered it, try again."
                }
                return text
            case .notWritten(let reason):
                return "known_hosts could not be updated: \(reason)"
            }
        }
    }

    static var knownHostsURL: URL {
        URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
            .appendingPathComponent(".ssh/known_hosts")
    }

    /// How many times to ask before giving up.
    static let scanAttempts = 3

    /// Asks the machine for its host keys, retrying a couple of times.
    ///
    /// One attempt is not enough in practice. A first approach to a machine
    /// fails for several reasons that clear by themselves: the address has not
    /// been resolved yet, a route is cold, or macOS is holding up the
    /// connection behind its local network permission prompt. All of those
    /// succeed on a second try a moment later.
    static func scan(host: String, port: Int) async throws -> [HostKeyCandidate] {
        var lastError: Error = HostKeyError.noKeysOffered(host)

        for attempt in 1...scanAttempts {
            do {
                return try await scanOnce(host: host, port: port)
            } catch {
                lastError = error
                guard attempt < scanAttempts else { break }
                try? await Task.sleep(nanoseconds: UInt64(attempt) * 700_000_000)
            }
        }
        throw lastError
    }

    private static func scanOnce(host: String, port: Int) async throws -> [HostKeyCandidate] {
        let scan: ProcessResult
        do {
            scan = try await ProcessRunner.run(
                executable: "/usr/bin/ssh-keyscan",
                arguments: ["-T", "8", "-p", String(port), host],
                timeout: 15)
        } catch {
            throw HostKeyError.scanFailed(error.localizedDescription)
        }

        let lines = scan.standardOutput
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }

        guard !lines.isEmpty else {
            let reason = scan.standardError.trimmingCharacters(in: .whitespacesAndNewlines)
            throw reason.isEmpty ? HostKeyError.noKeysOffered(host) : HostKeyError.scanFailed(reason)
        }

        let fingerprints = try await fingerprints(for: lines)
        return zip(lines, fingerprints).map { line, detail in
            HostKeyCandidate(
                knownHostsLine: line,
                algorithm: detail.algorithm,
                bits: detail.bits,
                fingerprint: detail.fingerprint)
        }
    }

    /// Appends approved keys to `~/.ssh/known_hosts`, creating it if needed.
    ///
    /// Appended, not rewritten. Reading the file, adding a line and writing the
    /// whole thing back would discard anything ssh recorded in between, replace
    /// the file with a new inode, drop extended attributes, and turn a symlinked
    /// known_hosts into a regular file. An `O_APPEND` write does none of that.
    ///
    /// An existing symlink is followed, but only if the opened target is a
    /// regular file this user owns and that is not group- or world-writable.
    /// A missing file is created in place (`O_EXCL | O_NOFOLLOW`) so a symlink
    /// cannot win the create race.
    static func trust(_ candidates: [HostKeyCandidate], at url: URL = knownHostsURL) throws {
        guard !candidates.isEmpty else { return }

        for candidate in candidates where !isWellFormed(candidate.knownHostsLine) {
            throw HostKeyError.notWritten(
                "ssh-keyscan returned something that is not a host key line, so nothing was added.")
        }

        try prepareParentDirectory(url.deletingLastPathComponent())

        let descriptor = try openKnownHosts(url.path)
        defer { close(descriptor) }

        var info = Darwin.stat()
        guard fstat(descriptor, &info) == 0 else {
            throw HostKeyError.notWritten(String(cString: strerror(errno)))
        }
        try validateKnownHostsFile(info)

        var text = candidates.map(\.knownHostsLine).joined(separator: "\n") + "\n"
        if let last = try lastByte(of: descriptor, size: info.st_size), last != 0x0A {
            text = "\n" + text
        }

        let payload = Array(text.utf8)
        var offset = 0
        while offset < payload.count {
            let written = payload.withUnsafeBytes { bytes in
                Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
            }
            if written > 0 {
                offset += written
                continue
            }
            if written < 0 && errno == EINTR { continue }
            throw HostKeyError.notWritten(String(cString: strerror(errno)))
        }
    }

    /// The folder must be a directory this user owns, and not writable by
    /// group or other. `0755` is fine; `0770` is not.
    private static func prepareParentDirectory(_ directory: URL) throws {
        var info = Darwin.stat()
        if stat(directory.path, &info) != 0 {
            guard errno == ENOENT else {
                throw HostKeyError.notWritten(String(cString: strerror(errno)))
            }
            do {
                try FileManager.default.createDirectory(
                    at: directory, withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o700])
            } catch {
                throw HostKeyError.notWritten(error.localizedDescription)
            }
            guard stat(directory.path, &info) == 0 else {
                throw HostKeyError.notWritten(String(cString: strerror(errno)))
            }
        }
        guard (info.st_mode & S_IFMT) == S_IFDIR else {
            throw HostKeyError.notWritten("its folder is not a directory")
        }
        guard info.st_uid == getuid() else {
            throw HostKeyError.notWritten("its folder is not owned by this user")
        }
        guard (info.st_mode & 0o022) == 0 else {
            throw HostKeyError.notWritten("its folder is writable by others")
        }
    }

    /// Follow an existing path; create only if nothing is there, and only as a
    /// regular file at that name.
    private static func openKnownHosts(_ path: String) throws -> Int32 {
        let existing = openIgnoringInterrupt(
            path, O_RDWR | O_APPEND | O_CLOEXEC | O_NONBLOCK)
        if existing >= 0 { return existing }
        let opened = errno
        guard opened == ENOENT else {
            throw HostKeyError.notWritten(String(cString: strerror(opened)))
        }

        let created = openIgnoringInterrupt(
            path, O_RDWR | O_APPEND | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
            0o600)
        if created >= 0 { return created }
        throw HostKeyError.notWritten(String(cString: strerror(errno)))
    }

    private static func openIgnoringInterrupt(
        _ path: String, _ flags: Int32, _ mode: mode_t = 0
    ) -> Int32 {
        while true {
            let descriptor = open(path, flags, mode)
            if descriptor >= 0 || errno != EINTR { return descriptor }
        }
    }

    private static func validateKnownHostsFile(_ info: Darwin.stat) throws {
        guard (info.st_mode & S_IFMT) == S_IFREG else {
            throw HostKeyError.notWritten("it is not a regular file")
        }
        guard info.st_uid == getuid() else {
            throw HostKeyError.notWritten("it is not owned by this user")
        }
        guard (info.st_mode & 0o022) == 0 else {
            throw HostKeyError.notWritten("it is writable by others")
        }
    }

    /// `nil` when the file is empty, so a new first line needs no separator.
    private static func lastByte(of descriptor: Int32, size: off_t) throws -> UInt8? {
        guard size > 0 else { return nil }
        var last: UInt8 = 0
        while true {
            let read = pread(descriptor, &last, 1, size - 1)
            if read == 1 { return last }
            if read < 0 && errno == EINTR { continue }
            if read == 0 {
                throw HostKeyError.notWritten("the file changed while it was being checked")
            }
            throw HostKeyError.notWritten(String(cString: strerror(errno)))
        }
    }

    /// A host pattern, a key type and base64 key material, on one line.
    ///
    /// The lines come from another machine by way of ssh-keyscan, and they are
    /// about to be appended to the file that decides which servers are trusted.
    /// Nothing that does not look exactly like an entry goes in.
    static func isWellFormed(_ line: String) -> Bool {
        guard !line.isEmpty, line.utf8.count <= 8192 else { return false }
        guard !line.unicodeScalars.contains(where: { $0.properties.generalCategory == .control })
        else { return false }

        // ssh-keyscan writes exactly three fields. Anything else is not what
        // this is for, and the file is too important to be lenient with.
        let fields = line.split(separator: " ").map(String.init)
        guard fields.count == 3 else { return false }

        let keyType = fields[1]
        guard keyType.hasPrefix("ssh-") || keyType.hasPrefix("ecdsa-") || keyType.hasPrefix("sk-")
        else { return false }

        let material = fields[2]
        let base64 = CharacterSet(
            charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        return !material.isEmpty && material.unicodeScalars.allSatisfy(base64.contains)
    }

    struct Detail: Equatable {
        var bits: String
        var fingerprint: String
        var algorithm: String
    }

    /// `ssh-keygen -l` reads every line from stdin and prints one fingerprint
    /// per line, in order.
    private static func fingerprints(for lines: [String]) async throws -> [Detail] {
        let input = Data((lines.joined(separator: "\n") + "\n").utf8)
        let result: ProcessResult
        do {
            result = try await ProcessRunner.run(
                executable: "/usr/bin/ssh-keygen",
                arguments: ["-l", "-f", "-"],
                input: input,
                timeout: 15)
        } catch {
            throw HostKeyError.scanFailed(error.localizedDescription)
        }

        let parsed = result.standardOutput
            .split(separator: "\n")
            .compactMap { parseFingerprintLine(String($0)) }
        guard parsed.count == lines.count else {
            throw HostKeyError.scanFailed(
                result.standardError.isEmpty
                    ? "ssh-keygen did not describe every key." : result.standardError)
        }
        return parsed
    }

    /// Parses `256 SHA256:abc… comment (ED25519)`.
    static func parseFingerprintLine(_ line: String) -> Detail? {
        let fields = line.split(separator: " ").map(String.init)
        guard fields.count >= 3 else { return nil }
        let algorithm = fields.last.map { $0.trimmingCharacters(in: CharacterSet(charactersIn: "()")) } ?? "unknown"
        return Detail(bits: fields[0], fingerprint: fields[1], algorithm: algorithm)
    }
}
