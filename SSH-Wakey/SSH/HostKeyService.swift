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
                return "\(host) did not offer a host key. It may not be running an SSH server."
            case .notWritten(let reason):
                return "known_hosts could not be updated: \(reason)"
            }
        }
    }

    static var knownHostsURL: URL {
        URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
            .appendingPathComponent(".ssh/known_hosts")
    }

    static func scan(host: String, port: Int) async throws -> [HostKeyCandidate] {
        let scan: ProcessResult
        do {
            scan = try await ProcessRunner.run(
                executable: "/usr/bin/ssh-keyscan",
                arguments: ["-T", "5", "-p", String(port), host],
                timeout: 20)
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
    static func trust(_ candidates: [HostKeyCandidate], at url: URL = knownHostsURL) throws {
        guard !candidates.isEmpty else { return }

        for candidate in candidates where !isWellFormed(candidate.knownHostsLine) {
            throw HostKeyError.notWritten(
                "ssh-keyscan returned something that is not a host key line, so nothing was added.")
        }

        let directory = url.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: directory.path) {
            do {
                try FileManager.default.createDirectory(
                    at: directory, withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o700])
            } catch {
                throw HostKeyError.notWritten(error.localizedDescription)
            }
        }

        var text = candidates.map(\.knownHostsLine).joined(separator: "\n") + "\n"
        if endsWithoutNewline(url) { text = "\n" + text }

        let descriptor = open(url.path, O_WRONLY | O_APPEND | O_CREAT, 0o600)
        guard descriptor >= 0 else {
            throw HostKeyError.notWritten(String(cString: strerror(errno)))
        }
        defer { close(descriptor) }

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

    /// True when a new entry would otherwise be joined onto the last line.
    private static func endsWithoutNewline(_ url: URL) -> Bool {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? handle.close() }
        guard let size = try? handle.seekToEnd(), size > 0 else { return false }
        try? handle.seek(toOffset: size - 1)
        return (try? handle.read(upToCount: 1)) != Data([0x0A])
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
