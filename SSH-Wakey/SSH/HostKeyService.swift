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
    static func trust(_ candidates: [HostKeyCandidate]) throws {
        guard !candidates.isEmpty else { return }
        let url = knownHostsURL
        let directory = url.deletingLastPathComponent()

        do {
            if !FileManager.default.fileExists(atPath: directory.path) {
                try FileManager.default.createDirectory(
                    at: directory, withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o700])
            }

            var existing = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
            if !existing.isEmpty && !existing.hasSuffix("\n") { existing += "\n" }
            existing += candidates.map(\.knownHostsLine).joined(separator: "\n") + "\n"

            try existing.write(to: url, atomically: true, encoding: .utf8)
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch {
            throw HostKeyError.notWritten(error.localizedDescription)
        }
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
