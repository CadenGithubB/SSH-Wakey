import CryptoKit
import Foundation

struct HostKeyCandidate: Identifiable, Equatable, Sendable {
    let id = UUID()
    let knownHostsLine: String
    let algorithm: String
    let bits: String
    let fingerprint: String
}

/// Trust belongs to this app. A network scan supplies an untrusted Ed25519
/// public key; the user must compare its fingerprint independently before enrollment.
enum HostKeyService {
    enum HostKeyError: LocalizedError {
        case scanFailed(String)
        case noKeysOffered(String)
        case notWritten(String)

        var errorDescription: String? {
            switch self {
            case .scanFailed(let reason): return "The host key could not be fetched: \(reason)"
            case .noKeysOffered(let host):
                var text = "\(host) did not answer with an Ed25519 host key. It may not be running an SSH server yet, or it may not be reachable from here."
                if NetworkScope.isLocal(host) {
                    text += " macOS may interrupt the first local connection with its permission prompt. If you have just answered it, try again."
                }
                return text
            case .notWritten(let reason): return "SSH-Wakey’s host-key file could not be used: \(reason)"
            }
        }
    }

    static var knownHostsURL: URL {
        URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
            .appendingPathComponent("Library/Application Support", isDirectory: true)
            .appendingPathComponent(AppDistribution.supportFolderName, isDirectory: true)
            .appendingPathComponent("known_hosts")
    }

    static let scanAttempts = 3
    static let maximumStoreBytes = 1024 * 1024

    static func scan(host: String, port: Int) async throws -> [HostKeyCandidate] {
        guard ConnectionValidator.isValidHost(host), ConnectionValidator.portRange.contains(port) else {
            throw HostKeyError.scanFailed("The destination is not valid.")
        }
        var lastError: Error = HostKeyError.noKeysOffered(host)
        for attempt in 1...scanAttempts {
            try Task.checkCancellation()
            do { return try await scanOnce(host: host, port: port) }
            catch {
                lastError = error
                guard attempt < scanAttempts else { break }
                try await Task.sleep(nanoseconds: UInt64(attempt) * 700_000_000)
            }
        }
        throw lastError
    }

    private static func scanOnce(host: String, port: Int) async throws -> [HostKeyCandidate] {
        let canonical = ConnectionValidator.canonicalHost(host)
        let result = try await ProcessRunner.run(
            executable: "/usr/bin/ssh-keyscan",
            arguments: ["-T", "8", "-t", "ed25519", "-p", String(port), canonical],
            timeout: 15)
        guard !result.timedOut, !result.outputLimitExceeded, result.exitCode == 0 else {
            throw HostKeyError.noKeysOffered(host)
        }
        let lines = result.standardOutput.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
        let expectedHost = port == 22 ? canonical : "[\(canonical)]:\(port)"
        // A single algorithm and destination must yield exactly one key. Never
        // approve additional keys merely because one displayed fingerprint matched.
        guard lines.count == 1, let candidate = candidate(for: lines[0]),
              lines[0].split(separator: " ").first.map(String.init) == expectedHost else {
            throw HostKeyError.scanFailed("The scan did not return exactly one Ed25519 key for this destination.")
        }
        return [candidate]
    }

    /// Called before every authentication attempt. ssh receives this checked,
    /// immutable snapshot, so it neither follows the live trust-store path nor
    /// writes trust automatically. Absence gives an empty strict-checking store.
    static func prepareTrustSnapshot(in directory: URL, from source: URL = knownHostsURL) throws -> URL {
        do {
            try ProtectedFile.createPrivateDirectory(at: source.deletingLastPathComponent())
            let data = try ProtectedFile.read(from: source, maximumBytes: maximumStoreBytes) ?? Data()
            _ = try entries(in: data)
            try ProtectedFile.createPrivateDirectory(at: directory)
            let snapshot = directory.appendingPathComponent("known_hosts.snapshot")
            try ProtectedFile.write(data, to: snapshot, mode: 0o400)
            return snapshot
        } catch {
            throw HostKeyError.notWritten(error.localizedDescription)
        }
    }

    /// Enroll only one independently verified key. Changed keys require an
    /// explicit repair of the trust store; appending another trusted alternative
    /// would silently defeat changed-host detection.
    static func trust(_ candidates: [HostKeyCandidate], at url: URL = knownHostsURL) throws {
        guard candidates.count == 1, let supplied = candidates.first,
              let checked = candidate(for: supplied.knownHostsLine),
              checked.fingerprint == supplied.fingerprint,
              supplied.algorithm == "ED25519", supplied.bits == "256" else {
            throw HostKeyError.notWritten("Exactly one verified Ed25519 host key is required.")
        }
        do {
            try ProtectedFile.createPrivateDirectory(at: url.deletingLastPathComponent())
            try ProtectedFile.update(at: url, maximumBytes: maximumStoreBytes) { previous in
                var existing = try entries(in: previous ?? Data())
                let host = checked.knownHostsLine.split(separator: " ")[0]
                if let old = existing.first(where: { $0.knownHostsLine.split(separator: " ")[0] == host }) {
                    guard old.knownHostsLine == checked.knownHostsLine else {
                        throw HostKeyError.notWritten("The saved key for this destination is different. Verify the change independently before repairing the trust store.")
                    }
                    return previous ?? Data()
                }
                existing.append(checked)
                let data = Data((existing.map(\.knownHostsLine).joined(separator: "\n") + "\n").utf8)
                guard data.count <= maximumStoreBytes else {
                    throw HostKeyError.notWritten("The host-key file is too large.")
                }
                return data
            }
        } catch let error as HostKeyError { throw error }
        catch { throw HostKeyError.notWritten(error.localizedDescription) }
    }

    private static func entries(in data: Data) throws -> [HostKeyCandidate] {
        guard let text = String(data: data, encoding: .utf8) else {
            throw HostKeyError.notWritten("The host-key file is not valid UTF-8.")
        }
        var result: [HostKeyCandidate] = []
        var hosts = Set<String>()
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            guard let key = candidate(for: String(line)),
                  let host = line.split(separator: " ").first,
                  hosts.insert(String(host)).inserted else {
                throw HostKeyError.notWritten("The host-key file contains an invalid or duplicate destination.")
            }
            result.append(key)
        }
        return result
    }

    static func isWellFormed(_ line: String) -> Bool { candidate(for: line) != nil }

    /// Validate the SSH wire-format Ed25519 blob and compute the exact public
    /// key's SHA-256 fingerprint in process. No secondary command or output zip.
    static func candidate(for line: String) -> HostKeyCandidate? {
        guard !line.isEmpty, line.utf8.count <= 8192,
              !line.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) else { return nil }
        let fields = line.split(separator: " ", omittingEmptySubsequences: false)
        guard fields.count == 3, fields[1] == "ssh-ed25519", validHostField(String(fields[0])),
              let blob = Data(base64Encoded: String(fields[2])), blob.count == 51 else { return nil }
        let prefix: [UInt8] = [0, 0, 0, 11] + Array("ssh-ed25519".utf8) + [0, 0, 0, 32]
        guard blob.prefix(prefix.count).elementsEqual(prefix), blob.base64EncodedString() == fields[2] else { return nil }
        let fingerprint = Data(SHA256.hash(data: blob)).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
        return HostKeyCandidate(knownHostsLine: line, algorithm: "ED25519", bits: "256",
                                fingerprint: "SHA256:\(fingerprint)")
    }

    private static func validHostField(_ field: String) -> Bool {
        if field.hasPrefix("["), let end = field.range(of: "]:") {
            let host = String(field[field.index(after: field.startIndex)..<end.lowerBound])
            let portText = String(field[end.upperBound...])
            guard let port = Int(portText), String(port) == portText,
                  ConnectionValidator.portRange.contains(port) else { return false }
            return ConnectionValidator.isValidHost(host)
                && ConnectionValidator.canonicalHost(host) == host
        }
        return ConnectionValidator.isValidHost(field)
            && ConnectionValidator.canonicalHost(field) == field
    }
}
