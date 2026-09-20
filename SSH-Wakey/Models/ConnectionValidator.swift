import Darwin
import Foundation

/// Field-level checks for a saved connection.
///
/// Validation runs before a connection can be saved and again before it is
/// used, so a file edited by hand cannot push a strange value into an argument
/// list.
enum ConnectionValidator {

    enum Issue: Equatable, Identifiable {
        case emptyName
        case emptyUsername
        case emptyHost
        case invalidUsername
        case invalidHost
        case portOutOfRange(Int)
        case badArguments(String)

        var id: String { message }

        var field: Field {
            switch self {
            case .emptyName: return .name
            case .emptyUsername, .invalidUsername: return .username
            case .emptyHost, .invalidHost: return .host
            case .portOutOfRange: return .port
            case .badArguments: return .arguments
            }
        }

        var message: String {
            switch self {
            case .emptyName:
                return "Give the connection a display name."
            case .emptyUsername:
                return "Enter the username to log in as."
            case .emptyHost:
                return "Enter a hostname or IP address."
            case .invalidUsername:
                return "Use a username containing letters, numbers, dots, underscores or hyphens, with no leading hyphen."
            case .invalidHost:
                return "Enter one DNS hostname, IPv4 address or IPv6 address. Host patterns, aliases and command characters are not allowed."
            case .portOutOfRange(let port):
                return "Port \(port) is out of range. Use a number from 1 to 65535."
            case .badArguments(let reason):
                return reason
            }
        }
    }

    enum Field { case name, username, host, port, arguments }

    static let portRange = 1...65535

    /// Every problem with the connection, in field order. Empty means valid.
    static func issues(in connection: SSHConnection) -> [Issue] {
        let candidate = connection.normalized
        var issues: [Issue] = []

        if candidate.name.isEmpty { issues.append(.emptyName) }

        if candidate.username.isEmpty {
            issues.append(.emptyUsername)
        } else if !isValidUsername(candidate.username) {
            issues.append(.invalidUsername)
        }

        if candidate.host.isEmpty {
            issues.append(.emptyHost)
        } else if !isValidHost(candidate.host) {
            issues.append(.invalidHost)
        }

        if !portRange.contains(candidate.port) {
            issues.append(.portOutOfRange(candidate.port))
        }

        if !candidate.extraArguments.isEmpty {
            do {
                _ = try SSHArgumentParser.parse(candidate.extraArguments)
            } catch let error as SSHArgumentParser.ParseError {
                issues.append(.badArguments(error.errorDescription ?? "The extra arguments are not valid."))
            } catch {
                issues.append(.badArguments(error.localizedDescription))
            }
        }

        return issues
    }

    static func isValid(_ connection: SSHConnection) -> Bool {
        issues(in: connection).isEmpty
    }

    /// A leading dash would be read by `ssh` as an option rather than a value,
    /// so it is refused even though the value is passed as a separate argument.
    static func isValidUsername(_ username: String) -> Bool {
        guard !username.isEmpty, username.count <= 256, !username.hasPrefix("-") else { return false }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        return username.unicodeScalars.allSatisfy(allowed.contains)
    }

    /// Accepts hostnames, IPv4 literals and bracketed or bare IPv6 literals.
    /// The goal is to exclude anything that could confuse `ssh`, not to prove
    /// the name resolves.
    static func isValidHost(_ host: String) -> Bool {
        guard !host.isEmpty, host.count <= 255, !host.hasPrefix("-") else { return false }
        if host.contains(":") {
            var address = host
            if address.hasPrefix("[") && address.hasSuffix("]") {
                address = String(address.dropFirst().dropLast())
            }
            let pieces = address.split(separator: "%", omittingEmptySubsequences: false)
            guard (1...2).contains(pieces.count) else { return false }
            if pieces.count == 2 {
                let zone = pieces[1]
                let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
                guard !zone.isEmpty, zone.count <= 32, !zone.hasPrefix("-"),
                      zone.unicodeScalars.allSatisfy(allowed.contains) else { return false }
            }
            var parsed = in6_addr()
            return String(pieces[0]).withCString { inet_pton(AF_INET6, $0, &parsed) } == 1
        }
        let name = host.hasSuffix(".") ? String(host.dropLast()) : host
        let letters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        let interior = letters.union(CharacterSet(charactersIn: "-"))
        return name.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            guard (1...63).contains(label.utf8.count),
                  let first = label.unicodeScalars.first, let last = label.unicodeScalars.last,
                  letters.contains(first), letters.contains(last) else { return false }
            return label.unicodeScalars.allSatisfy(interior.contains)
        }
    }

    static func canonicalHost(_ host: String) -> String {
        let value = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.hasPrefix("[") && value.hasSuffix("]") {
            return String(value.dropFirst().dropLast()).lowercased()
        }
        return value.lowercased()
    }
}
