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
                return "The username may not contain spaces, @, : or a leading dash."
            case .invalidHost:
                return "The hostname may not contain spaces, @, / or a leading dash."
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
        let rejected = CharacterSet(charactersIn: "@: /\\\t\n\"'")
        guard username.rangeOfCharacter(from: rejected) == nil else { return false }
        return !username.unicodeScalars.contains { $0.properties.generalCategory == .control }
    }

    /// Accepts hostnames, IPv4 literals and bracketed or bare IPv6 literals.
    /// The goal is to exclude anything that could confuse `ssh`, not to prove
    /// the name resolves.
    static func isValidHost(_ host: String) -> Bool {
        guard !host.isEmpty, host.count <= 255, !host.hasPrefix("-") else { return false }
        let rejected = CharacterSet(charactersIn: "@/\\ \t\n\"'")
        guard host.rangeOfCharacter(from: rejected) == nil else { return false }
        return !host.unicodeScalars.contains { $0.properties.generalCategory == .control }
    }
}
