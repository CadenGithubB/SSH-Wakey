import Foundation

/// A connection attempt that did not end in a usable session, translated from
/// ssh's exit status and diagnostics into something worth showing a person.
struct SSHFailure: Equatable, Sendable {

    enum Kind: Equatable, Sendable {
        case invalidConnection
        case authentication
        case passwordNotOffered
        case timeout
        case connectionRefused
        case hostUnreachable
        case nameResolution
        case hostKeyUnknown
        case hostKeyChanged
        case closedByRemote
        case badOption
        case cancelled
        case launchFailed
        case askpassRefused
        case unknown
    }

    var kind: Kind
    /// One line, shown in bold in the status panel.
    var headline: String
    /// What to try next. Shown under the headline.
    var guidance: String?
    /// Raw ssh diagnostics, shown only when the user opens Details. Never
    /// contains the password: it is ssh's own stderr, and the password is
    /// never on the command line ssh was given.
    var detail: String?
    /// Set when the destination is on the local network and the failure looks
    /// like what a missing Local Network permission produces.
    var suggestsLocalNetworkPermission = false

    /// True when the fix is to review and trust the server's host key.
    var offersHostKeyReview: Bool { kind == .hostKeyUnknown }

    /// True when the target may simply not be running an SSH server yet, which
    /// is the case worth explaining carefully for a Mac sitting at the
    /// FileVault unlock screen.
    var offersBootHelp: Bool {
        kind == .connectionRefused || kind == .timeout || kind == .hostUnreachable
    }

    /// Failures that a missing Local Network permission is known to produce.
    static let localNetworkSuspects: Set<Kind> = [
        .hostUnreachable, .timeout, .connectionRefused, .nameResolution,
    ]
}

/// Turns ssh's exit code and stderr into an `SSHFailure`.
///
/// Kept as a pure function so it can be unit tested against real ssh output
/// without opening a socket.
enum SSHOutputClassifier {

    /// True once ssh has said it authenticated.
    ///
    /// Only printed at `LogLevel=VERBOSE`. It is the one signal that survives
    /// the server hanging up immediately afterwards, which is exactly what a
    /// Mac unlocking its FileVault disk does. A partial success is not a
    /// success, so it deliberately does not match.
    static func indicatesAuthenticationSucceeded(_ standardError: String) -> Bool {
        standardError.contains("Authenticated to ")
    }

    static func classify(exitCode: Int32, standardError: String) -> SSHFailure {
        let text = standardError
        let lowered = text.lowercased()
        let detail = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedDetail = detail.isEmpty ? nil : detail

        if text.contains("REMOTE HOST IDENTIFICATION HAS CHANGED") {
            return SSHFailure(
                kind: .hostKeyChanged,
                headline: "The server's host key has changed.",
                guidance: "This can mean the machine was reinstalled, or that something is impersonating it. "
                    + "Confirm the new fingerprint with someone who has physical access, then remove the old line "
                    + "from ~/.ssh/known_hosts yourself. SSH-Wakey will not do that for you.",
                detail: trimmedDetail)
        }

        if lowered.contains("host key verification failed")
            || lowered.contains("no matching host key")
            || (lowered.contains("host key is known") && lowered.contains("strict"))
            || lowered.contains("no ed25519 host key is known")
            || lowered.contains("no rsa host key is known")
            || lowered.contains("no ecdsa host key is known") {
            return SSHFailure(
                kind: .hostKeyUnknown,
                headline: "This host is not in your known_hosts file.",
                guidance: "Review the server's key fingerprint and add it before connecting.",
                detail: trimmedDetail)
        }

        if lowered.contains("permission denied") || lowered.contains("authentication failed")
            || lowered.contains("too many authentication failures") {
            if lowered.contains("(publickey)") && !lowered.contains("password") {
                return SSHFailure(
                    kind: .passwordNotOffered,
                    headline: "The server refused the password.",
                    guidance: "It only accepts key-based login. Enable "
                        + "PasswordAuthentication on the server, or add an SSH key for this account.",
                    detail: trimmedDetail)
            }
            return SSHFailure(
                kind: .authentication,
                headline: "Authentication failed.",
                guidance: "Check the username and password. SSH-Wakey never retries a password on its own, "
                    + "so a repeated attempt has to start from Connect again.",
                detail: trimmedDetail)
        }

        if lowered.contains("connection refused") {
            return SSHFailure(
                kind: .connectionRefused,
                headline: "The machine answered, but nothing is listening on that port.",
                guidance: "Remote Login is probably off, or the machine has not finished starting up.",
                detail: trimmedDetail)
        }

        if lowered.contains("operation timed out") || lowered.contains("connection timed out")
            || lowered.contains("timed out") {
            return SSHFailure(
                kind: .timeout,
                headline: "The connection timed out.",
                guidance: "The machine did not answer in time. It may be off, asleep, on another network, "
                    + "or still starting up.",
                detail: trimmedDetail)
        }

        if lowered.contains("no route to host") || lowered.contains("network is unreachable")
            || lowered.contains("host is down") {
            return SSHFailure(
                kind: .hostUnreachable,
                headline: "That machine could not be reached.",
                guidance: "Check that you are on the same network and that the address is still correct.",
                detail: trimmedDetail)
        }

        if lowered.contains("could not resolve hostname") || lowered.contains("nodename nor servname")
            || lowered.contains("name or service not known") {
            return SSHFailure(
                kind: .nameResolution,
                headline: "That hostname could not be resolved.",
                guidance: "Check the spelling, or use the IP address instead.",
                detail: trimmedDetail)
        }

        if lowered.contains("connection closed by") || lowered.contains("connection reset by peer") {
            return SSHFailure(
                kind: .closedByRemote,
                headline: "The server closed the connection.",
                guidance: "This often means the account is not allowed to log in remotely.",
                detail: trimmedDetail)
        }

        if lowered.contains("bad configuration option") || lowered.contains("unknown option")
            || lowered.contains("command-line: line") {
            return SSHFailure(
                kind: .badOption,
                headline: "ssh rejected one of the extra arguments.",
                guidance: "Edit the connection and correct the extra SSH arguments.",
                detail: trimmedDetail)
        }

        return SSHFailure(
            kind: .unknown,
            headline: "The connection failed. ssh exited with status \(exitCode).",
            guidance: trimmedDetail == nil ? "ssh gave no diagnostics." : "See the details below.",
            detail: trimmedDetail)
    }
}
