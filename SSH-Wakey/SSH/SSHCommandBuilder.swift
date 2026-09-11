import Foundation

/// What Connect should actually do.
enum ConnectMode: String, CaseIterable, Identifiable, Sendable {
    /// Log in to prove the password works, then close straight away.
    case unlock
    /// Log in and hold the connection open for a shell.
    case session

    var id: String { rawValue }

    var title: String {
        switch self {
        case .unlock: return "Connect, Unlock, then disconnect"
        case .session: return "Open a session"
        }
    }

    var explanation: String {
        switch self {
        case .unlock:
            return "Logs in to prove the password works, then closes the connection immediately. "
                + "This is what a Mac waiting at the FileVault screen needs: the login is what "
                + "unlocks its disk, and nothing has to stay open afterwards."
        case .session:
            return "Logs in and holds the connection open, so Open in Terminal can start a shell "
                + "on it without asking for the password again. It stays up until you disconnect "
                + "or quit SSH-Wakey."
        }
    }
}

/// Builds the argument arrays handed to `Process`.
///
/// Every value goes into its own array element. Nothing is interpolated into a
/// command string and no shell is ever involved, so a hostname or option value
/// cannot turn into a second command.
enum SSHCommandBuilder {

    static let sshExecutable = "/usr/bin/ssh"

    /// The long-lived master connection. `-N` means no remote command is
    /// started, so this process exists only to hold the authenticated
    /// connection open; other ssh clients attach to it through the control
    /// socket without authenticating again.
    static func masterArguments(
        for connection: SSHConnection,
        controlPath: String,
        connectTimeout: Int
    ) throws -> [String] {
        let candidate = connection.normalized
        var arguments = [
            "-M",
            "-N",
            "-o", "ControlPath=\(controlPath)",
            "-o", "ControlPersist=no",
            "-o", "StrictHostKeyChecking=\(candidate.strictHostKeyChecking ? "yes" : "accept-new")",
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "BatchMode=no",
            "-o", "ConnectTimeout=\(connectTimeout)",
            // Makes ssh announce that it authenticated, so a machine that hangs
            // up the instant it accepts the password is not mistaken for one
            // that rejected it.
            "-o", "LogLevel=VERBOSE",
            "-p", String(candidate.port),
            "-l", candidate.username,
        ]
        arguments.append(contentsOf: try SSHArgumentParser.parse(candidate.extraArguments))
        arguments.append(candidate.host)
        return arguments
    }

    /// Logging in and nothing else.
    ///
    /// No control socket and no multiplexing, because nothing is going to
    /// attach to this. `LogLevel=VERBOSE` is what makes ssh announce that it
    /// authenticated, which matters here: a Mac unlocking its disk closes the
    /// connection the instant it accepts the password, so the exit code alone
    /// cannot tell success from failure.
    static func unlockArguments(
        for connection: SSHConnection,
        connectTimeout: Int
    ) throws -> [String] {
        let candidate = connection.normalized
        var arguments = [
            "-N",
            "-o", "StrictHostKeyChecking=\(candidate.strictHostKeyChecking ? "yes" : "accept-new")",
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "BatchMode=no",
            "-o", "ConnectTimeout=\(connectTimeout)",
            "-o", "LogLevel=VERBOSE",
            "-p", String(candidate.port),
            "-l", candidate.username,
        ]
        arguments.append(contentsOf: try SSHArgumentParser.parse(candidate.extraArguments))
        arguments.append(candidate.host)
        return arguments
    }

    /// `-O check` / `-O exit` against an existing master.
    static func controlArguments(
        for connection: SSHConnection,
        controlPath: String,
        command: String
    ) -> [String] {
        let candidate = connection.normalized
        return [
            "-o", "ControlPath=\(controlPath)",
            "-O", command,
            "-p", String(candidate.port),
            "-l", candidate.username,
            candidate.host,
        ]
    }

    /// The interactive session a terminal runs. It reuses the master, so it
    /// never asks for a password and never sees one.
    static func attachArguments(
        for connection: SSHConnection,
        controlPath: String
    ) -> [String] {
        let candidate = connection.normalized
        return [
            "-o", "ControlPath=\(controlPath)",
            "-o", "ControlMaster=no",
            "-p", String(candidate.port),
            "-l", candidate.username,
            candidate.host,
        ]
    }
}
