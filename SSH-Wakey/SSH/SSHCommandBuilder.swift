import Foundation

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
