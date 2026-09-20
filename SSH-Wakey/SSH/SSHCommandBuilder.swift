import Foundation

/// What the primary button should actually do for one saved connection.
///
/// The default is to log in, wake the Mac via SSH, then disconnect. That is
/// what a machine waiting at FileVault needs, and it is what the button does
/// unless this connection was set to hold a session open.
enum ConnectMode: String, CaseIterable, Identifiable, Codable, Hashable, Sendable {
    /// Log in to wake the machine, then close straight away.
    case unlock
    /// Log in and hold the connection open for a shell.
    case session

    var id: String { rawValue }

    var title: String {
        switch self {
        case .unlock: return "Connect, wake, then disconnect"
        case .session: return "Open a session"
        }
    }

    /// The primary button next to the mode menu.
    var buttonTitle: String {
        switch self {
        case .unlock: return "Wake"
        case .session: return "Connect"
        }
    }

    /// A few words for the change history, where the long title is too much.
    var historyName: String {
        switch self {
        case .unlock: return "wake, then disconnect"
        case .session: return "open a session"
        }
    }

    var explanation: String {
        switch self {
        case .unlock:
            return "Connects, wakes the Mac via SSH, then disconnects. "
                + "This is what a Mac waiting at the FileVault screen needs: the login is what "
                + "unlocks its disk, and nothing has to stay open afterwards."
        case .session:
            return "Logs in and holds the connection open, so Open in Terminal can start a shell "
                + "on it without asking for the password again. It stays up until you disconnect "
                + "or quit SSH-Wakey."
        }
    }

    func idleHeadline(destination: String) -> String {
        switch self {
        case .unlock: return "Ready to wake \(destination) via SSH."
        case .session: return "Ready to open a session to \(destination)."
        }
    }

    var idleGuidance: String {
        switch self {
        case .unlock:
            return "Wake asks for the password, uses it once to connect, then disconnects. "
                + "That is what a Mac at the FileVault screen needs."
        case .session:
            return "Connect asks for the password, uses it once, and then keeps the session open."
        }
    }
}

/// Builds the argument arrays handed to `Process`.
///
/// Connection fields are passed as argv, not shell syntax. The only local
/// command is the fixed, quoted signed-helper authentication callback.
enum SSHCommandBuilder {

    static let sshExecutable = "/usr/bin/ssh"

    /// Do not inherit directives from the user's or system SSH config. The
    /// connection fields and the checked extra-argument allow-list are the
    /// complete policy for an SSH-Wakey connection.
    ///
    /// Host trust comes from a checked, private snapshot for each attempt.
    private static let isolatedConfigurationArguments = [
        "-F", "/dev/null",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "HostKeyAlgorithms=ssh-ed25519",
        "-o", "VerifyHostKeyDNS=no",
        "-o", "UpdateHostKeys=no",
        "-o", "NoHostAuthenticationForLocalhost=no",
        "-o", "ForwardAgent=no",
        "-o", "ForwardX11=no",
        "-o", "ForwardX11Trusted=no",
        "-o", "ClearAllForwardings=yes",
        "-o", "AddKeysToAgent=no",
        "-o", "GSSAPIAuthentication=no",
        "-o", "GSSAPIDelegateCredentials=no",
        "-o", "HostbasedAuthentication=no",
        "-o", "PermitLocalCommand=no",
        "-o", "ProxyJump=none",
    ]

    /// `-o` values are parsed by ssh_config even when argv bypasses the shell.
    /// Quote the path for that parser too: Application Support contains a space.
    static func quotedConfigurationPath(_ path: String) -> String {
        "\"" + path.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "%", with: "%%") + "\""
    }

    private static func authenticationArguments(knownHostsPath: String, diagnosticLogPath: String,
                                                authenticatedCallbackCommand: String) -> [String] {
        // OpenSSH uses the first value, so these fixed callback options precede
        // the default prohibition used by control and Terminal invocations.
        ["-o", "PermitLocalCommand=yes", "-o", "LocalCommand=\(authenticatedCallbackCommand)"]
        + isolatedConfigurationArguments + [
            "-o", "UserKnownHostsFile=\(quotedConfigurationPath(knownHostsPath))",
            "-E", diagnosticLogPath,
        ]
    }

    /// The long-lived master connection. `-N` means no remote command is
    /// started, so this process exists only to hold the authenticated
    /// connection open; other ssh clients attach to it through the control
    /// socket without authenticating again.
    static func masterArguments(
        for connection: SSHConnection,
        controlPath: String,
        connectTimeout: Int,
        diagnosticLogPath: String,
        knownHostsPath: String,
        authenticatedCallbackCommand: String
    ) throws -> [String] {
        let candidate = connection.normalized
        var arguments = [
            "-M",
            "-N",
        ]
        arguments.append(contentsOf: authenticationArguments(
            knownHostsPath: knownHostsPath, diagnosticLogPath: diagnosticLogPath,
            authenticatedCallbackCommand: authenticatedCallbackCommand))
        arguments.append(contentsOf: [
            "-o", "ControlPath=\(quotedConfigurationPath(controlPath))",
            "-o", "ControlPersist=no",
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "BatchMode=no",
            "-o", "ConnectTimeout=\(connectTimeout)",
            // Bounded diagnostic input is used for failure categories only.
            "-o", "LogLevel=VERBOSE",
            "-p", String(candidate.port),
            "-l", candidate.username,
        ])
        arguments.append(contentsOf: try SSHArgumentParser.parse(candidate.extraArguments))
        arguments.append(candidate.host)
        return arguments
    }

    /// Logging in and nothing else.
    ///
    /// No control socket and no multiplexing. Authentication is proven by the
    /// verified LocalCommand callback even if the remote closes immediately.
    static func unlockArguments(
        for connection: SSHConnection,
        connectTimeout: Int,
        diagnosticLogPath: String,
        knownHostsPath: String,
        authenticatedCallbackCommand: String
    ) throws -> [String] {
        let candidate = connection.normalized
        var arguments = [
            "-N",
        ]
        arguments.append(contentsOf: authenticationArguments(
            knownHostsPath: knownHostsPath, diagnosticLogPath: diagnosticLogPath,
            authenticatedCallbackCommand: authenticatedCallbackCommand))
        arguments.append(contentsOf: [
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "BatchMode=no",
            "-o", "ConnectTimeout=\(connectTimeout)",
            "-o", "LogLevel=VERBOSE",
            "-p", String(candidate.port),
            "-l", candidate.username,
        ])
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
        return isolatedConfigurationArguments + [
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ControlPath=\(quotedConfigurationPath(controlPath))",
            "-O", command,
            "-p", String(candidate.port),
            "-l", candidate.username,
            candidate.host,
        ]
    }

    /// Closes an abandoned master without needing the original connection
    /// fields. It still uses the same isolated policy as every other ssh
    /// invocation made by the app.
    static func abandonedControlArguments(controlPath: String) -> [String] {
        isolatedConfigurationArguments + [
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ControlPath=\(quotedConfigurationPath(controlPath))",
            "-O", "exit",
            "abandoned-session",
        ]
    }

    /// The interactive session a terminal runs. It reuses the master, so it
    /// never asks for a password and never sees one.
    static func attachArguments(
        for connection: SSHConnection,
        controlPath: String
    ) -> [String] {
        let candidate = connection.normalized
        return isolatedConfigurationArguments + [
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ControlPath=\(quotedConfigurationPath(controlPath))",
            "-o", "ControlMaster=no",
            "-o", "BatchMode=yes",
            // A vanished master must not fall back to a fresh connection.
            "-o", "ProxyCommand=/usr/bin/false",
            "-p", String(candidate.port),
            "-l", candidate.username,
            candidate.host,
        ]
    }
}
