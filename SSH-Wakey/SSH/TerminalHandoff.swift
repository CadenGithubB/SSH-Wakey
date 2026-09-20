import Foundation

/// Opens Terminal on a session that is already authenticated.
///
/// The new `ssh` client attaches to the running master through its control
/// socket, so it performs no authentication of its own: no password is typed,
/// passed or stored anywhere in this path. No keystrokes are simulated and no
/// application is scripted; Terminal is simply asked to open a file.
///
/// That file is a short shell script. It holds no secret, every value is quoted,
/// and it removes itself the moment it starts.
enum TerminalHandoff {

    enum HandoffError: LocalizedError {
        case scriptNotWritten(String)
        case terminalNotLaunched(String)

        var errorDescription: String? {
            switch self {
            case .scriptNotWritten(let reason):
                return "The session script could not be written: \(reason)"
            case .terminalNotLaunched(let reason):
                return "Terminal could not be opened: \(reason)"
            }
        }
    }

    static func open(connection: SSHConnection, controlPath: String, in directory: URL) throws {
        let scriptURL = directory.appendingPathComponent(fileName(for: connection), isDirectory: false)
        let contents = scriptContents(for: connection, controlPath: controlPath)

        do {
            try ProtectedFile.write(Data(contents.utf8), to: scriptURL, mode: 0o700)
        } catch {
            throw HandoffError.scriptNotWritten(error.localizedDescription)
        }

        let opener = Process()
        opener.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        opener.arguments = ["-a", "/System/Applications/Utilities/Terminal.app", scriptURL.path]
        opener.environment = ProcessRunner.minimalEnvironment()
        opener.standardInput = FileHandle.nullDevice
        opener.standardOutput = FileHandle.nullDevice
        opener.standardError = FileHandle.nullDevice
        do {
            try opener.run()
        } catch {
            throw HandoffError.terminalNotLaunched(error.localizedDescription)
        }
    }

    /// Exposed for tests: the script must contain no password, must quote every
    /// value, and must delete itself.
    static func scriptContents(for connection: SSHConnection, controlPath: String) -> String {
        let arguments = SSHCommandBuilder.attachArguments(for: connection, controlPath: controlPath)
        let quoted = ([SSHCommandBuilder.sshExecutable] + arguments).map(shellQuote).joined(separator: " ")
        return """
        #!/bin/sh
        # Written by SSH-Wakey for a session that is already authenticated.
        # It contains no password, and it deletes itself before connecting.
        /bin/rm -f "$0"
        exec \(quoted)
        """
    }

    /// POSIX single-quoting. Everything inside single quotes is literal, and an
    /// embedded quote is closed, escaped and reopened.
    static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func fileName(for connection: SSHConnection) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: " -_."))
        let cleaned = String(connection.name.unicodeScalars.filter { allowed.contains($0) })
            .trimmingCharacters(in: .whitespaces)
        return (cleaned.isEmpty ? "SSH session" : cleaned) + ".command"
    }
}
