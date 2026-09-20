import Darwin
import Foundation

/// Shared nonsecret askpass argument and authorization handling. The adapter
/// never owns a password field or password bytes.
enum AskpassHelper {
    static let authenticationArguments = ["--ssh-wakey-authenticated", "--post-authentication"]

    static func isAuthenticationCallback(arguments: [String] = CommandLine.arguments) -> Bool {
        Array(arguments.dropFirst()) == authenticationArguments
    }

    static func reportAuthentication(environment: [String: String]) -> Never {
        guard disableCoreDumps(),
              let path = environment[AskpassProtocol.socketEnvironmentKey],
              let nonce = environment[AskpassProtocol.nonceEnvironmentKey], nonce.utf8.count == 64,
              let ssh = ProcessIdentity.read(getppid()), ssh.isAppleSSH,
              let requirement = HelperIdentity.requirement(at: HelperLayout.enclosingBundle(of: Bundle.main.bundleURL)) else { exit(1) }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0, AskpassProtocol.configure(fd),
              (try? AskpassProtocol.withSocketAddress(path: path) { connect(fd, $0, $1) }) == 0,
              let server = ProcessIdentity.peer(on: fd), server.pid == ssh.parent,
              HelperIdentity.peer(on: fd, matches: requirement), ssh.isCurrent,
              let message = AskpassProtocol.encode(AskpassProtocol.Message(nonce: nonce,
                  prompt: "", event: "authenticated")),
              AskpassProtocol.sendLine(message, to: fd),
              AskpassProtocol.readLine(from: fd) == "accepted" else { exit(1) }
        close(fd)
        exit(0)
    }

    static func authenticationCommand(helperPath: String) -> String {
        // OpenSSH expands percent tokens before /bin/sh parses LocalCommand.
        // exec preserves the direct SSH parent relationship for peer validation.
        let path = helperPath.replacingOccurrences(of: "%", with: "%%")
            .replacingOccurrences(of: "'", with: "'\\''")
        return "exec '" + path + "' " + authenticationArguments.joined(separator: " ")
    }

    struct Request {
        let socketPath: String
        let nonce: String
        let prompt: String
    }

    static func requestFromEnvironment(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        arguments: [String] = CommandLine.arguments
    ) -> Request? {
        guard let path = environment[AskpassProtocol.socketEnvironmentKey],
              let nonce = environment[AskpassProtocol.nonceEnvironmentKey],
              !path.isEmpty, nonce.utf8.count == 64, arguments.count == 2,
              arguments[1].utf8.count < 2048 else { return nil }
        return Request(socketPath: path, nonce: nonce, prompt: arguments[1])
    }

    /// Verify the main app before opening a password-entry service. This adapter
    /// connects the private socket; the sandbox receives only its open descriptor.
    static func authorize(_ request: Request) -> (FileHandle, AskpassProtocol.Grant)? {
        guard let parent = ProcessIdentity.read(getppid()), parent.isAppleSSH,
              let requirement = HelperIdentity.requirement(at: HelperLayout.enclosingBundle(of: Bundle.main.bundleURL))
        else { return nil }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        let channel = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        guard AskpassProtocol.configure(fd),
              (try? AskpassProtocol.withSocketAddress(path: request.socketPath) { connect(fd, $0, $1) }) == 0,
              let server = ProcessIdentity.peer(on: fd), server.pid == parent.parent,
              HelperIdentity.peer(on: fd, matches: requirement), parent.isCurrent,
              let message = AskpassProtocol.encode(AskpassProtocol.Message(nonce: request.nonce,
                  prompt: AskpassProtocol.looksLikePasswordPrompt(request.prompt) ? "Password:" : "Unsupported")),
              AskpassProtocol.sendLine(message, to: fd),
              let line = AskpassProtocol.readLine(from: fd),
              let grant = AskpassProtocol.decode(AskpassProtocol.Grant.self, line), grant.ssh == parent,
              grant.expiresAt > ProcessInfo.processInfo.systemUptime,
              grant.expiresAt <= ProcessInfo.processInfo.systemUptime + AskpassProtocol.promptLifetime + 1,
              grant.context.destination.utf8.count <= 1024 else { return nil }
        return (channel, grant)
    }

    static func disableCoreDumps() -> Bool {
        var limit = rlimit(rlim_cur: 0, rlim_max: 0)
        return setrlimit(RLIMIT_CORE, &limit) == 0
    }
}
