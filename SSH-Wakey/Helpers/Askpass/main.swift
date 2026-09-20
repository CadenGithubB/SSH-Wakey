import Darwin
import Foundation

signal(SIGPIPE, SIG_IGN)
guard AskpassHelper.disableCoreDumps() else { exit(1) }
// XPC failure fails the attempt; this adapter has no password UI or secret bytes.
alarm(UInt32(AskpassProtocol.promptLifetime + 10))
let environment = ProcessInfo.processInfo.environment
if AskpassHelper.isAuthenticationCallback() {
    AskpassHelper.reportAuthentication(environment: environment)
}
#if DEBUG
let sandboxProbe = Array(CommandLine.arguments.dropFirst()) == ["--ssh-wakey-sandbox-check", "--diagnostic-only"]
let requestArguments = sandboxProbe ? [CommandLine.arguments[0], "Password:"] : CommandLine.arguments
#else
let requestArguments = CommandLine.arguments
#endif
guard let request = AskpassHelper.requestFromEnvironment(arguments: requestArguments),
      let (channel, grant) = AskpassHelper.authorize(request),
      let encoded = AskpassProtocol.encode(grant),
      let identifier = Bundle.main.bundleIdentifier,
      let serviceRequirement = HelperIdentity.requirement(at: HelperLayout.service(in: Bundle.main.bundleURL)),
      let ownURL = Bundle.main.executableURL else { exit(1) }
let connection = NSXPCConnection(serviceName: identifier + ".password-input")
connection.setCodeSigningRequirement(serviceRequirement)
connection.remoteObjectInterface = NSXPCInterface(with: PasswordInputProtocol.self)
connection.invalidationHandler = { exit(1) }
connection.interruptionHandler = { exit(1) }
connection.resume()
do {
    let ownCode = try FileHandle(forReadingFrom: ownURL)
    let app = HelperLayout.enclosingBundle(of: Bundle.main.bundleURL)
    let appCode = try FileHandle(forReadingFrom: HelperLayout.executable(in: app, name: HelperLayout.appName))
    let appInfo = try HelperIdentity.readInfoPlist(in: app)
    let proxy = connection.remoteObjectProxyWithErrorHandler { _ in exit(1) } as! PasswordInputProtocol
    proxy.prepare(ownCode) { accepted in
        guard accepted else { exit(1) }
        // A new message lets XPC enforce the requirement installed by prepare.
        #if DEBUG
        if sandboxProbe {
            let fixture = URL(fileURLWithPath: request.socketPath).deletingLastPathComponent()
                .deletingLastPathComponent().appendingPathComponent("sandbox-fixture").path
            proxy.probe(channel, output: .standardOutput, appCode: appCode, appInfo: appInfo, grant: encoded,
                        fixture: fixture) { result in
                fputs(result + "\n", stderr)
                exit(result == "SSHWAKEY_SANDBOX_OK" ? 0 : 1)
            }
            return
        }
        #endif
        proxy.collect(channel, output: .standardOutput, appCode: appCode, appInfo: appInfo, grant: encoded) { sent in
            exit(sent ? 0 : 1)
        }
    }
    RunLoop.main.run()
} catch { exit(1) }
exit(1)
