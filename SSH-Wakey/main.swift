import Foundation

// Password entry exists only in the separately sandboxed helper. Never fall
// back to a password popup in the main application's process.
let environment = ProcessInfo.processInfo.environment
if environment[AskpassProtocol.socketEnvironmentKey] != nil
    || environment[AskpassProtocol.nonceEnvironmentKey] != nil { exit(1) }
guard AskpassHelper.disableCoreDumps() else {
    fputs("SSH-Wakey could not disable core dumps.\n", stderr)
    exit(1)
}
SSHWakeyApp.main()
