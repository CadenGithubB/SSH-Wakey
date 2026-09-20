import Darwin
import Foundation

signal(SIGPIPE, SIG_IGN)
guard AskpassHelper.disableCoreDumps(), PasswordInputService.hasExpectedSandbox else { exit(1) }
// XPC services usually persist. This one is bounded to a single attempt.
alarm(UInt32(AskpassProtocol.promptLifetime + 10))
let delegate = PasswordInputListener()
let listener = NSXPCListener.service()
listener.delegate = delegate
listener.resume()
