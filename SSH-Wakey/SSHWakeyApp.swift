import AppKit
import SwiftUI

/// The app scene. `main.swift` calls `SSHWakeyApp.main()` after ruling out
/// askpass mode, which is why there is no `@main` attribute here.
struct SSHWakeyApp: App {

    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        Window("SSH-Wakey", id: "main") {
            ContentView()
        }
        .defaultSize(width: Column.minimumWindowWidth + 120, height: 600)
        .commands {
            CommandGroup(replacing: .newItem) {}
        }
    }
}

/// Sessions live inside this process, so quitting closes them. The user is
/// told that rather than finding out when a Terminal window goes dead.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {

    weak var sessions: SSHSessionManager?

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let sessions, sessions.activeSessionCount > 0 else { return .terminateNow }

        let count = sessions.activeSessionCount
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = count == 1
            ? "Quit and close the open session?"
            : "Quit and close \(count) open sessions?"
        alert.informativeText = "SSH-Wakey holds each connection open, so any Terminal window using one "
            + "will be disconnected when the app quits."
        alert.addButton(withTitle: "Quit and Disconnect")
        alert.addButton(withTitle: "Cancel")

        guard alert.runModal() == .alertFirstButtonReturn else { return .terminateCancel }
        sessions.disconnectAll()
        return .terminateNow
    }
}
