import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// The app scene. `main.swift` calls `SSHWakeyApp.main()` after ruling out
/// askpass mode, which is why there is no `@main` attribute here.
struct SSHWakeyApp: App {

    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    // Owned here rather than in the window, because the Settings scene works on
    // the same store.
    @State private var store: ConnectionStore
    @State private var sessions: SSHSessionManager
    @State private var security: AppSecurityCoordinator

    init() {
        let store = ConnectionStore.forCurrentEnvironment()
        let sessions = SSHSessionManager()
        _store = State(initialValue: store)
        _sessions = State(initialValue: sessions)
        _security = State(initialValue: AppSecurityCoordinator(store: store, sessions: sessions))
    }

    var body: some Scene {
        Window(AppDistribution.windowTitle, id: "main") {
            ContentView(store: store, sessions: sessions, security: security)
                .onAppear { security.start() }
                .onChange(of: store.access) { _, _ in security.refresh() }
                .onChange(of: store.isAppLockEnabled) { _, _ in security.refresh() }
                .onChange(of: store.isAuthenticating) { _, _ in security.refresh() }
        }
        .defaultSize(width: Column.minimumWindowWidth + 120, height: 600)
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandGroup(after: .appSettings) {
                Button("Lock SSH-Wakey", action: security.lockNow)
                    .keyboardShortcut("l", modifiers: [.command, .shift])
                    .disabled(!store.isAppLockEnabled || store.isLocked)
            }
            CommandGroup(replacing: .help) {
                Button("What SSH-Wakey Does") {
                    NotificationCenter.default.post(name: .showWakeyHelp, object: nil)
                }
                Divider()
                Button("Save Diagnostics…", action: saveDiagnostics)
                    .disabled(sessions.diagnostics.isEmpty || !store.allowsDiagnostics
                              || store.access != .open || store.isAuthenticating)
            }
        }

        Settings {
            SecuritySettingsView(store: store, security: security)
        }
    }
}

extension Notification.Name {
    /// Posted by the Help menu, because a menu command cannot reach the
    /// window's own state directly.
    static let showWakeyHelp = Notification.Name("com.CadenGithubB.sshwakey.showHelp")
}

extension SSHWakeyApp {

    /// Writes what happened on recent connection attempts to a file.
    ///
    /// The default Help item opens a help book this app does not have, so the
    /// whole group is replaced rather than added to.
    private func saveDiagnostics() {
        guard store.allowsDiagnostics, security.authorizeCurrentAccess() else { return }
        let panel = NSSavePanel()
        panel.title = "Save Diagnostics"
        panel.nameFieldStringValue = DiagnosticsReport.suggestedFileName()
        panel.allowedContentTypes = [.plainText]
        panel.canCreateDirectories = true
        panel.message = "This file includes destination metadata and curated connection results."

        guard panel.runModal() == .OK, let url = panel.url,
              security.authorizeCurrentAccess() else { return }

        let text = DiagnosticsReport.text(
            entries: sessions.diagnostics,
            connectionCount: store.connections.count,
            isEncrypted: store.isEncrypted)

        do {
            try ProtectedFile.write(Data(text.utf8), to: url)
        } catch {
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "The diagnostics could not be saved."
            alert.informativeText = error.localizedDescription
            alert.runModal()
        }
    }
}

/// Sessions live inside this process, so quitting closes them. The user is
/// told that rather than finding out when a Terminal window goes dead.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {

    weak var sessions: SSHSessionManager?

    func applicationWillFinishLaunching(_ notification: Notification) {
        Self.bringToFront()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        Self.bringToFront()
    }

    func applicationDidBecomeActive(_ notification: Notification) {
        // After a Keychain Allow sheet, SecurityAgent was front; without this
        // the app stays at the back of Command-Tab even though it just launched.
        Self.bringToFront()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        Self.bringToFront()
        return true
    }

    /// Command-Tab is most-recently-used. If we never become the active app,
    /// a just-launched SSH-Wakey sits last behind whatever was already front
    /// (and behind the Keychain prompt, which is another process).
    static func bringToFront() {
        NSApp.activate(ignoringOtherApps: true)
        for window in NSApp.windows where !window.isSheet {
            window.makeKeyAndOrderFront(nil)
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        sessions?.disconnectAll()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let sessions else { return .terminateNow }
        guard sessions.activeSessionCount > 0 else {
            sessions.disconnectAll()
            return .terminateNow
        }

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
