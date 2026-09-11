import AppKit
import Carbon.HIToolbox
import SwiftUI

/// Asks for the password for one connection attempt.
///
/// The text lives in this view's state only until Connect is pressed. It is
/// handed straight to a `SecureBuffer` and the binding is cleared in the same
/// turn, so the `String` is unreferenced as early as Swift allows.
struct PasswordPromptView: View {

    let connection: SSHConnection
    var onConnect: (String) -> Void
    var onCancel: () -> Void

    @State private var password = ""
    @State private var secureInput = SecureInputSession()
    @FocusState private var focused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 10) {
                    Image(systemName: "lock.shield")
                        .font(.system(size: 22))
                        .foregroundStyle(.tint)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Password for \(connection.name)")
                            .font(.headline)
                        Text(connection.displayDestination)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                }

                SecureField("Password", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .focused($focused)
                    .onSubmit(submit)

                Label(HelpNotes.passwordNote, systemImage: "info.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(20)

            Divider()

            HStack {
                Spacer()
                Button("Cancel") {
                    password = ""
                    onCancel()
                }
                .keyboardShortcut(.cancelAction)

                Button("Connect", action: submit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(password.isEmpty)
            }
            .padding(16)
        }
        .frame(width: 420)
        .background(UncapturableWindow())
        .onAppear {
            focused = true
            secureInput.acquire()
        }
        .onDisappear { secureInput.release() }
        // Secure input is a system-wide setting, so it is given up the moment
        // this app stops being frontmost and taken again when it comes back.
        .onReceive(NotificationCenter.default.publisher(
            for: NSApplication.didBecomeActiveNotification)) { _ in secureInput.acquire() }
        .onReceive(NotificationCenter.default.publisher(
            for: NSApplication.didResignActiveNotification)) { _ in secureInput.release() }
    }

    private func submit() {
        guard !password.isEmpty else { return }
        let entered = password
        password = ""
        onConnect(entered)
    }
}


/// Marks the sheet's window as not capturable, so the password field does not
/// appear in screenshots, screen recordings or a shared screen.
struct UncapturableWindow: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async { view.window?.sharingType = .none }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {}
}

/// Holds secure event input for as long as the password sheet is on screen.
///
/// Secure event input stops other processes reading keystrokes through an event
/// tap, which is the ordinary way a keylogger works. NSSecureTextField does this
/// itself while it is the first responder; asking explicitly covers the whole
/// time the sheet is up, including while focus is elsewhere in it.
///
/// It is released as soon as the sheet closes or the app stops being frontmost,
/// because secure input is system-wide and leaving it on interferes with text
/// input everywhere else.
@MainActor
final class SecureInputSession {
    private var isHolding = false

    /// Exposed so the state can be asserted in tests.
    var isActive: Bool { isHolding }

    func acquire() {
        guard !isHolding, EnableSecureEventInput() == noErr else { return }
        isHolding = true
    }

    func release() {
        guard isHolding else { return }
        DisableSecureEventInput()
        isHolding = false
    }
}
