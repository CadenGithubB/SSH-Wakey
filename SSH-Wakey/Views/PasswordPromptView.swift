import AppKit
import Carbon.HIToolbox
import SwiftUI

/// Asks for the password for one connection attempt.
///
/// The destination and the mode sit together because they are the two facts
/// this sheet exists to confirm: where the password is going, and what will
/// happen after it is accepted. The destination cannot be edited here; the
/// mode can, so a wrong picker in the window does not mean cancelling and
/// typing the password again.
///
/// The text lives in this view's state only until Wake or Connect is pressed.
/// It is handed straight to a `SecureBuffer` and the binding is cleared in the
/// same turn, so the `String` is unreferenced as early as Swift allows.
struct PasswordPromptView: View {

    let connection: SSHConnection
    var onConnect: (String, ConnectMode) -> Void
    var onCancel: () -> Void

    @State private var mode: ConnectMode
    @State private var password = ""
    @State private var secureInput = SecureInputSession()
    @FocusState private var focused: Bool

    init(
        connection: SSHConnection,
        onConnect: @escaping (String, ConnectMode) -> Void,
        onCancel: @escaping () -> Void
    ) {
        self.connection = connection
        self.onConnect = onConnect
        self.onCancel = onCancel
        _mode = State(initialValue: connection.connectMode)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 10) {
                    Image(systemName: "lock.shield")
                        .font(.system(size: 22))
                        .foregroundStyle(.tint)
                    Text("Password for \(connection.name)")
                        .font(.headline)
                }

                confirmation

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

                Button(mode.buttonTitle, action: submit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(password.isEmpty)
            }
            .padding(16)
        }
        .frame(width: 440)
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

    /// Where it goes, and what happens next, as two facts in one block.
    private var confirmation: some View {
        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 14, verticalSpacing: 8) {
            GridRow {
                Text("To")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                    .gridColumnAlignment(.trailing)
                Text(connection.displayDestination)
                    .font(.system(size: 12, design: .monospaced))
                    .textSelection(.enabled)
                    .gridColumnAlignment(.leading)
            }
            GridRow {
                Text("Then")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                Picker("Then", selection: $mode) {
                    ForEach(ConnectMode.allCases) { option in
                        Text(option.title).tag(option)
                    }
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .fixedSize()
                .help(mode.explanation)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .contain)
    }

    private func submit() {
        guard !password.isEmpty else { return }
        let entered = password
        password = ""
        onConnect(entered, mode)
    }
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
