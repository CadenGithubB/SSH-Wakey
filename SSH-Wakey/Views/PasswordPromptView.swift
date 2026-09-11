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
        .onAppear { focused = true }
    }

    private func submit() {
        guard !password.isEmpty else { return }
        let entered = password
        password = ""
        onConnect(entered)
    }
}
