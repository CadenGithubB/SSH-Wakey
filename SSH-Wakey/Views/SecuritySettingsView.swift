import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// The Settings window. Everything here is about how the saved connections file
/// is stored.
struct SecuritySettingsView: View {

    let store: ConnectionStore

    @State private var sheet: PassphraseSheet.Purpose?
    @State private var confirmsTurningOff = false
    @State private var problem: String?
    @State private var note: String?

    var body: some View {
        Form {
            Section {
                LabeledContent("Saved connections") {
                    Label(
                        store.isEncrypted ? "Encrypted on disk" : "Stored in plain text",
                        systemImage: store.isEncrypted ? "lock.fill" : "doc.plaintext")
                        .foregroundStyle(store.isEncrypted ? Color.green : Color.secondary)
                }

                Text(store.isEncrypted ? Self.encryptedExplanation : Self.plainExplanation)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Section {
                if store.isEncrypted {
                    Button("Change Recovery Passphrase…") { sheet = .change }
                        .disabled(store.isLocked)
                    Button("Turn Off Encryption…") { confirmsTurningOff = true }
                        .disabled(store.isLocked)
                } else {
                    Button("Turn On Encryption…") { sheet = .create }
                }

                Button("Export a Readable Copy…", action: export)
                    .disabled(store.isLocked)
            } footer: {
                Text("An export is an ordinary, unencrypted file. It is the copy to keep somewhere "
                     + "safe before you need it, and the one to keep out of shared folders.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if let note {
                Section {
                    Label(note, systemImage: "checkmark.circle.fill")
                        .font(.caption)
                        .foregroundStyle(.green)
                }
            }

            if let problem {
                Section {
                    Label(problem, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .formStyle(.grouped)
        .frame(width: 480, height: 420)
        .sheet(item: $sheet) { purpose in
            PassphraseSheet(
                purpose: purpose,
                onSubmit: { passphrase in
                    switch purpose {
                    case .create:
                        try store.enableEncryption(passphrase: passphrase)
                        announce("Your connections are encrypted now.")
                    case .change:
                        try store.changePassphrase(to: passphrase)
                        announce("The recovery passphrase has been changed.")
                    case .unlock:
                        try store.unlock(withPassphrase: passphrase)
                        announce("Unlocked, and a fresh Keychain key has been stored.")
                    }
                    sheet = nil
                },
                onCancel: { sheet = nil })
        }
        .confirmationDialog(
            "Turn off encryption?", isPresented: $confirmsTurningOff, titleVisibility: .visible
        ) {
            Button("Turn Off and Store in Plain Text", role: .destructive) {
                run { try store.disableEncryption() }
                announce("Encryption is off. The file is plain text again.")
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The file will be rewritten in plain text and the Keychain key removed. Only your "
                 + "account can read it, and FileVault still covers it while the Mac is off.")
        }
    }

    private static let plainExplanation = """
    The file holds names, usernames, addresses and ports. No passwords and no keys. Only your \
    account can read it, and FileVault encrypts it whenever this Mac is off or locked.
    """

    private static let encryptedExplanation = """
    There are two ways in. A key in your Keychain opens it silently every time. Your recovery \
    passphrase opens it if that key is ever gone. Losing one does not lose the other.
    """

    private func export() {
        let panel = NSSavePanel()
        panel.title = "Export Connections"
        panel.nameFieldStringValue = "SSH-Wakey connections.json"
        panel.allowedContentTypes = [.json]
        panel.canCreateDirectories = true
        panel.message = "This copy is not encrypted."

        guard panel.runModal() == .OK, let url = panel.url else { return }
        run { try store.export(to: url) }
        if problem == nil { announce("Exported to \(url.lastPathComponent).") }
    }

    private func run(_ work: () throws -> Void) {
        do {
            try work()
            problem = nil
        } catch {
            problem = error.localizedDescription
        }
    }

    private func announce(_ message: String) {
        note = message
        problem = nil
    }
}

extension PassphraseSheet.Purpose: Identifiable {
    var id: String {
        switch self {
        case .create: return "create"
        case .change: return "change"
        case .unlock: return "unlock"
        }
    }
}
