import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// The Settings window. Everything here is about how the saved connections file
/// is stored.
struct SecuritySettingsView: View {

    let store: ConnectionStore

    @State private var sheet: PassphraseSheet.Purpose?
    @State private var problem: String?
    @State private var note: String?

    var body: some View {
        Form {
            if store.isManagedBuild {
                Section {
                    Label {
                        Text(store.organizationName.map { "This copy is managed by \($0)." }
                             ?? "This copy is managed by your organization.")
                            .fixedSize(horizontal: false, vertical: true)
                    } icon: {
                        Image(systemName: "building.2.fill")
                    }
                    Text("Machines are assigned by IT. You cannot add, edit or export them, and "
                         + "this copy only wakes a Mac — it will not open a session.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
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
                    Button("Turn Off Encryption…") { sheet = .disable }
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
                onSubmit: { entry in
                    switch purpose {
                    case .create:
                        try store.enableEncryption(passphrase: entry.new)
                        announce("Encrypted. Export a copy now, while the passphrase is in front "
                                 + "of you.")
                    case .change:
                        try store.changePassphrase(from: entry.current ?? "", to: entry.new)
                        announce("The recovery passphrase has been changed.")
                    case .unlock:
                        try store.unlock(withPassphrase: entry.new)
                        announce("Unlocked, and a fresh Keychain key has been stored.")
                    case .disable:
                        try store.disableEncryption(passphrase: entry.new)
                        announce("Encryption is off. The file is plain text again.")
                    case .export(let url):
                        try store.export(to: url, passphrase: entry.new)
                        announce("Exported to \(url.lastPathComponent).")
                    }
                    sheet = nil
                },
                onCancel: { sheet = nil })
        }
    }

    private static let plainExplanation = """
    Display names, usernames, hostnames or IP addresses, and ports, all in plain text. No \
    passwords and no keys. Only your account can read the file, and FileVault encrypts it whenever \
    this Mac is off or locked.
    """

    private static let encryptedExplanation = """
    There are two ways in. A key in your Keychain opens it silently every time. Your recovery \
    passphrase opens it if that key is ever gone. Losing one does not lose the other.
    """

    /// Destination first, then the passphrase, so it is held only for the
    /// moment it takes to write the file.
    private func export() {
        let panel = NSSavePanel()
        panel.title = "Export Connections"
        panel.nameFieldStringValue = "SSH-Wakey connections.json"
        panel.allowedContentTypes = [.json]
        panel.canCreateDirectories = true
        panel.message = "This copy is not encrypted."

        guard panel.runModal() == .OK, let url = panel.url else { return }

        guard store.isEncrypted else {
            run { try store.export(to: url) }
            if problem == nil { announce("Exported to \(url.lastPathComponent).") }
            return
        }
        sheet = .export(url)
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
        case .disable: return "disable"
        case .export: return "export"
        }
    }
}
