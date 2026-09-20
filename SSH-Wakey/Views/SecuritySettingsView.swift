import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// The Settings window. Everything here is about how the saved connections file
/// is stored.
struct SecuritySettingsView: View {

    let store: ConnectionStore
    let security: AppSecurityCoordinator

    @State private var sheet: PassphraseSheet.Purpose?
    @State private var problem: String?
    @State private var note: String?
    @State private var operation: Task<Void, Never>?
    @State private var operationID: UUID?

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
                        store.isUnavailable
                            ? "Could not be opened"
                            : (store.isEncrypted ? "Encrypted on disk" : "Stored in plain text"),
                        systemImage: store.isUnavailable
                            ? "exclamationmark.shield.fill"
                            : (store.isEncrypted ? "lock.fill" : "doc.plaintext"))
                        .foregroundStyle(
                            store.isUnavailable
                                ? Color.red
                                : (store.isEncrypted ? Color.green : Color.secondary))
                }

                Text(storageExplanation)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Section("App Lock") {
                if store.isAppLockEnabled {
                    LabeledContent("Lock after", value: "5 minutes without activity")
                    Text("Also locks when your Mac locks, sleeps or switches users. Locking disconnects open SSH sessions and clears the unlocked connection list.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if store.isLocked {
                        Button("Unlock with macOS…") { Task { await security.unlock() } }
                            .disabled(store.isAuthenticating)
                    } else {
                        Button("Lock Now", action: security.lockNow)
                        Button("Turn Off App Lock…") { sheet = .disableAppLock }
                            .disabled(store.isAuthenticating)
                    }
                } else {
                    Text("Use Touch ID or your Mac login password to unlock SSH-Wakey for five minutes of activity. Your remote Mac password is still entered separately.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Button("Turn On App Lock…") { sheet = .enableAppLock }
                        .disabled(!store.isEncrypted || store.access != .open || store.isAuthenticating)
                    if !store.isEncrypted {
                        Text("Turn on connection-file encryption first so locking can release the key protecting your saved connections.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                if store.isAuthenticating {
                    HStack {
                        ProgressView().controlSize(.small)
                        Text("Waiting for macOS authentication…").font(.caption)
                        Button("Cancel") { cancelOperation() }
                    }
                }
            }

            Section {
                if store.isEncrypted {
                    Button("Change Recovery Passphrase…") { sheet = .change }
                        .disabled(store.isLocked || store.isUnavailable || store.isAuthenticating)
                    Button("Turn Off Encryption…") { sheet = .disable }
                        .disabled(store.isLocked || store.isUnavailable || store.isAuthenticating
                                  || store.isAppLockEnabled)
                    if store.isAppLockEnabled {
                        Text("Turn off App Lock before removing connection-file encryption.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Button("Turn On Encryption…") { sheet = .create }
                        .disabled(store.isUnavailable || store.isAuthenticating)
                }

                Button("Export a Readable Copy…", action: export)
                    .disabled(store.isLocked || store.isUnavailable || store.isAuthenticating)
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
        .frame(width: 500, height: 580)
        .onReceive(NotificationCenter.default.publisher(for: .wakeyDidLock)) { _ in
            operation?.cancel()
            operation = nil
            operationID = nil
            sheet = nil
            note = nil
            problem = nil
        }
        .sheet(item: $sheet) { purpose in
            PassphraseSheet(
                purpose: purpose,
                onSubmit: { entry in
                    // Recovery is deliberately available while locked. Every
                    // other action must still own a current inactivity lease.
                    if case .unlock = purpose { }
                    else if !security.authorizeCurrentAccess() {
                        throw AppLockError.invalidPreparation
                    }
                    switch purpose {
                    case .create:
                        try store.enableEncryption(passphrase: entry.new)
                        announce("Encrypted. Export a copy now, while the passphrase is in front "
                                 + "of you.")
                    case .change:
                        if store.isAppLockEnabled {
                            let preparation = try store.prepareChangePassphrase(from: entry.current ?? "", to: entry.new)
                            startOperation(success: "The recovery passphrase has been changed.") {
                                try await store.changePassphrase(preparation)
                            }
                        } else {
                            try store.changePassphrase(from: entry.current ?? "", to: entry.new)
                            announce("The recovery passphrase has been changed.")
                        }
                    case .unlock:
                        try store.unlock(withPassphrase: entry.new)
                        announce("Your connections are unlocked.")
                    case .disable:
                        try store.disableEncryption(passphrase: entry.new)
                        announce("Encryption is off. The file is plain text again.")
                    case .export(let url):
                        try store.export(to: url, passphrase: entry.new)
                        announce("Exported to \(url.lastPathComponent).")
                    case .enableAppLock:
                        let preparation = try store.prepareEnableAppLock(passphrase: entry.new)
                        startOperation(success: "App Lock is on. The app locks after five minutes without activity.") {
                            try await store.enableAppLock(preparation)
                        }
                    case .disableAppLock:
                        let preparation = try store.prepareDisableAppLock(passphrase: entry.new)
                        startOperation(success: "App Lock is off. Your connection file remains encrypted.") {
                            try await store.disableAppLock(preparation)
                        }
                    }
                    security.refresh()
                    sheet = nil
                },
                onCancel: { sheet = nil })
        }
    }

    private var storageExplanation: String {
        if store.isUnavailable {
            return store.storageError
                ?? "The saved connections file could not be opened. Do not add machines or turn on encryption until it can be read."
        }
        if store.isAppLockEnabled {
            return "Your connection file is encrypted. Unlock with Touch ID or your Mac login password, or use your recovery passphrase if the protected local key is unavailable. SSH passwords are never saved."
        }
        return store.isEncrypted ? Self.encryptedExplanation : Self.plainExplanation
    }

    private static let plainExplanation = """
    Display names, usernames, hostnames or IP addresses, and ports, all in plain text. No \
    passwords and no keys. The file is private to your account. FileVault protects the volume at \
    rest; locking the screen does not remove a running account’s access.
    """

    private static let encryptedExplanation = """
    There are two ways in. A key in your Keychain opens it silently every time. Your recovery \
    passphrase opens it if that key is ever gone. Losing one does not lose the other.
    """

    /// Destination first, then the passphrase, so it is held only for the
    /// moment it takes to write the file.
    private func export() {
        guard security.authorizeCurrentAccess() else { return }
        let panel = NSSavePanel()
        panel.title = "Export Connections"
        panel.nameFieldStringValue = "SSH-Wakey connections.json"
        panel.allowedContentTypes = [.json]
        panel.canCreateDirectories = true
        panel.message = "This copy is not encrypted."

        guard panel.runModal() == .OK, let url = panel.url,
              security.authorizeCurrentAccess() else { return }

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

    private func cancelOperation() {
        operation?.cancel()
        operation = nil
        operationID = nil
        security.lockNow()
    }

    /// Only prepared encrypted material and owned key objects cross this await;
    /// the native passphrase field's String bridge is never captured here.
    private func startOperation(success: String, work: @escaping @MainActor () async throws -> Void) {
        let id = UUID()
        operationID = id
        problem = nil
        note = nil
        operation = Task {
            do {
                try await work()
                if operationID == id, !Task.isCancelled { announce(success) }
            } catch is CancellationError { }
            catch {
                if operationID == id, !Task.isCancelled { problem = error.localizedDescription }
            }
            security.refresh()
            if operationID == id {
                operation = nil
                operationID = nil
            }
        }
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
        case .enableAppLock: return "enableAppLock"
        case .disableAppLock: return "disableAppLock"
        }
    }
}
