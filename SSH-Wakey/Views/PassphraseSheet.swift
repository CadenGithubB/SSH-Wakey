import SwiftUI

/// Sets, changes or asks for the recovery passphrase.
@MainActor
struct PassphraseSheet: View {

    enum Purpose {
        /// Turning encryption on for the first time.
        case create
        /// Replacing the existing passphrase.
        case change
        /// Opening a file whose Keychain key has gone.
        case unlock
        /// Going back to a plain text file.
        case disable
        /// Writing a plain text copy somewhere else.
        case export(URL)
        /// Migrates the local wrapping key to require system authentication.
        case enableAppLock
        /// Removes system authentication while retaining vault encryption.
        case disableAppLock

        var title: String {
            switch self {
            case .create: return "Choose a recovery passphrase"
            case .change: return "Change the recovery passphrase"
            case .unlock: return "Enter your recovery passphrase"
            case .disable: return "Turn off encryption"
            case .export: return "Export a readable copy"
            case .enableAppLock: return "Turn on App Lock"
            case .disableAppLock: return "Turn off App Lock"
            }
        }

        var actionTitle: String {
            switch self {
            case .create: return "Encrypt"
            case .change: return "Change"
            case .unlock: return "Unlock"
            case .disable: return "Turn Off"
            case .export: return "Export"
            case .enableAppLock, .disableAppLock: return "Continue"
            }
        }

        var wantsConfirmation: Bool {
            switch self {
            case .create, .change: return true
            case .unlock, .disable, .export, .enableAppLock, .disableAppLock: return false
            }
        }

        /// Replacing a passphrase should prove you know the one being replaced,
        /// the same as any other password change.
        var wantsCurrent: Bool {
            if case .change = self { return true }
            return false
        }

        var explanation: String {
            switch self {
            case .create, .change:
                return """
                This passphrase is another way to open your encrypted connections if the local \
                key is unavailable, such as after a Keychain reset or a move to another Mac. \
                If App Lock is on, it also lets you recover access without the normal unlock method.

                Put it in your password manager. It is not meant to be memorised, and there is no \
                way to recover it.
                """
            case .unlock:
                return """
                Your recovery passphrase is the other way to open your encrypted connections, \
                even if the local key is missing or you cannot use the normal unlock method.

                If App Lock is on, recovery keeps it on. The app will still lock after five \
                minutes without activity.
                """
            case .enableAppLock:
                return """
                Confirm your recovery passphrase before changing how this vault opens. macOS \
                will then ask you to authenticate with Touch ID or your Mac login password.

                SSH-Wakey will lock after five minutes without activity, and when your Mac \
                locks, sleeps or switches users. Locking disconnects all SSH sessions, including \
                any Terminal windows using them. Remote Mac passwords are still entered separately.
                """
            case .disableAppLock:
                return """
                Enter your recovery passphrase to turn off App Lock. Your connection file stays \
                encrypted, but the app will open it without asking for Touch ID or your Mac \
                login password. Automatic locking and its session disconnections will stop.
                """
            case .export(let url):
                return """
                A readable copy of your connections will be written to \(url.lastPathComponent). \
                It is an ordinary file with no encryption, so keep it somewhere safe and out of \
                shared folders.

                Your passphrase confirms it is you, the same as the other two ways of ending up \
                with a plain-text copy.
                """
            case .disable:
                return """
                The file will be rewritten in plain text and the Keychain key removed. Only your \
                account will be able to read it, and FileVault protects the volume at rest; screen locking \
                does not remove the running account's access.

                Your passphrase confirms it is you. Without that, a moment at an unlocked Mac \
                would be enough to quietly turn this off and leave the file readable.
                """
            }
        }
    }

    /// What the sheet collected.
    struct Entry {
        /// The existing passphrase, when the sheet asked for one as well as a
        /// new one.
        var current: String?
        /// Whatever was typed in the main field: a new passphrase, or the
        /// existing one when that is all the sheet asked for.
        var new: String
    }

    let purpose: Purpose
    /// Throws to keep the sheet open and show what went wrong.
    var onSubmit: (Entry) throws -> Void
    var onCancel: () -> Void

    // SwiftUI retains references to native fields, never their plaintext value.
    // Native AppKit storage and the scoped submission bridge cannot be promised
    // to be explicitly erasable. No ordinary TextField/reveal/undo path is used.
    @State private var fields = RecoveryFields()
    @State private var copied = false
    @State private var problem: String?
    @State private var inputProtected = false

    private static func icon(for purpose: Purpose) -> String {
        switch purpose {
        case .create, .change: return "key.horizontal"
        case .unlock: return "lock.rotation"
        case .disable: return "lock.open"
        case .export: return "square.and.arrow.up"
        case .enableAppLock, .disableAppLock: return "lock.shield"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 10) {
                    Image(systemName: Self.icon(for: purpose))
                        .font(.system(size: 22))
                        .foregroundStyle(.tint)
                    Text(purpose.title).font(.headline)
                }

                Text(purpose.explanation)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                if purpose.wantsCurrent {
                    NativeRecoveryField(field: fields.current, placeholder: "Current passphrase",
                                        focusInitially: true, onSubmit: submit)
                        .frame(height: 24)
                }

                NativeRecoveryField(field: fields.passphrase,
                                    placeholder: purpose.wantsConfirmation ? "New passphrase" : "Recovery passphrase",
                                    focusInitially: !purpose.wantsCurrent, onSubmit: submit)
                    .frame(height: 24)

                if purpose.wantsConfirmation {
                    NativeRecoveryField(field: fields.confirmation, placeholder: "Repeat it",
                                        focusInitially: false, onSubmit: submit)
                        .frame(height: 24)

                    Text("At least \(VaultCrypto.minimumPassphraseLength) characters.")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    Divider()

                    HStack(spacing: 8) {
                        Button("Generate", action: generate)
                        Button(copied ? "Copied" : "Copy", action: copy)
                            .disabled(!inputProtected)
                        Button("Open Passwords") {
                            NSWorkspace.shared.open(
                                URL(fileURLWithPath: "/System/Applications/Passwords.app"))
                        }
                        Spacer()
                    }
                    .controlSize(.small)

                    Text("""
                    SSH-Wakey does not save this in Passwords. Copy it and add it there yourself \
                    as a new entry. The clipboard is limited to this Mac and cleared again after \
                    a minute and a half if nothing else has replaced it.
                    """)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                }

                if let problem {
                    Label(problem, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(20)

            Divider()

            HStack {
                Spacer()
                Button("Cancel") {
                    fields.invalidate()
                    onCancel()
                }
                .keyboardShortcut(.cancelAction)

                Button(purpose.actionTitle, action: submit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!inputProtected)
            }
            .padding(16)
        }
        .frame(width: 460)
        .onAppear(perform: activateInput)
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            activateInput()
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
            fields.secureInput.release()
            fields.setEnabled(false)
            inputProtected = false
        }
        .onReceive(NotificationCenter.default.publisher(for: .wakeyDidLock)) { _ in
            fields.invalidate()
            inputProtected = false
            onCancel()
        }
        .onDisappear {
            fields.invalidate()
        }
    }

    private func activateInput() {
        guard !fields.isInvalidated, NSApplication.shared.isActive else {
            fields.setEnabled(false)
            inputProtected = false
            return
        }
        fields.secureInput.acquire()
        inputProtected = fields.secureInput.isActive
        fields.setEnabled(inputProtected)
        if !inputProtected { problem = "Secure keyboard input is unavailable. Close this sheet and try again." }
    }

    private func generate() {
        guard !fields.isInvalidated, inputProtected, fields.secureInput.isActive else { return }
        do {
            try autoreleasepool {
                let suggestion = try VaultCrypto.suggestedPassphrase()
                fields.passphrase.stringValue = suggestion
                fields.confirmation.stringValue = suggestion
            }
            copied = false
            problem = nil
        } catch { problem = error.localizedDescription }
    }

    /// Copy is an explicit transfer to the system clipboard. Concealed/transient
    /// markers ask cooperating clipboard managers not to retain it, and the
    /// current-host-only option prevents Universal Clipboard transfer.
    private func copy() {
        guard !fields.isInvalidated, inputProtected, fields.secureInput.isActive else { return }
        autoreleasepool {
            fields.passphrase.validateEditing()
            let value = fields.passphrase.stringValue
            guard !value.isEmpty else { return }
            let pasteboard = NSPasteboard.general
            let item = NSPasteboardItem()
            item.setString(value, forType: .string)
            item.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
            item.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.TransientType"))
            pasteboard.prepareForNewContents(with: .currentHostOnly)
            copied = pasteboard.writeObjects([item])
            let stamp = pasteboard.changeCount
            if copied { RecoveryClipboard.remember(changeCount: stamp) }
            DispatchQueue.main.asyncAfter(deadline: .now() + 90) {
                RecoveryClipboard.clearIfOwned(changeCount: stamp)
            }
        }
    }

    private func submit() {
        guard !fields.isInvalidated, inputProtected, fields.secureInput.isActive else { return }
        do {
            try autoreleasepool {
                fields.validateEditing()
                let passphrase = fields.passphrase.stringValue
                guard !passphrase.isEmpty else {
                    throw EntryError.message("Enter your recovery passphrase.")
                }
                guard passphrase.utf8.count <= VaultCrypto.maximumPassphraseBytes else {
                    throw EntryError.message("The recovery passphrase is too long.")
                }
                let current = purpose.wantsCurrent ? fields.current.stringValue : nil
                if purpose.wantsCurrent && (current?.isEmpty ?? true) {
                    throw EntryError.message("Enter the current recovery passphrase.")
                }
                if purpose.wantsConfirmation {
                    guard passphrase == fields.confirmation.stringValue else {
                        throw EntryError.message("The two passphrases do not match.")
                    }
                    guard passphrase.count >= VaultCrypto.minimumPassphraseLength else {
                        throw EntryError.message("Use at least \(VaultCrypto.minimumPassphraseLength) characters.")
                    }
                }
                // Synchronous scope only: no async task, SwiftUI state, or
                // persistent model retains Entry or the field's String bridge.
                try onSubmit(Entry(current: current, new: passphrase))
            }
            fields.invalidate()
        } catch {
            problem = error.localizedDescription
        }
    }

    private enum EntryError: LocalizedError {
        case message(String)
        var errorDescription: String? { switch self { case .message(let text): return text } }
    }
}

/// Tracks only an explicitly copied recovery phrase, never its plaintext.
/// Locking cannot leave that phrase available as an immediate alternate unlock.
@MainActor
enum RecoveryClipboard {
    private static var ownedChangeCount: Int?

    static func remember(changeCount: Int) { ownedChangeCount = changeCount }

    static func clearIfOwned(changeCount: Int? = nil, pasteboard: NSPasteboard = .general) {
        guard let owned = ownedChangeCount,
              changeCount == nil || changeCount == owned else { return }
        if pasteboard.changeCount == owned { pasteboard.clearContents() }
        ownedChangeCount = nil
    }
}

@MainActor
private final class RecoveryFields {
    let current = NSSecureTextField()
    let passphrase = NSSecureTextField()
    let confirmation = NSSecureTextField()
    let secureInput = SecureInputSession()
    private(set) var isInvalidated = false

    init() {
        for field in [current, passphrase, confirmation] {
            field.maximumNumberOfLines = 1
            field.isAutomaticTextCompletionEnabled = false
            field.allowsEditingTextAttributes = false
            field.isEnabled = false
        }
    }

    func setEnabled(_ enabled: Bool) {
        for field in [current, passphrase, confirmation] { field.isEnabled = enabled && !isInvalidated }
    }

    func invalidate() {
        isInvalidated = true
        clear()
        setEnabled(false)
        secureInput.release()
    }

    func validateEditing() {
        for field in [current, passphrase, confirmation] { field.validateEditing() }
    }

    func clear() {
        for field in [current, passphrase, confirmation] {
            field.currentEditor()?.string = ""
            field.stringValue = ""
        }
    }
}

@MainActor
private struct NativeRecoveryField: NSViewRepresentable {
    let field: NSSecureTextField
    let placeholder: String
    let focusInitially: Bool
    let onSubmit: () -> Void

    func makeCoordinator() -> Coordinator { Coordinator(onSubmit: onSubmit) }

    func makeNSView(context: Context) -> NSSecureTextField {
        field.placeholderString = placeholder
        field.target = context.coordinator
        field.action = #selector(Coordinator.submit(_:))
        if focusInitially {
            DispatchQueue.main.async { field.window?.makeFirstResponder(field) }
        }
        return field
    }

    func updateNSView(_ nsView: NSSecureTextField, context: Context) {
        context.coordinator.onSubmit = onSubmit
    }

    final class Coordinator: NSObject {
        var onSubmit: () -> Void
        init(onSubmit: @escaping () -> Void) { self.onSubmit = onSubmit }
        @objc func submit(_ sender: Any?) { onSubmit() }
    }
}
