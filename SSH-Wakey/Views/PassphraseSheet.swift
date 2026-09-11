import SwiftUI

/// Sets, changes or asks for the recovery passphrase.
struct PassphraseSheet: View {

    enum Purpose {
        /// Turning encryption on for the first time.
        case create
        /// Replacing the existing passphrase.
        case change
        /// Opening a file whose Keychain key has gone.
        case unlock

        var title: String {
            switch self {
            case .create: return "Choose a recovery passphrase"
            case .change: return "Change the recovery passphrase"
            case .unlock: return "Enter your recovery passphrase"
            }
        }

        var actionTitle: String {
            switch self {
            case .create: return "Encrypt"
            case .change: return "Change"
            case .unlock: return "Unlock"
            }
        }

        var wantsConfirmation: Bool { self != .unlock }

        var explanation: String {
            switch self {
            case .create, .change:
                return """
                Your connections are normally opened with a key kept in your Keychain, without \
                asking you for anything. This passphrase is the other way in, for when that key is \
                gone: a Keychain reset, a new Mac, or an item deleted by hand.

                Put it in your password manager. It is not meant to be memorised, and there is no \
                way to recover it.
                """
            case .unlock:
                return """
                The key in your Keychain is missing or no longer fits, so your connections could \
                not be opened automatically. The recovery passphrase you set when you turned \
                encryption on will open them.

                Once it does, a fresh Keychain key is stored so this does not happen again.
                """
            }
        }
    }

    let purpose: Purpose
    /// Throws to keep the sheet open and show what went wrong.
    var onSubmit: (String) throws -> Void
    var onCancel: () -> Void

    @State private var passphrase = ""
    @State private var confirmation = ""
    @State private var problem: String?
    @FocusState private var focused: Bool

    private var isComplete: Bool {
        guard !passphrase.isEmpty else { return false }
        return purpose.wantsConfirmation ? !confirmation.isEmpty : true
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 10) {
                    Image(systemName: purpose == .unlock ? "lock.rotation" : "key.horizontal")
                        .font(.system(size: 22))
                        .foregroundStyle(.tint)
                    Text(purpose.title).font(.headline)
                }

                Text(purpose.explanation)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                SecureField(purpose == .unlock ? "Recovery passphrase" : "New passphrase",
                            text: $passphrase)
                    .textFieldStyle(.roundedBorder)
                    .focused($focused)
                    .onSubmit(submit)

                if purpose.wantsConfirmation {
                    SecureField("Repeat it", text: $confirmation)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit(submit)

                    Text("At least \(VaultCrypto.minimumPassphraseLength) characters.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
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
                    passphrase = ""
                    confirmation = ""
                    onCancel()
                }
                .keyboardShortcut(.cancelAction)

                Button(purpose.actionTitle, action: submit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(!isComplete)
            }
            .padding(16)
        }
        .frame(width: 440)
        .onAppear { focused = true }
    }

    private func submit() {
        guard isComplete else { return }
        if purpose.wantsConfirmation {
            guard passphrase == confirmation else {
                problem = "The two passphrases do not match."
                return
            }
            guard passphrase.count >= VaultCrypto.minimumPassphraseLength else {
                problem = "Use at least \(VaultCrypto.minimumPassphraseLength) characters."
                return
            }
        }

        do {
            try onSubmit(passphrase)
            passphrase = ""
            confirmation = ""
        } catch {
            problem = error.localizedDescription
        }
    }
}
