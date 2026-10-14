import SwiftUI

/// Shows the host keys a server is offering so the user can approve them
/// before they are written to `known_hosts`.
struct HostKeyApprovalView: View {

    let connection: SSHConnection
    let mode: ConnectMode
    var authorize: () -> Bool = { true }
    var onTrusted: () -> Void
    var onCancel: () -> Void

    private enum Phase: Equatable {
        case loading
        case ready([HostKeyCandidate])
        case failed(String)
    }

    @State private var phase: Phase = .loading
    @State private var isWriting = false
    @State private var expectedFingerprint = ""
    @State private var verifiesFingerprint = false
    @State private var scanTask: Task<Void, Never>?
    @State private var isValid = true

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Trust “\(connection.name)”?")
                    .font(.headline)
                Text("This is your first connection to this destination in SSH-Wakey.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 20)
            .padding(.top, 20)
            .padding(.bottom, 14)

            Divider()

            content
                .frame(maxWidth: .infinity, minHeight: 150, alignment: .leading)
                .padding(20)

            Divider()

            HStack {
                Spacer()
                Button("Cancel", action: onCancel)
                    .keyboardShortcut(.cancelAction)
                Button(isWriting ? "Saving…" : "Trust & \(mode.buttonTitle)") {
                    trust()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(isWriting || !canTrust)
            }
            .padding(16)
        }
        .frame(width: 560)
        .onAppear(perform: startScan)
        .onDisappear(perform: invalidate)
        .onReceive(NotificationCenter.default.publisher(for: .wakeyDidLock)) { _ in invalidate() }
    }

    private var canTrust: Bool {
        if case .ready(let keys) = phase, keys.count == 1 {
            return !verifiesFingerprint || trimmedFingerprint == keys[0].fingerprint
        }
        return false
    }

    private var trimmedFingerprint: String {
        expectedFingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    @ViewBuilder
    private var content: some View {
        switch phase {
        case .loading:
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 10) {
                    ProgressView().controlSize(.small)
                    Text("Asking \(connection.host) for its host key…")
                        .foregroundStyle(.secondary)
                }
                Text("It tries a few times, so give it a moment.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

        case .failed(let message):
            VStack(alignment: .leading, spacing: 14) {
                Label {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(message).fixedSize(horizontal: false, vertical: true)
                        Text("If the machine has only just restarted, it may not be running its "
                             + "SSH server yet.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                }

                Button("Try Again") {
                    phase = .loading
                    startScan()
                }
            }

        case .ready(let keys):
            VStack(alignment: .leading, spacing: 14) {
                Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 5) {
                    GridRow {
                        Text("Host").foregroundStyle(.secondary)
                        Text(connection.host).textSelection(.enabled)
                    }
                    GridRow {
                        Text("Port").foregroundStyle(.secondary)
                        Text(String(connection.port))
                    }
                    GridRow {
                        Text("Username").foregroundStyle(.secondary)
                        Text(connection.username).textSelection(.enabled)
                    }
                }

                Text("SSH-Wakey will remember this key and block future connections if it changes.")
                    .fixedSize(horizontal: false, vertical: true)

                ForEach(keys) { key in
                    VStack(alignment: .leading, spacing: 3) {
                        Text("\(key.algorithm) · \(key.bits) bits")
                            .font(.system(size: 12, weight: .semibold))
                        Text(key.fingerprint)
                            .font(.system(size: 12, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }

                Text("Trusting without comparing a fingerprint relies on the machine answering at this address being the one you expect.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                Toggle("Verify fingerprint first (optional)", isOn: $verifiesFingerprint)

                if verifiesFingerprint {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Get the fingerprint directly from the Mac or your administrator. On the Mac, run:")
                            .font(.caption)
                            .fixedSize(horizontal: false, vertical: true)
                        Text("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub")
                            .font(.system(size: 11, design: .monospaced))
                            .textSelection(.enabled)
                        TextField("Paste its SHA256:… fingerprint", text: $expectedFingerprint)
                            .font(.system(size: 11, design: .monospaced))
                            .textFieldStyle(.roundedBorder)
                        if !trimmedFingerprint.isEmpty {
                            Label(canTrust ? "Fingerprints match" : "Fingerprints do not match. Check the destination before continuing.",
                                  systemImage: canTrust ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                                .font(.caption)
                                .foregroundStyle(canTrust ? Color.green : Color.orange)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
            }
        }
    }

    private func load() async {
        guard isValid, authorize(), !Task.isCancelled else { return }
        expectedFingerprint = ""
        do {
            let keys = try await HostKeyService.scan(host: connection.host, port: connection.port)
            guard isValid, !Task.isCancelled, authorize() else { return }
            phase = .ready(keys)
        } catch {
            guard isValid, !Task.isCancelled, authorize() else { return }
            phase = .failed(error.localizedDescription)
        }
    }

    private func startScan() {
        guard isValid, authorize() else { return }
        scanTask?.cancel()
        scanTask = Task { await load() }
    }

    private func invalidate() {
        isValid = false
        scanTask?.cancel()
        scanTask = nil
        expectedFingerprint = ""
        phase = .loading
    }

    private func trust() {
        guard isValid, !isWriting, authorize(), case .ready(let keys) = phase, canTrust else { return }
        isWriting = true
        do {
            try HostKeyService.trust(keys, expectedFingerprint: verifiesFingerprint ? expectedFingerprint : nil)
            onTrusted()
        } catch {
            phase = .failed(error.localizedDescription)
            isWriting = false
        }
    }
}
