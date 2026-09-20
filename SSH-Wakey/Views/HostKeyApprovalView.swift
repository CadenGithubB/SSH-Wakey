import SwiftUI

/// Shows the host keys a server is offering so the user can approve them
/// before they are written to `known_hosts`.
struct HostKeyApprovalView: View {

    let connection: SSHConnection
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
    @State private var scanTask: Task<Void, Never>?
    @State private var isValid = true

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Host key for \(connection.host)")
                    .font(.headline)
                Text("This machine does not yet have an approved key in SSH-Wakey.")
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
                Button(isWriting ? "Adding…" : "Trust Verified Key") {
                    trust()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(isWriting || !hasVerifiedKey)
            }
            .padding(16)
        }
        .frame(width: 560)
        .onAppear(perform: startScan)
        .onDisappear(perform: invalidate)
        .onReceive(NotificationCenter.default.publisher(for: .wakeyDidLock)) { _ in invalidate() }
    }

    private var hasVerifiedKey: Bool {
        if case .ready(let keys) = phase, keys.count == 1 {
            return expectedFingerprint.trimmingCharacters(in: .whitespacesAndNewlines) == keys[0].fingerprint
        }
        return false
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
                ForEach(keys) { key in
                    VStack(alignment: .leading, spacing: 3) {
                        Text("\(key.algorithm) · \(key.bits) bits")
                            .font(.system(size: 12, weight: .semibold))
                        Text(key.fingerprint)
                            .font(.system(size: 12, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }

                Label {
                    Text("""
                    On the Mac itself, run ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub. Enter its SHA256:… \
                    fingerprint below. Obtain it directly from the Mac or a trusted administrator; the \
                    fingerprint displayed above came from the network and is not proof of identity.
                    """)
                    .font(.caption)
                    .fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "hand.raised.fill").foregroundStyle(.orange)
                }
                .padding(10)
                .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 6))

                TextField("Fingerprint independently obtained from the Mac", text: $expectedFingerprint)
                    .font(.system(size: 11, design: .monospaced))
                    .textFieldStyle(.roundedBorder)
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
        guard isValid, authorize(), case .ready(let keys) = phase, hasVerifiedKey else { return }
        isWriting = true
        do {
            try HostKeyService.trust(keys)
            onTrusted()
        } catch {
            phase = .failed(error.localizedDescription)
            isWriting = false
        }
    }
}
