import SwiftUI

/// Shows the host keys a server is offering so the user can approve them
/// before they are written to `known_hosts`.
struct HostKeyApprovalView: View {

    let connection: SSHConnection
    var onTrusted: () -> Void
    var onCancel: () -> Void

    private enum Phase: Equatable {
        case loading
        case ready([HostKeyCandidate])
        case failed(String)
    }

    @State private var phase: Phase = .loading
    @State private var isWriting = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Host key for \(connection.host)")
                    .font(.headline)
                Text("This machine is not in your known_hosts file yet.")
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
                Button(isWriting ? "Adding…" : "Trust and Add") {
                    trust()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(isWriting || !hasKeys)
            }
            .padding(16)
        }
        .frame(width: 560)
        .task { await load() }
    }

    private var hasKeys: Bool {
        if case .ready(let keys) = phase { return !keys.isEmpty }
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
                    Task { await load() }
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
                    Fetching a fingerprint over the network does not prove it is genuine: whatever answers \
                    that address supplies it. Compare it with the value printed on the machine itself, from \
                    ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub, before you trust it.
                    """)
                    .font(.caption)
                    .fixedSize(horizontal: false, vertical: true)
                } icon: {
                    Image(systemName: "hand.raised.fill").foregroundStyle(.orange)
                }
                .padding(10)
                .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 6))
            }
        }
    }

    private func load() async {
        do {
            let keys = try await HostKeyService.scan(host: connection.host, port: connection.port)
            phase = .ready(keys)
        } catch {
            phase = .failed(error.localizedDescription)
        }
    }

    private func trust() {
        guard case .ready(let keys) = phase else { return }
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
