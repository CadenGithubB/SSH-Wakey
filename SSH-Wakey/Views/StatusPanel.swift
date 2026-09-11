import SwiftUI

/// The band under the list that reports what the selected connection is doing
/// and, when something goes wrong, what to do about it.
struct StatusPanel: View {

    let connection: SSHConnection?
    let state: SSHSessionManager.State
    let storageError: String?
    let actionError: String?
    /// Matches the eye toggle in the window, so hiding addresses hides them here too.
    var redactsAddresses = false

    var onCancel: () -> Void
    var onReviewHostKey: () -> Void
    var onShowHelp: () -> Void

    @State private var showsDetail = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let storageError {
                banner(icon: "externaldrive.badge.xmark", tint: .orange, text: storageError)
            }
            if let actionError {
                banner(icon: "exclamationmark.triangle.fill", tint: .orange, text: actionError)
            }

            HStack(alignment: .top, spacing: 10) {
                icon
                VStack(alignment: .leading, spacing: 4) {
                    Text(headline)
                        .font(.system(size: 13, weight: .semibold))
                        .fixedSize(horizontal: false, vertical: true)

                    if let guidance {
                        Text(guidance)
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    HStack(spacing: 12) {
                        if state.isConnecting {
                            Button("Cancel", action: onCancel)
                                .controlSize(.small)
                        }
                        if case .failed(let failure) = state {
                            if failure.suggestsLocalNetworkPermission {
                                Button("Local Network Settings…") {
                                    SystemSettings.openLocalNetworkPrivacy()
                                }
                                .controlSize(.small)
                            }
                            if failure.offersHostKeyReview {
                                Button("Review host key…", action: onReviewHostKey)
                                    .controlSize(.small)
                            }
                            if failure.offersBootHelp {
                                Button("Why can't I connect?", action: onShowHelp)
                                    .controlSize(.small)
                            }
                            if failure.detail != nil {
                                Button(showsDetail ? "Hide details" : "Show details") {
                                    showsDetail.toggle()
                                }
                                .controlSize(.small)
                            }
                        }
                    }
                    .padding(.top, 2)

                    if showsDetail, case .failed(let failure) = state, let detail = failure.detail {
                        ScrollView {
                            Text(detail)
                                .font(.system(size: 11, design: .monospaced))
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(6)
                        }
                        .frame(maxHeight: 88)
                        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 5))
                    }
                }
                Spacer(minLength: 0)

                if state.isConnecting {
                    ProgressView()
                        .controlSize(.small)
                        .padding(.top, 1)
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .onChange(of: state) { _, _ in showsDetail = false }
    }

    private func banner(icon: String, tint: Color, text: String) -> some View {
        Label {
            Text(text).font(.system(size: 12)).fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: icon).foregroundStyle(tint)
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 6))
    }

    @ViewBuilder
    private var icon: some View {
        switch state {
        case .idle:
            Image(systemName: connection == nil ? "sidebar.left" : "terminal")
                .foregroundStyle(.secondary)
        case .connecting:
            Image(systemName: "arrow.triangle.2.circlepath")
                .foregroundStyle(.blue)
        case .connected:
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)
        case .failed(let failure):
            Image(systemName: failure.kind == .cancelled ? "xmark.circle" : "exclamationmark.triangle.fill")
                .foregroundStyle(failure.kind == .cancelled ? Color.secondary : Color.red)
        }
    }

    private var destination: String {
        guard let connection else { return "" }
        return redactsAddresses ? connection.name : connection.displayDestination
    }

    private var headline: String {
        switch state {
        case .idle:
            guard connection != nil else { return "Select a connection." }
            return "Ready to connect to \(destination)."
        case .connecting(let stage):
            return stage
        case .connected:
            guard connection != nil else { return "Connected." }
            return "Connected to \(destination)."
        case .failed(let failure):
            return failure.headline
        }
    }

    private var guidance: String? {
        switch state {
        case .idle:
            return connection == nil
                ? "Add a machine, or pick one from the list."
                : "Connect asks for the password, uses it once, and then keeps the session open."
        case .connecting:
            return HelpNotes.passwordNote
        case .connected(let info):
            let opened = info.since.formatted(date: .omitted, time: .shortened)
            return info.usedPassword
                ? "Authenticated at \(opened). Open in Terminal starts a shell on this session without asking again."
                : "Authenticated at \(opened) with an SSH key, so the password you typed was never used or sent."
        case .failed(let failure):
            return failure.guidance
        }
    }
}
