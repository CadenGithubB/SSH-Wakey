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
    /// When more than one row is selected, Connect and Edit are off the table and
    /// this panel says so instead of talking about a single machine.
    var selectedCount = 0
    /// IT catalog: no add/remove copy, Wake-only idle text.
    var isManagedCatalog = false
    /// Rows in the current list. Needed so “nothing selected” is not described
    /// as an empty catalog when IT has assigned machines.
    var assignedCount = 0
    /// The saved file exists but could not be read. Idle copy must not invite
    /// adding a machine, which would replace that file.
    var fileUnavailable = false

    var onCancel: () -> Void
    var onReviewHostKey: () -> Void
    var onShowHelp: () -> Void

    private var isMultiSelect: Bool { selectedCount > 1 }

    @State private var showsDetail = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if storageError != nil {
                storageBanner
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

                    HStack(alignment: .firstTextBaseline, spacing: 12) {
                        if !isMultiSelect, state.isConnecting {
                            Button("Cancel", action: onCancel)
                                .controlSize(.small)
                        }
                        if !isMultiSelect, case .failed(let failure) = state {
                            if failure.suggestsLocalNetworkPermission {
                                Button("Local Network Settings…") {
                                    SystemSettings.openLocalNetworkPrivacy()
                                }
                                .controlSize(.small)
                            }
                            if failure.offersHostKeyReview {
                                // Full size, unlike the buttons beside it. When
                                // a host is unknown this is not a footnote, it
                                // is the thing that has to happen next.
                                Button("Review host key…", action: onReviewHostKey)
                            }
                            if failure.offersBootHelp {
                                Button("What SSH-Wakey does", action: onShowHelp)
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

                if !isMultiSelect, state.isConnecting {
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

    private var storageBanner: some View {
        let integrity = storageError?.localizedCaseInsensitiveContains("damaged or altered") == true
            || storageError?.localizedCaseInsensitiveContains("seal no longer") == true
        return banner(
            icon: integrity ? "exclamationmark.shield.fill" : "externaldrive.badge.xmark",
            tint: integrity ? .red : .orange,
            text: storageError ?? "")
    }

    @ViewBuilder
    private var icon: some View {
        if isMultiSelect {
            Image(systemName: "checklist")
                .foregroundStyle(.secondary)
        } else {
            switch state {
            case .idle:
                Image(systemName: connection == nil
                      ? "sidebar.left"
                      : (connection?.connectMode == .session ? "terminal" : "lock.open"))
                    .foregroundStyle(.secondary)
            case .connecting:
                Image(systemName: "arrow.triangle.2.circlepath")
                    .foregroundStyle(.blue)
            case .connected:
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            case .unlocked:
                Image(systemName: "lock.open.fill")
                    .foregroundStyle(.blue)
            case .failed(let failure):
                Image(systemName: failure.kind == .cancelled ? "xmark.circle" : "exclamationmark.triangle.fill")
                    .foregroundStyle(failure.kind == .cancelled ? Color.secondary : Color.red)
            }
        }
    }

    private var destination: String {
        guard let connection else { return "" }
        return redactsAddresses ? connection.name : connection.displayDestination
    }

    private var headline: String {
        if isMultiSelect {
            return "\(selectedCount) connections selected."
        }
        switch state {
        case .idle:
            guard connection != nil else {
                return Self.unselectedHeadline(
                    isManagedCatalog: isManagedCatalog, assignedCount: assignedCount,
                    fileUnavailable: fileUnavailable)
            }
            let mode = isManagedCatalog ? ConnectMode.unlock : (connection?.connectMode ?? .unlock)
            return mode.idleHeadline(destination: destination)
        case .connecting(let stage):
            return stage
        case .connected:
            guard connection != nil else { return "Connected." }
            return "Connected to \(destination)."
        case .unlocked:
            guard connection != nil else { return "Logged in, then closed." }
            return "Logged in to \(destination). The connection is closed."
        case .failed(let failure):
            return failure.headline
        }
    }

    private var guidance: String? {
        if isMultiSelect {
            return isManagedCatalog
                ? "Wake still needs one machine selected."
                : "Remove deletes them from this Mac. Wake, Connect and Edit still need one selection."
        }
        switch state {
        case .idle:
            if connection == nil {
                return Self.unselectedGuidance(
                    isManagedCatalog: isManagedCatalog, assignedCount: assignedCount,
                    fileUnavailable: fileUnavailable)
            }
            return isManagedCatalog
                ? ConnectMode.unlock.idleGuidance
                : (connection?.connectMode ?? .unlock).idleGuidance
        case .connecting(let stage):
            return stage == SSHSessionManager.wakingHeadline
                ? "A wake packet is on the network. SSH starts once the machine can hear it."
                : HelpNotes.passwordNote
        case .connected(let info):
            let opened = info.since.formatted(date: .omitted, time: .shortened)
            return info.usedPassword
                ? "Authenticated at \(opened). Open in Terminal starts a shell on this session without asking again."
                : "Authenticated at \(opened) without submitting a password."
        case .unlocked(let info):
            var lines: [String] = []
            if info.closedByServer {
                var text = "The machine closed the connection straight after completing "
                    + "authentication. If it was waiting at the FileVault screen, that is what "
                    + "waking it looks like: it is starting up now."
                if !isManagedCatalog {
                    text += " Give it a minute, then choose Open a session if you want a shell."
                }
                lines.append(text)
            } else {
                var text = "That is all Wake does. Authentication succeeded and nothing "
                    + "was left open. If that Mac was waiting at the FileVault screen it is "
                    + "starting up now."
                if !isManagedCatalog {
                    text += " Choose Open a session if you want a shell."
                }
                lines.append(text)
            }
            if !info.usedPassword {
                lines.append("This attempt authenticated without submitting a password. "
                    + "No password popup was needed.")
            }
            return lines.joined(separator: "\n\n")
        case .failed(let failure):
            return failure.guidance
        }
    }

    /// Idle copy when no row is selected. The empty-catalog sentence belongs
    /// only to an empty list, not to “nothing highlighted yet.”
    static func unselectedHeadline(
        isManagedCatalog: Bool, assignedCount: Int, fileUnavailable: Bool = false
    ) -> String {
        if fileUnavailable {
            return "The saved connections file could not be opened."
        }
        if isManagedCatalog {
            return assignedCount == 0
                ? "Your organization has not assigned any machines."
                : "Select a machine."
        }
        return "Select a connection."
    }

    static func unselectedGuidance(
        isManagedCatalog: Bool, assignedCount: Int, fileUnavailable: Bool = false
    ) -> String? {
        if fileUnavailable { return nil }
        if isManagedCatalog {
            return assignedCount == 0 ? nil : "Pick one from the list to wake it."
        }
        return "Add a machine, or pick one from the list."
    }
}
