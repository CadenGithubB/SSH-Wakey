import SwiftUI

/// Recent connection attempts for one saved host, opened from the row menu.
///
/// This is the same record Help ▸ Save Diagnostics writes out, filtered to one
/// machine. It lives only while the app is open: nothing about attempts is
/// written to the connections file.
struct ActivityLogView: View {

    let connection: SSHConnection
    let entries: [DiagnosticEntry]
    var onDismiss: () -> Void

    @State private var expanded: Set<UUID> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Activity for \(connection.name)")
                    .font(.headline)
                Text("Connection attempts since SSH-Wakey was opened. Hostnames and usernames "
                     + "appear here. Raw SSH output and server prompts are excluded.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.horizontal, 20)
            .padding(.top, 20)
            .padding(.bottom, 14)

            Divider()

            if entries.isEmpty {
                ContentUnavailableView {
                    Label("No attempts yet", systemImage: "clock")
                } description: {
                    Text("Wake or Connect once and what happened will show up here.")
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        ForEach(entries) { entry in
                            entryRow(entry)
                        }
                    }
                    .padding(20)
                }
            }

            Divider()

            HStack {
                Text(entries.isEmpty
                     ? "Nothing recorded for this machine yet."
                     : "\(entries.count) attempt\(entries.count == 1 ? "" : "s")")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Done", action: onDismiss)
                    .keyboardShortcut(.defaultAction)
            }
            .padding(16)
        }
        .frame(width: 560, height: 520)
    }

    private func entryRow(_ entry: DiagnosticEntry) -> some View {
        let isOpen = expanded.contains(entry.id)
        return VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(entry.result)
                        .font(.system(size: 13, weight: .semibold))
                        .fixedSize(horizontal: false, vertical: true)
                    Text(entry.at.formatted(date: .abbreviated, time: .standard))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(entry.mode)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
                Button(isOpen ? "Hide details" : "Show details") {
                    if isOpen {
                        expanded.remove(entry.id)
                    } else {
                        expanded.insert(entry.id)
                    }
                }
                .controlSize(.small)
            }

            if isOpen {
                VStack(alignment: .leading, spacing: 8) {
                    labeled("Destination", entry.destination)
                    labeled("Password channel", entry.channel)

                }
                .padding(.top, 2)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
    }

    private func labeled(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
            Text(value)
                .font(.system(size: 12, design: .monospaced))
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
