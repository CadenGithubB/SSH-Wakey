import Foundation

/// One connection attempt, kept so it can be written out afterwards when
/// something needs explaining.
///
/// The ssh output is what ssh itself printed. It carries hostnames, usernames
/// and key fingerprints, and no password: the password is never on the command
/// line ssh was given and never appears in its output.
struct DiagnosticEntry: Identifiable, Sendable {
    let id = UUID()
    var at: Date
    var connection: String
    var destination: String
    var mode: String
    var result: String
    var channel: String
    var output: String
}

/// Renders recent attempts as something that can be read, saved and sent on.
enum DiagnosticsReport {

    /// Enough to see a pattern, few enough that the file stays readable.
    static let maximumEntries = 10

    static func text(
        entries: [DiagnosticEntry],
        connectionCount: Int,
        isEncrypted: Bool,
        now: Date = Date()
    ) -> String {
        var lines: [String] = []

        lines.append("SSH-Wakey diagnostics")
        lines.append("Written \(stamp(now))")
        lines.append("")
        lines.append("Read this before sending it anywhere. It lists the hostnames, usernames and")
        lines.append("host key fingerprints of the machines you connected to. It contains no")
        lines.append("passwords: the password is never placed on a command line and never appears")
        lines.append("in ssh's output.")
        lines.append("")
        lines.append(String(repeating: "─", count: 64))
        lines.append(field("App", "\(version()) (\(configuration()))"))
        lines.append(field("macOS", ProcessInfo.processInfo.operatingSystemVersionString))
        lines.append(field("Saved file", isEncrypted ? "encrypted" : "plain text"))
        lines.append(field("Connections", String(connectionCount)))
        lines.append(field("Attempts recorded", String(entries.count)))
        lines.append("")

        guard !entries.isEmpty else {
            lines.append("No connection attempts have been made since the app was opened.")
            return lines.joined(separator: "\n") + "\n"
        }

        for (index, entry) in entries.enumerated().reversed() {
            lines.append(String(repeating: "─", count: 64))
            lines.append("Attempt \(index + 1) of \(entries.count)")
            lines.append("")
            lines.append(field("When", stamp(entry.at)))
            lines.append(field("Connection", entry.connection))
            lines.append(field("Destination", entry.destination))
            lines.append(field("Mode", entry.mode))
            lines.append(field("Result", entry.result))
            lines.append(field("Password channel", entry.channel))
            lines.append("")
            lines.append("ssh output")
            let output = entry.output.trimmingCharacters(in: .whitespacesAndNewlines)
            if output.isEmpty {
                lines.append("    (ssh printed nothing)")
            } else {
                lines.append(contentsOf: output.split(separator: "\n", omittingEmptySubsequences: false)
                    .map { "    " + $0 })
            }
            lines.append("")
        }

        return lines.joined(separator: "\n") + "\n"
    }

    /// A sensible name for the saved file, with the date in it so several do
    /// not overwrite one another.
    static func suggestedFileName(_ now: Date = Date()) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HHmm"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return "SSH-Wakey diagnostics \(formatter.string(from: now)).txt"
    }

    private static func field(_ label: String, _ value: String) -> String {
        label.padding(toLength: max(18, label.count + 1), withPad: " ", startingAt: 0) + value
    }

    private static func stamp(_ date: Date) -> String {
        date.formatted(date: .abbreviated, time: .standard)
    }

    private static func version() -> String {
        let short = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "?"
        return "\(short) (\(build))"
    }

    private static func configuration() -> String {
        #if DEBUG
        return "Debug build, not hardened"
        #else
        return "Release build"
        #endif
    }
}
