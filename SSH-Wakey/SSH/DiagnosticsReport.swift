import Foundation

/// One connection attempt, kept so it can be written out afterwards when
/// something needs explaining.
///
/// Retains application-generated summaries only. SSH banners, errors and
/// interactive prompts can contain anything supplied by a server, including a
/// reflected password, so raw output must never become a lasting diagnostic.
struct DiagnosticEntry: Identifiable, Sendable {
    let id = UUID()
    var at: Date
    /// Ties the attempt to a saved connection so Activity can show one machine.
    var connectionID: UUID
    var connection: String
    var destination: String
    var mode: String
    var result: String
    var channel: String

    init(at: Date, connectionID: UUID, connection: String, destination: String,
         mode: String, result: String, channel: String, output: String = "") {
        self.at = at
        self.connectionID = connectionID
        self.connection = connection
        self.destination = destination
        self.mode = mode
        self.result = result
        self.channel = channel
        // Deliberately discard output; retained for source compatibility with
        // callers that also use transient SSH output to classify a failure.
    }
}

/// Renders recent attempts as something that can be read, saved and sent on.
enum DiagnosticsReport {

    /// Enough for several hosts to each have a short history in one session,
    /// few enough that the diagnostics file stays readable.
    static let maximumEntries = 40
    /// Cap for one machine's Activity sheet, so a busy host cannot crowd out
    /// every other entry in the shared list.
    static let maximumEntriesPerConnection = 20

    /// Newest first. Used by the per-host Activity sheet.
    static func entries(
        _ entries: [DiagnosticEntry],
        for connectionID: UUID
    ) -> [DiagnosticEntry] {
        entries
            .filter { $0.connectionID == connectionID }
            .sorted { $0.at > $1.at }
    }

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
        lines.append("Read this before sending it anywhere. It lists saved connection names,")
        lines.append("hostnames, usernames and application-generated results. Raw SSH output and")
        lines.append("server prompts are excluded because a server can return sensitive text.")
        lines.append("Passwords are not intentionally recorded. Review saved names before sharing.")
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
        // Keep user-defined labels from injecting additional report fields or
        // terminal control sequences when someone opens the exported file.
        let safe = String(String.UnicodeScalarView(value.unicodeScalars.prefix(1024)
            .filter { !CharacterSet.controlCharacters.contains($0) }))
        return label.padding(toLength: max(18, label.count + 1), withPad: " ", startingAt: 0) + safe
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
