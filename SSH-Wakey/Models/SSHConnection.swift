import Foundation

/// One recorded change to a saved connection.
struct ConnectionRevision: Codable, Identifiable, Hashable, Sendable {
    var id: UUID
    var date: Date
    /// What changed, in the form `Host: old → new`.
    var summary: String

    init(id: UUID = UUID(), date: Date, summary: String) {
        self.id = id
        self.date = date
        self.summary = summary
    }
}

/// Metadata for one saved SSH destination.
///
/// This type deliberately holds no secrets. There is no password field, no key
/// material and no passphrase. Everything here is safe to write to disk in
/// plain text, which is exactly what `ConnectionFileStore` does.
struct SSHConnection: Codable, Identifiable, Hashable, Sendable {

    static let defaultPort = 22
    /// Oldest revisions are dropped past this, so the file cannot grow without
    /// bound on a connection that is edited often.
    static let maxRevisions = 20

    var id: UUID
    var name: String
    var username: String
    var host: String
    var port: Int
    /// Additional `ssh` options, written the way they would be typed on a
    /// command line. They are tokenised by `SSHArgumentParser`, never by a
    /// shell, and they are checked against an allow list before use.
    var extraArguments: String
    /// When true, a host whose key is not already in `known_hosts` is refused
    /// instead of being trusted automatically.
    var strictHostKeyChecking: Bool

    /// Nil for a connection saved by a build that did not record dates yet.
    /// Left nil rather than invented, so the window can say it does not know.
    var createdAt: Date?
    var modifiedAt: Date?
    var revisions: [ConnectionRevision]

    init(
        id: UUID = UUID(),
        name: String = "",
        username: String = "",
        host: String = "",
        port: Int = SSHConnection.defaultPort,
        extraArguments: String = "",
        strictHostKeyChecking: Bool = true,
        createdAt: Date? = nil,
        modifiedAt: Date? = nil,
        revisions: [ConnectionRevision] = []
    ) {
        self.id = id
        self.name = name
        self.username = username
        self.host = host
        self.port = port
        self.extraArguments = extraArguments
        self.strictHostKeyChecking = strictHostKeyChecking
        self.createdAt = createdAt
        self.modifiedAt = modifiedAt
        self.revisions = revisions
    }

    /// `user@host` plus the port when it is not the default. Display only.
    var displayDestination: String {
        let base = "\(username)@\(host)"
        return port == Self.defaultPort ? base : "\(base):\(port)"
    }

    /// Whitespace trimmed from every text field. Applied before validating and
    /// before saving so that a stray space cannot produce a bad argument list.
    var normalized: SSHConnection {
        var copy = self
        copy.name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        copy.username = username.trimmingCharacters(in: .whitespacesAndNewlines)
        copy.host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        copy.extraArguments = extraArguments.trimmingCharacters(in: .whitespacesAndNewlines)
        return copy
    }

    /// A readable list of what differs from an earlier version of the same
    /// connection. Empty when nothing that is worth recording changed.
    func changes(from previous: SSHConnection) -> [String] {
        var changes: [String] = []

        func compare(_ label: String, _ before: String, _ after: String) {
            guard before != after else { return }
            let from = before.isEmpty ? "(empty)" : before
            let to = after.isEmpty ? "(empty)" : after
            changes.append("\(label): \(from) → \(to)")
        }

        compare("Name", previous.name, name)
        compare("Username", previous.username, username)
        compare("Host", previous.host, host)
        compare("Port", String(previous.port), String(port))
        compare("Extra arguments", previous.extraArguments, extraArguments)

        if previous.strictHostKeyChecking != strictHostKeyChecking {
            func describe(_ strict: Bool) -> String { strict ? "required" : "trust on first use" }
            changes.append("Known host key: \(describe(previous.strictHostKeyChecking)) "
                + "→ \(describe(strictHostKeyChecking))")
        }

        return changes
    }
}

extension SSHConnection {

    private enum CodingKeys: String, CodingKey {
        case id, name, username, host, port, extraArguments, strictHostKeyChecking
        case createdAt, modifiedAt, revisions
    }

    /// Decoding tolerates files written by an older build that did not have
    /// every field yet, so upgrading the app never discards saved connections.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        name = try container.decode(String.self, forKey: .name)
        username = try container.decode(String.self, forKey: .username)
        host = try container.decode(String.self, forKey: .host)
        port = try container.decodeIfPresent(Int.self, forKey: .port) ?? SSHConnection.defaultPort
        extraArguments = try container.decodeIfPresent(String.self, forKey: .extraArguments) ?? ""
        strictHostKeyChecking = try container.decodeIfPresent(Bool.self, forKey: .strictHostKeyChecking) ?? true
        createdAt = try container.decodeIfPresent(Date.self, forKey: .createdAt)
        modifiedAt = try container.decodeIfPresent(Date.self, forKey: .modifiedAt)
        revisions = try container.decodeIfPresent([ConnectionRevision].self, forKey: .revisions) ?? []
    }
}

extension Date {
    /// Timestamps are kept to whole seconds, so what is written to the file is
    /// exactly what is read back out of it.
    static func stamp(_ now: Date = Date()) -> Date {
        Date(timeIntervalSince1970: now.timeIntervalSince1970.rounded(.down))
    }
}
