import SwiftUI

/// Add and Edit sheet.
///
/// Nothing is marked as a problem until Save is pressed. A form that turns red
/// while you are still filling in the first field is telling you off for not
/// having finished yet. After the first failed Save, the messages do follow
/// along as you type, because by then they are useful.
struct ConnectionEditorView: View {

    let title: String
    var onSave: (SSHConnection) -> Void
    var onCancel: () -> Void

    @State private var draft: SSHConnection
    @State private var portText: String
    @State private var showsProblems = false
    @State private var showsOptionHelp = false

    init(
        connection: SSHConnection,
        title: String,
        onSave: @escaping (SSHConnection) -> Void,
        onCancel: @escaping () -> Void
    ) {
        self.title = title
        self.onSave = onSave
        self.onCancel = onCancel
        _draft = State(initialValue: connection)
        _portText = State(initialValue: String(connection.port))
    }

    private var candidate: SSHConnection {
        var copy = draft
        copy.port = Int(portText.trimmingCharacters(in: .whitespaces)) ?? -1
        return copy.normalized
    }

    private var issues: [ConnectionValidator.Issue] {
        ConnectionValidator.issues(in: candidate)
    }

    /// Nil until Save has been pressed at least once.
    private func issue(for field: ConnectionValidator.Field) -> String? {
        guard showsProblems else { return nil }
        return issues.first { $0.field == field }?.message
    }

    private var isExisting: Bool { draft.createdAt != nil || !draft.revisions.isEmpty }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(title)
                .font(.headline)
                .padding(.horizontal, 20)
                .padding(.top, 20)
                .padding(.bottom, 12)

            Form {
                field("Display name", text: $draft.name, prompt: "Studio Mac", issue: issue(for: .name))
                field("Username", text: $draft.username, prompt: "admin", issue: issue(for: .username))
                field("Host or IP", text: $draft.host, prompt: "192.168.1.24", issue: issue(for: .host))

                LabeledContent("Port") {
                    VStack(alignment: .leading, spacing: 3) {
                        TextField("Port", text: $portText, prompt: Text("22"))
                            .labelsHidden()
                            .frame(width: 90)
                        message(issue(for: .port))
                    }
                }

                Section {
                    LabeledContent {
                        VStack(alignment: .leading, spacing: 3) {
                            TextField("Extra SSH arguments", text: $draft.extraArguments,
                                      prompt: Text("-J jumphost -o ServerAliveInterval=30"))
                                .labelsHidden()
                                .font(.system(size: 12, design: .monospaced))
                            message(issue(for: .arguments))
                        }
                    } label: {
                        HStack(spacing: 4) {
                            Text("Extra SSH arguments")
                            Button {
                                showsOptionHelp.toggle()
                            } label: {
                                Image(systemName: "info.circle")
                            }
                            .buttonStyle(.borderless)
                            .help("What can go here")
                            .popover(isPresented: $showsOptionHelp, arrowEdge: .trailing) {
                                SSHOptionsReference()
                            }
                        }
                    }

                    Toggle(isOn: $draft.strictHostKeyChecking) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Require a known host key")
                            Text(draft.strictHostKeyChecking
                                 ? "An unknown host is refused. SSH-Wakey offers to show you its fingerprint so you can approve it."
                                 : "An unknown host is trusted on first use. A host key that has changed is still refused.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    Picker("When you press the button", selection: $draft.connectMode) {
                        ForEach(ConnectMode.allCases) { mode in
                            Text(mode.title).tag(mode)
                        }
                    }
                    Text(draft.connectMode.explanation)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                if isExisting {
                    Section("History") {
                        LabeledContent("Added", value: Self.longDate(draft.createdAt))
                        LabeledContent("Last edited", value: Self.longDate(draft.modifiedAt))

                        if draft.revisions.isEmpty {
                            Text("No changes since it was added.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        } else {
                            DisclosureGroup("Changes (\(draft.revisions.count))") {
                                VStack(alignment: .leading, spacing: 8) {
                                    ForEach(draft.revisions.reversed()) { revision in
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(revision.date.formatted(date: .abbreviated, time: .shortened))
                                                .font(.caption)
                                                .foregroundStyle(.secondary)
                                            Text(revision.summary)
                                                .font(.system(size: 11, design: .monospaced))
                                                .textSelection(.enabled)
                                                .fixedSize(horizontal: false, vertical: true)
                                        }
                                    }
                                }
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.top, 4)
                            }
                        }
                    }
                }
            }
            .formStyle(.grouped)

            Divider()

            HStack(spacing: 10) {
                Text("Passwords are never part of a saved connection.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Cancel", action: onCancel)
                    .keyboardShortcut(.cancelAction)
                Button("Save", action: save)
                    .keyboardShortcut(.defaultAction)
            }
            .padding(16)
        }
        .frame(width: 560)
        .frame(maxHeight: 640)
    }

    private func save() {
        let candidate = candidate
        guard ConnectionValidator.issues(in: candidate).isEmpty else {
            showsProblems = true
            return
        }
        onSave(candidate)
    }

    static func longDate(_ date: Date?) -> String {
        guard let date else { return "Not recorded" }
        return date.formatted(date: .abbreviated, time: .shortened)
    }

    private func field(
        _ label: String,
        text: Binding<String>,
        prompt: String,
        issue: String?
    ) -> some View {
        LabeledContent(label) {
            VStack(alignment: .leading, spacing: 3) {
                TextField(label, text: text, prompt: Text(prompt))
                    .labelsHidden()
                message(issue)
            }
        }
    }

    @ViewBuilder
    private func message(_ text: String?) -> some View {
        if let text {
            Label(text, systemImage: "exclamationmark.circle.fill")
                .font(.caption)
                .foregroundStyle(.red)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// A short key of the `ssh` options worth knowing, shown from the info button
/// next to the extra arguments field.
struct SSHOptionsReference: View {

    private struct Group: Identifiable {
        let id = UUID()
        let title: String
        let options: [(flag: String, meaning: String)]
    }

    private static let groups: [Group] = [
        Group(title: "Seeing what is happening", options: [
            ("-v", "Print what ssh is doing. Repeat as -vv or -vvv for more."),
            ("-q", "Quiet. Hides warnings."),
        ]),
        Group(title: "Getting there", options: [
            ("-J admin@jump.example.com", "Reach the machine through a jump host."),
            ("-i ~/.ssh/id_ed25519", "Offer one particular private key."),
            ("-4", "Force IPv4. Useful when a name resolves to both."),
            ("-6", "Force IPv6."),
        ]),
        Group(title: "Staying connected", options: [
            ("-o ServerAliveInterval=30", "Send a keepalive every 30 seconds so an idle session is not dropped."),
            ("-o ServerAliveCountMax=3", "Give up after this many keepalives go unanswered."),
            ("-o ConnectionAttempts=3", "Retry the initial connection this many times."),
        ]),
        Group(title: "Carrying things over the connection", options: [
            ("-L 8080:localhost:80", "Local port 8080 here reaches port 80 on the far side."),
            ("-R 9090:localhost:90", "Remote port 9090 there reaches port 90 here."),
            ("-D 1080", "A SOCKS proxy on local port 1080."),
            ("-C", "Compress the connection. Worth it on a slow link."),
            ("-A", "Forward your SSH agent, so the remote machine can use your keys."),
            ("-X", "Forward X11."),
        ]),
    ]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("Extra SSH arguments")
                    .font(.headline)

                Text("Options only. The username, host and port come from the fields above, so do "
                     + "not repeat them here.")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                ForEach(Self.groups) { group in
                    VStack(alignment: .leading, spacing: 6) {
                        Text(group.title)
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundStyle(.secondary)
                            .textCase(.uppercase)

                        ForEach(group.options, id: \.flag) { option in
                            VStack(alignment: .leading, spacing: 1) {
                                Text(option.flag)
                                    .font(.system(size: 11, design: .monospaced))
                                    .textSelection(.enabled)
                                Text(option.meaning)
                                    .font(.system(size: 11))
                                    .foregroundStyle(.secondary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                }

                Divider()

                VStack(alignment: .leading, spacing: 6) {
                    Text("What is refused")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(.secondary)
                        .textCase(.uppercase)
                    Text("""
                    Anything that can make ssh run another program on this Mac: ProxyCommand, \
                    LocalCommand, PermitLocalCommand, KnownHostsCommand, PKCS11Provider, Match, \
                    Include. Anything that points ssh at a different known_hosts. And anything \
                    SSH-Wakey sets itself, such as -p, -l, -M, -S, ControlPath and \
                    StrictHostKeyChecking.

                    Arguments are split by SSH-Wakey, never by a shell, so quotes group words and \
                    $(...) is just text.
                    """)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(16)
        }
        .frame(width: 400, height: 460)
    }
}
