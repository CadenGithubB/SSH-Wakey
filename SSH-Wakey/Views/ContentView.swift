import AppKit
import SwiftUI

/// The main window: the saved list, what it is doing, and the buttons.
struct ContentView: View {

    let store: ConnectionStore
    let sessions: SSHSessionManager

    @State private var selection: SSHConnection.ID?
    @State private var sheet: SheetKind?
    @State private var removalTarget: SSHConnection?
    @State private var showsColumnPicker = false

    /// The one row whose details are on show. Everything else is masked, and
    /// revealing a row hides whichever was revealed before, so at most one
    /// machine's username and address is ever readable at a glance.
    @State private var revealedRow: SSHConnection.ID?

    /// What Connect does. Unlocking is the default, because getting a machine
    /// past its FileVault screen is the job this app exists for, and that needs
    /// nothing left open afterwards.
    @AppStorage("connectMode") private var connectMode: ConnectMode = .unlock

    /// Which optional columns are showing, and the order and widths of all of
    /// them. Name, Username, Host and the two dates cannot be hidden; Port and
    /// Extra arguments can.
    @State private var columns = TableColumnCustomization<SSHConnection>()
    @AppStorage("columnLayout.v2") private var storedColumnLayout = Data()

    enum SheetKind: Identifiable {
        case add
        case edit(SSHConnection)
        case password(SSHConnection)
        case hostKey(SSHConnection)
        case unlock
        case help

        var id: String {
            switch self {
            case .add: return "add"
            case .edit(let connection): return "edit-\(connection.id)"
            case .password(let connection): return "password-\(connection.id)"
            case .hostKey(let connection): return "hostkey-\(connection.id)"
            case .unlock: return "unlock"
            case .help: return "help"
            }
        }
    }

    private var selectedConnection: SSHConnection? { store.connection(with: selection) }
    private var selectedState: SSHSessionManager.State { sessions.state(for: selection) }

    var body: some View {
        VStack(spacing: 0) {
            listArea
            Divider()
            StatusPanel(
                connection: selectedConnection,
                state: selectedState,
                storageError: store.storageError,
                actionError: sessions.lastActionError,
                redactsAddresses: !isRevealed(selection),
                onCancel: { if let id = selection { sessions.cancelConnect(id) } },
                onReviewHostKey: { if let connection = selectedConnection { sheet = .hostKey(connection) } },
                onShowHelp: { sheet = .help })
            Divider()
            controls
        }
        .frame(minWidth: Column.minimumWindowWidth, minHeight: 480)
        .onAppear {
            (NSApp.delegate as? AppDelegate)?.sessions = sessions
            restoreColumnLayout()
            Task { await SSHSessionManager.sweepAbandonedSessions() }
        }
        .onChange(of: columns) { _, layout in saveColumnLayout(layout) }
        .sheet(item: $sheet, content: sheetContent)
        .alert(
            "Remove “\(removalTarget?.name ?? "")”?",
            isPresented: Binding(
                get: { removalTarget != nil },
                set: { if !$0 { removalTarget = nil } }),
            presenting: removalTarget
        ) { target in
            Button("Remove", role: .destructive) {
                if selection == target.id { selection = nil }
                store.remove(id: target.id)
                removalTarget = nil
            }
            Button("Cancel", role: .cancel) { removalTarget = nil }
        } message: { target in
            // Named rather than addressed when the row is hidden, so confirming
            // a deletion does not put the address back on screen.
            let described = isRevealed(target.id) ? target.displayDestination : "“\(target.name)”"
            Text("This removes the saved details for \(described) from this Mac, along with its "
                 + "history. Nothing on that machine is changed.")
        }
    }

    // MARK: - List

    @ViewBuilder
    private var listArea: some View {
        if store.isLocked {
            ContentUnavailableView {
                Label("Your connections are encrypted", systemImage: "lock.fill")
            } description: {
                Text("The key in your Keychain is missing or no longer fits, so they could not be "
                     + "opened automatically. Your recovery passphrase will open them.")
            } actions: {
                Button("Unlock…") { sheet = .unlock }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color(nsColor: .controlBackgroundColor))
        } else if store.connections.isEmpty {
            // Shown instead of the table, not over it, so the striped rows do
            // not run through the text.
            ContentUnavailableView {
                Label("No saved connections", systemImage: "desktopcomputer")
            } description: {
                Text("Add the machines you need to reach, so you do not have to remember "
                     + "usernames, addresses and ports.")
            } actions: {
                Button("Add a Connection") { sheet = .add }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color(nsColor: .controlBackgroundColor))
        } else {
            table.overlay(alignment: .topLeading) { columnsMenu }
        }
    }

    /// Sits in the header cell above the status dot and the eye, which is the
    /// one column with no title of its own.
    ///
    /// A plain button rather than a Menu: a Menu lays its label out against the
    /// leading edge and reserves room for an indicator, so the icon ends up
    /// off-centre no matter what the frame says. Centring an Image inside a
    /// fixed frame is exact.
    private var columnsMenu: some View {
        Button {
            showsColumnPicker.toggle()
        } label: {
            Image(systemName: "slider.horizontal.3")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .frame(width: Column.status.idealWidth, height: Column.headerHeight)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help("Choose which columns to show")
        .popover(isPresented: $showsColumnPicker, arrowEdge: .bottom) {
            VStack(alignment: .leading, spacing: 10) {
                Text("Optional columns")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)

                ForEach(Column.optional) { column in
                    Toggle(column.title, isOn: visibility(of: column))
                }

                Divider()

                Text("Name, Username, Host and the dates always show.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(14)
            .frame(width: 240)
        }
    }

    private var table: some View {
        Table(store.connections, selection: $selection, columnCustomization: $columns) {
            TableColumn("") { (connection: SSHConnection) in
                HStack(spacing: 7) {
                    StatusDot(state: sessions.state(for: connection.id))
                    hideButton(for: connection)
                }
                .frame(maxWidth: .infinity)
            }
            .width(Column.status.idealWidth)
            .customizationID(Column.status.id)
            .disabledCustomizationBehavior(.all)

            TableColumn("Name") { (connection: SSHConnection) in
                Text(connection.name).fontWeight(.medium)
            }
            .width(min: Column.name.minimumWidth, ideal: Column.name.idealWidth)
            .customizationID(Column.name.id)
            .disabledCustomizationBehavior(.visibility)

            TableColumn("Username") { (connection: SSHConnection) in
                DetailCell(value: connection.username, isHidden: !isRevealed(connection.id))
            }
            .width(min: Column.username.minimumWidth, ideal: Column.username.idealWidth)
            .customizationID(Column.username.id)
            .disabledCustomizationBehavior(.visibility)

            TableColumn("Host") { (connection: SSHConnection) in
                DetailCell(value: connection.host, isHidden: !isRevealed(connection.id), monospaced: true)
            }
            .width(min: Column.host.minimumWidth, ideal: Column.host.idealWidth)
            .customizationID(Column.host.id)
            .disabledCustomizationBehavior(.visibility)

            TableColumn("Port") { (connection: SSHConnection) in
                Text(String(connection.port)).monospacedDigit()
            }
            .width(Column.port.idealWidth)
            .customizationID(Column.port.id)

            TableColumn("Extra arguments") { (connection: SSHConnection) in
                DetailCell(value: connection.extraArguments, isHidden: !isRevealed(connection.id),
                           monospaced: true, dimmed: true)
            }
            .width(min: Column.arguments.minimumWidth, ideal: Column.arguments.idealWidth)
            .customizationID(Column.arguments.id)

            TableColumn("Added") { (connection: SSHConnection) in
                DetailCell(value: Self.shortDate(connection.createdAt),
                           isHidden: !isRevealed(connection.id) && connection.createdAt != nil,
                           dimmed: true)
                    .help(Self.relativeDate(connection.createdAt))
            }
            .width(min: Column.added.minimumWidth, ideal: Column.added.idealWidth)
            .customizationID(Column.added.id)
            .disabledCustomizationBehavior(.visibility)

            TableColumn("Last edited") { (connection: SSHConnection) in
                DetailCell(value: Self.shortDate(connection.modifiedAt),
                           isHidden: !isRevealed(connection.id) && connection.modifiedAt != nil,
                           dimmed: true)
                    .help(Self.relativeDate(connection.modifiedAt))
            }
            .width(min: Column.lastEdited.minimumWidth, ideal: Column.lastEdited.idealWidth)
            .customizationID(Column.lastEdited.id)
            .disabledCustomizationBehavior(.visibility)
        }
        .contextMenu(forSelectionType: SSHConnection.ID.self) { ids in
            if let id = ids.first, let connection = store.connection(with: id) {
                Button(sessions.state(for: id).isConnected ? "Open in Terminal" : "Connect") {
                    activate(connection)
                }
                Button("Edit…") { sheet = .edit(connection) }
                    .disabled(sessions.state(for: id).isConnected
                              || sessions.state(for: id).isConnecting)
                Button(isRevealed(id) ? "Hide Details" : "Show Details") {
                    toggleReveal(id)
                }
                Divider()
                Button("Remove…", role: .destructive) { removalTarget = connection }
                    .disabled(sessions.state(for: id).isConnected
                              || sessions.state(for: id).isConnecting)
            }
        } primaryAction: { ids in
            // Double-click.
            if let id = ids.first, let connection = store.connection(with: id) {
                selection = id
                activate(connection)
            }
        }
    }

    func isRevealed(_ id: SSHConnection.ID?) -> Bool {
        guard let id else { return false }
        return revealedRow == id
    }

    /// Reveals one row and hides whatever was revealed before.
    private func toggleReveal(_ id: SSHConnection.ID) {
        revealedRow = revealedRow == id ? nil : id
    }

    /// Per-row reveal, beside the status dot.
    private func hideButton(for connection: SSHConnection) -> some View {
        let shown = isRevealed(connection.id)
        return Button {
            toggleReveal(connection.id)
        } label: {
            Image(systemName: shown ? "eye.slash" : "eye")
                .font(.system(size: 11))
                .foregroundStyle(shown ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(shown
              ? "Hide this connection's username, address and dates"
              : "Show this one, and hide whichever is showing now")
    }

    /// Bound to the menu, and to the same state the header's own right-click
    /// menu writes to.
    private func visibility(of column: Column) -> Binding<Bool> {
        Binding(
            get: { columns[visibility: column.id] != .hidden },
            set: { columns[visibility: column.id] = $0 ? .visible : .hidden })
    }

    private func restoreColumnLayout() {
        guard !storedColumnLayout.isEmpty,
              let saved = try? JSONDecoder().decode(
                TableColumnCustomization<SSHConnection>.self, from: storedColumnLayout)
        else { return }
        columns = saved
    }

    private func saveColumnLayout(_ layout: TableColumnCustomization<SSHConnection>) {
        guard let encoded = try? JSONEncoder().encode(layout) else {
            storedColumnLayout = Data()
            return
        }
        storedColumnLayout = Self.strippingWidths(from: encoded) ?? encoded
    }

    /// Removes the per-column widths before the layout is saved.
    ///
    /// SwiftUI writes the width it has just worked out back into the
    /// customization, so storing it verbatim turns a column that was free to
    /// flex into one pinned at whatever the window happened to be that day.
    /// Restored into a smaller window those widths no longer fit, and the table
    /// scrolls sideways instead of shrinking. Which columns are showing, and in
    /// what order, is the part worth remembering.
    static func strippingWidths(from data: Data) -> Data? {
        guard var object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let states = object["perColumnState"] as? [Any]
        else { return nil }

        object["perColumnState"] = states.map { entry -> Any in
            guard var state = entry as? [String: Any] else { return entry }
            state.removeValue(forKey: "currentWidth")
            return state
        }
        return try? JSONSerialization.data(withJSONObject: object)
    }

    static let redactedPlaceholder = "••••••••"

    static func shortDate(_ date: Date?) -> String {
        guard let date else { return "—" }
        return date.formatted(date: .abbreviated, time: .omitted)
    }

    /// Shown as a tooltip, because "3 days ago" answers the question faster
    /// than a date does, and the exact time is worth having as well.
    static func relativeDate(_ date: Date?) -> String {
        guard let date else { return "Not recorded" }
        let relative = date.formatted(.relative(presentation: .named))
        return "\(date.formatted(date: .long, time: .shortened)) (\(relative))"
    }

    // MARK: - Buttons

    private var controls: some View {
        HStack(spacing: 10) {
            Button("Add") { sheet = .add }
                .disabled(store.isLocked)

            // Edit and Remove are absent rather than dimmed when there is
            // nothing to act on. A permanently greyed button is furniture.
            if let connection = selectedConnection {
                Button("Edit") { sheet = .edit(connection) }
                    .disabled(store.isLocked || selectedState.isConnected
                              || selectedState.isConnecting)

                Button("Remove") { removalTarget = connection }
                    .disabled(store.isLocked || selectedState.isConnected
                              || selectedState.isConnecting)
            }

            Button {
                sheet = .help
            } label: {
                Image(systemName: "questionmark.circle")
            }
            .buttonStyle(.borderless)
            .help("What SSH-Wakey does")

            SettingsLink {
                Image(systemName: "gearshape")
            }
            .buttonStyle(.borderless)
            .help("Settings")

            Spacer()

            trailingControls
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    @ViewBuilder
    private var trailingControls: some View {
        switch selectedState {
        case .connecting:
            Button("Cancel") {
                if let id = selection { sessions.cancelConnect(id) }
            }
            .keyboardShortcut(.cancelAction)

        case .connected:
            Button("Disconnect") {
                if let id = selection { sessions.disconnect(id) }
            }
            Button("Open in Terminal") {
                if let id = selection { sessions.openInTerminal(id) }
            }
            .keyboardShortcut(.defaultAction)

        case .idle, .failed, .unlocked:
            Picker("Connect mode", selection: $connectMode) {
                ForEach(ConnectMode.allCases) { mode in
                    Text(mode.title).tag(mode)
                }
            }
            .pickerStyle(.menu)
            .labelsHidden()
            .fixedSize()
            .help(connectMode.explanation)

            Button("Connect") {
                if let connection = selectedConnection { activate(connection) }
            }
            .keyboardShortcut(.defaultAction)
            .disabled(selectedConnection == nil || store.isLocked)
        }
    }

    // MARK: - Sheets

    @ViewBuilder
    private func sheetContent(_ kind: SheetKind) -> some View {
        switch kind {
        case .add:
            ConnectionEditorView(
                connection: SSHConnection(),
                title: "New Connection",
                onSave: { connection in
                    store.add(connection)
                    selection = connection.id
                    sheet = nil
                },
                onCancel: { sheet = nil })

        case .edit(let existing):
            ConnectionEditorView(
                connection: existing,
                title: "Edit Connection",
                onSave: { connection in
                    store.update(connection)
                    sheet = nil
                },
                onCancel: { sheet = nil })

        case .password(let connection):
            PasswordPromptView(
                connection: connection,
                onConnect: { entered in
                    sheet = nil
                    sessions.connect(connection, password: SecureBuffer(entered), mode: connectMode)
                },
                onCancel: { sheet = nil })

        case .hostKey(let connection):
            HostKeyApprovalView(
                connection: connection,
                onTrusted: {
                    // Dismiss first. Swapping one sheet straight for another
                    // can leave the second one unpresented on macOS.
                    sheet = nil
                    Task { @MainActor in
                        try? await Task.sleep(nanoseconds: 350_000_000)
                        sheet = .password(connection)
                    }
                },
                onCancel: { sheet = nil })

        case .unlock:
            PassphraseSheet(
                purpose: .unlock,
                onSubmit: { entry in
                    try store.unlock(withPassphrase: entry.new)
                    sheet = nil
                },
                onCancel: { sheet = nil })

        case .help:
            HelpSheet(onDismiss: { sheet = nil })
        }
    }

    // MARK: - Actions

    /// Connect, or open a terminal when the session is already up.
    private func activate(_ connection: SSHConnection) {
        switch sessions.state(for: connection.id) {
        case .connected:
            sessions.openInTerminal(connection.id)
        case .connecting:
            break
        case .idle, .failed, .unlocked:
            sheet = .password(connection)
        }
    }
}

/// A small coloured dot in the first column showing per-row session state.
struct StatusDot: View {
    let state: SSHSessionManager.State

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: 7, height: 7)
            .help(label)
    }

    private var color: Color {
        switch state {
        case .idle: return .secondary.opacity(0.25)
        case .connecting: return .yellow
        case .connected: return .green
        case .unlocked: return .blue
        case .failed(let failure): return failure.kind == .cancelled ? .secondary.opacity(0.25) : .red
        }
    }

    private var label: String {
        switch state {
        case .idle: return "Not connected"
        case .connecting: return "Connecting"
        case .connected: return "Connected"
        case .unlocked: return "Logged in, then closed"
        case .failed(let failure): return failure.headline
        }
    }
}

/// A table cell whose value can be hidden.
///
/// Every hidden cell renders the same placeholder in the same font, so a hidden
/// row lines up instead of showing two different sizes of dot.
private struct DetailCell: View {
    let value: String
    let isHidden: Bool
    var monospaced = false
    var dimmed = false

    var body: some View {
        if isHidden, !value.isEmpty {
            Text(ContentView.redactedPlaceholder)
                .font(.system(size: 12, design: .monospaced))
                .foregroundStyle(.tertiary)
        } else {
            Text(value)
                .font(.system(size: 12, design: monospaced ? .monospaced : .default))
                .foregroundStyle(dimmed ? .secondary : .primary)
        }
    }
}

/// The table's columns.
///
/// Everything that identifies a machine is required and cannot be switched off,
/// because a row with no name or address is not worth showing. Port and Extra
/// arguments are optional: most connections use port 22 and no extra options, so
/// those two columns are usually empty weight.
enum Column: String, CaseIterable, Identifiable {
    case status, name, username, host, port, arguments, added, lastEdited

    var id: String { rawValue }

    var title: String {
        switch self {
        case .status: return "Status"
        case .name: return "Name"
        case .username: return "Username"
        case .host: return "Host"
        case .port: return "Port"
        case .arguments: return "Extra arguments"
        case .added: return "Added"
        case .lastEdited: return "Last edited"
        }
    }

    /// The ones a person is allowed to hide.
    static var optional: [Column] { [.port, .arguments] }

    /// The narrowest this column may be squeezed before the table gives up and
    /// scrolls.
    var minimumWidth: CGFloat {
        switch self {
        case .status: return 42
        case .name: return 90
        case .username: return 70
        case .host: return 90
        case .port: return 44
        case .arguments: return 70
        case .added: return 72
        case .lastEdited: return 76
        }
    }

    /// What it asks for when there is room.
    var idealWidth: CGFloat {
        switch self {
        case .status: return 42
        case .name: return 130
        case .username: return 95
        case .host: return 135
        case .port: return 44
        case .arguments: return 105
        case .added: return 82
        case .lastEdited: return 88
        }
    }

    /// The status dot and the port never flex.
    var isFixedWidth: Bool { minimumWidth == idealWidth }

    static var totalIdealWidth: CGFloat { allCases.reduce(0) { $0 + $1.idealWidth } }
    static var totalMinimumWidth: CGFloat { allCases.reduce(0) { $0 + $1.minimumWidth } }

    /// The height of the table's header row, which is where the column menu
    /// sits. This is the standard macOS table header height.
    static let headerHeight: CGFloat = 24

    /// What the table needs beyond the columns themselves: the window frame,
    /// the scroll view's insets, and the gap between each pair of columns.
    static let tableChrome: CGFloat = 60

    /// The window is never allowed to be narrower than every column at its
    /// ideal width. That is what keeps the default layout from scrolling
    /// sideways, whatever the table decides to do with the widths.
    static var minimumWindowWidth: CGFloat { totalIdealWidth + tableChrome }
}
