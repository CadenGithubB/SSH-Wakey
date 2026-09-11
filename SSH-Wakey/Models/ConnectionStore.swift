import Foundation
import Observation

/// The in-memory connection list the UI binds to, backed by `ConnectionFileStore`.
@MainActor
@Observable
final class ConnectionStore {

    private(set) var connections: [SSHConnection] = []
    /// Set when loading or saving fails so the window can show it instead of
    /// failing silently.
    private(set) var storageError: String?

    private let fileStore: ConnectionFileStore

    var fileURL: URL { fileStore.fileURL }

    init(fileStore: ConnectionFileStore = ConnectionFileStore()) {
        self.fileStore = fileStore
        load()
    }

    func load() {
        do {
            connections = try fileStore.load()
            storageError = nil
        } catch {
            connections = []
            storageError = error.localizedDescription
        }
    }

    func add(_ connection: SSHConnection) {
        var added = connection.normalized
        let now = Date.stamp()
        added.createdAt = now
        added.modifiedAt = now
        added.revisions = []
        connections.append(added)
        sortAndSave()
    }

    /// Keeps the original creation date, and records what changed.
    func update(_ connection: SSHConnection) {
        guard let index = connections.firstIndex(where: { $0.id == connection.id }) else { return }
        let previous = connections[index]

        var updated = connection.normalized
        updated.hidesDetails = previous.hidesDetails
        updated.createdAt = previous.createdAt
        updated.revisions = previous.revisions

        let changes = updated.changes(from: previous)
        if changes.isEmpty {
            updated.modifiedAt = previous.modifiedAt
        } else {
            let now = Date.stamp()
            updated.modifiedAt = now
            updated.revisions.append(
                ConnectionRevision(date: now, summary: changes.joined(separator: ", ")))
            if updated.revisions.count > SSHConnection.maxRevisions {
                updated.revisions.removeFirst(updated.revisions.count - SSHConnection.maxRevisions)
            }
        }

        connections[index] = updated
        sortAndSave()
    }

    /// Toggles the per-row display setting. It is not an edit: it does not
    /// touch the modified date and it does not appear in the change history.
    func setDetailsHidden(_ hidden: Bool, for id: SSHConnection.ID) {
        guard let index = connections.firstIndex(where: { $0.id == id }),
              connections[index].hidesDetails != hidden else { return }
        connections[index].hidesDetails = hidden
        sortAndSave()
    }

    func remove(id: SSHConnection.ID) {
        connections.removeAll { $0.id == id }
        sortAndSave()
    }

    func connection(with id: SSHConnection.ID?) -> SSHConnection? {
        guard let id else { return nil }
        return connections.first { $0.id == id }
    }

    private func sortAndSave() {
        connections.sort { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
        do {
            try fileStore.save(connections)
            storageError = nil
        } catch {
            storageError = "Could not save connections: \(error.localizedDescription)"
        }
    }
}
