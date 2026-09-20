import Darwin
import Foundation

@MainActor
final class PasswordAuthorization {
    let channel: FileHandle
    let grant: AskpassProtocol.Grant
    let server: ProcessIdentity
    let adapter: ProcessIdentity
    var descriptor: Int32 { channel.fileDescriptor }
    init(channel: FileHandle, grant: AskpassProtocol.Grant, server: ProcessIdentity, adapter: ProcessIdentity) {
        self.channel = channel; self.grant = grant; self.server = server; self.adapter = adapter
    }
    var isValid: Bool {
        guard adapter.isCurrent, adapter.parent == grant.ssh.pid, grant.ssh.isCurrent,
              grant.ssh.parent == server.pid, server.isCurrent,
              ProcessInfo.processInfo.systemUptime < grant.expiresAt else { return false }
        var status = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
        if poll(&status, 1, 0) < 0 { return false }
        if status.revents & Int16(POLLHUP | POLLERR | POLLNVAL) != 0 { return false }
        if status.revents & Int16(POLLIN) != 0 {
            var byte: UInt8 = 0
            return recv(descriptor, &byte, 1, MSG_PEEK | MSG_DONTWAIT) > 0
        }
        return true
    }
}
