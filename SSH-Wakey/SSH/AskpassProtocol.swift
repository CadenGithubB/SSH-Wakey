import Darwin
import Foundation
import Security

/// Only nonsecret authorization/context crosses this socket. The password is
/// entered in the helper and goes directly to its verified parent ssh's stdout.
enum AskpassProtocol {
    static let socketEnvironmentKey = "SSH_WAKEY_ASKPASS_SOCKET"
    static let nonceEnvironmentKey = "SSH_WAKEY_ASKPASS_NONCE"
    static let maxRequestBytes = 4096
    // OpenSSH's askpass reader uses a 1024-byte buffer, including terminator.
    static let maximumPasswordBytes = 1022
    static let promptLifetime: TimeInterval = 120

    struct Context: Codable, Equatable, Sendable {
        let destination: String
        let action: String
    }
    struct Message: Codable {
        let nonce: String
        let prompt: String
        var event: String = "password"
    }
    struct Grant: Codable {
        let context: Context
        let ssh: ProcessIdentity
        let expiresAt: TimeInterval
    }

    /// This is an extra filter, not an identity or host-verification mechanism.
    static func looksLikePasswordPrompt(_ prompt: String) -> Bool {
        let lowered = prompt.lowercased()
        let disqualifying = ["yes/no", "fingerprint", "continue connecting", "passphrase", "(y/n)"]
        return lowered.contains("password") && !disqualifying.contains(where: lowered.contains)
    }

    static func validPassword(_ string: String) -> Bool {
        !string.isEmpty && string.utf8.count <= maximumPasswordBytes
            && !string.utf8.contains(where: { $0 == 0 || $0 == 10 || $0 == 13 })
    }

    static func withSocketAddress<R>(path: String,
        _ body: (UnsafePointer<sockaddr>, socklen_t) throws -> R) throws -> R {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        guard !pathBytes.contains(0), pathBytes.count < MemoryLayout.size(ofValue: address.sun_path)
        else { throw AskpassError.socketPathTooLong }
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: pathBytes) }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        return try withUnsafePointer(to: &address) { pointer in
            try pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                try body($0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
    }

    static func configure(_ descriptor: Int32) -> Bool {
        var noSignal: Int32 = 1
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        return fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0
            && setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0
            && setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0
    }

    static func writeAll(_ descriptor: Int32, _ bytes: UnsafeRawBufferPointer) -> Bool {
        guard let base = bytes.baseAddress else { return true }
        var offset = 0
        while offset < bytes.count {
            let written = write(descriptor, base.advanced(by: offset), bytes.count - offset)
            if written > 0 { offset += written }
            else if written < 0 && errno == EINTR { continue }
            else { return false }
        }
        return true
    }

    static func sendLine(_ text: String, to descriptor: Int32) -> Bool {
        let data = Data((text + "\n").utf8) // authorization metadata only
        return data.withUnsafeBytes { writeAll(descriptor, $0) }
    }

    static func readLine(from descriptor: Int32, timeout: TimeInterval = 3) -> String? {
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        var bytes: [UInt8] = [] // never a password
        while bytes.count < maxRequestBytes {
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else { return nil }
            var state = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            let ready = poll(&state, 1, Int32(min(remaining * 1000, 500)))
            if ready < 0 && errno == EINTR { continue }
            guard ready >= 0 else { return nil }
            if ready == 0 { continue }
            var byte: UInt8 = 0
            let amount = read(descriptor, &byte, 1)
            if amount < 0 && errno == EINTR { continue }
            guard amount == 1 else { return nil }
            if byte == 10 { return String(bytes: bytes, encoding: .utf8) }
            bytes.append(byte)
        }
        return nil
    }

    static func encode<T: Encodable>(_ value: T) -> String? {
        guard let data = try? JSONEncoder().encode(value), data.count < maxRequestBytes else { return nil }
        return String(data: data, encoding: .utf8)
    }
    static func decode<T: Decodable>(_ type: T.Type, _ text: String) -> T? {
        try? JSONDecoder().decode(type, from: Data(text.utf8))
    }

    static func constantTimeEquals(_ lhs: String, _ rhs: String) -> Bool {
        let left = Array(lhs.utf8), right = Array(rhs.utf8)
        guard left.count == 64, right.count == 64 else { return false }
        var difference: UInt8 = 0
        for index in 0..<64 { difference |= left[index] ^ right[index] }
        return difference == 0
    }
}

/// A PID alone is not a process identity. Include start time, owner and parent.
struct ProcessIdentity: Codable, Equatable, Sendable {
    let pid: pid_t
    let parent: pid_t
    let uid: uid_t
    let startedSeconds: UInt64
    let startedMicroseconds: UInt64
    let path: String

    static func read(_ pid: pid_t) -> ProcessIdentity? {
        guard pid > 0 else { return nil }
        var info = proc_bsdinfo()
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
                == Int32(MemoryLayout<proc_bsdinfo>.size) else { return nil }
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard proc_pidpath(pid, &path, UInt32(path.count)) > 0 else { return nil }
        return ProcessIdentity(pid: pid, parent: pid_t(info.pbi_ppid), uid: info.pbi_uid,
            startedSeconds: info.pbi_start_tvsec, startedMicroseconds: info.pbi_start_tvusec,
            path: URL(fileURLWithPath: String(cString: path)).resolvingSymlinksInPath().path)
    }
    var isCurrent: Bool { Self.read(pid) == self }

    static func peer(on descriptor: Int32) -> ProcessIdentity? {
        var uid = uid_t(0), gid = gid_t(0), pid = pid_t(0)
        var size = socklen_t(MemoryLayout<pid_t>.size)
        guard getpeereid(descriptor, &uid, &gid) == 0, uid == getuid(),
              getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) == 0,
              size == MemoryLayout<pid_t>.size,
              let identity = read(pid), identity.uid == uid else { return nil }
        return identity
    }

    var isAppleSSH: Bool {
        guard uid == getuid(), path == "/usr/bin/ssh", isCurrent else { return false }
        var code: SecCode?, requirement: SecRequirement?
        guard SecRequirementCreateWithString("anchor apple and identifier \"com.apple.ssh\"" as CFString,
                                             [], &requirement) == errSecSuccess,
              SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid as String: pid] as CFDictionary,
                                            [], &code) == errSecSuccess,
              let code, let requirement else { return false }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess && isCurrent
    }
}

enum AskpassError: LocalizedError, Equatable {
    case socketPathTooLong, socketCreationFailed, invalidProcess, randomFailed
    var errorDescription: String? {
        switch self {
        case .socketPathTooLong: return "The private password authorization path is too long."
        case .socketCreationFailed: return "Could not create the private password authorization channel."
        case .invalidProcess: return "The SSH password helper could not be securely identified."
        case .randomFailed: return "Could not generate a secure authorization token."
        }
    }
}
