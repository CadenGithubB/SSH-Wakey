import Foundation

/// The contract between SSH-Wakey and the copy of itself that `ssh` runs as
/// its `SSH_ASKPASS` helper.
///
/// The helper is told where to ask and what to say by two environment
/// variables that exist only in the environment of the one `ssh` process the
/// app spawns. Neither carries the password.
enum AskpassProtocol {

    static let socketEnvironmentKey = "SSH_WAKEY_ASKPASS_SOCKET"
    static let nonceEnvironmentKey = "SSH_WAKEY_ASKPASS_NONCE"

    /// Generous enough for any real prompt, small enough to bound the read.
    static let maxRequestBytes = 4096
    static let maxResponseBytes = 4096

    /// Only an actual password prompt gets an answer.
    ///
    /// With `StrictHostKeyChecking=yes` ssh never asks for host key
    /// confirmation through askpass, but if any build or configuration ever
    /// changed that, this check keeps the password from being handed to a
    /// "are you sure you want to continue connecting" question, and keeps it
    /// from being reused as a local key passphrase.
    static func looksLikePasswordPrompt(_ prompt: String) -> Bool {
        let lowered = prompt.lowercased()
        let disqualifying = ["yes/no", "fingerprint", "continue connecting", "passphrase", "(y/n)"]
        if disqualifying.contains(where: lowered.contains) { return false }
        return lowered.contains("password")
    }

    /// Builds a `sockaddr_un` for a path, refusing paths that do not fit.
    static func withSocketAddress<R>(
        path: String,
        _ body: (UnsafePointer<sockaddr>, socklen_t) throws -> R
    ) throws -> R {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard pathBytes.count < capacity else { throw AskpassError.socketPathTooLong(path) }
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            raw.copyBytes(from: pathBytes)
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        return try withUnsafePointer(to: &address) { pointer in
            try pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                try body(sockaddrPointer, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
    }

    /// Length-independent comparison so a mismatched nonce leaks nothing by timing.
    static func constantTimeEquals(_ lhs: String, _ rhs: String) -> Bool {
        let left = Array(lhs.utf8)
        let right = Array(rhs.utf8)
        var difference: UInt8 = left.count == right.count ? 0 : 1
        for index in 0..<max(left.count, right.count) {
            let a = index < left.count ? left[index] : 0
            let b = index < right.count ? right[index] : 0
            difference |= a ^ b
        }
        return difference == 0
    }
}

enum AskpassError: LocalizedError, Equatable {
    case socketPathTooLong(String)
    case socketCreationFailed(String)
    case temporaryDirectoryUnavailable(String)

    var errorDescription: String? {
        switch self {
        case .socketPathTooLong(let path):
            return "The temporary socket path is too long for a UNIX socket: \(path)"
        case .socketCreationFailed(let reason):
            return "SSH-Wakey could not open its local password channel: \(reason)"
        case .temporaryDirectoryUnavailable(let reason):
            return "SSH-Wakey could not create a private temporary folder: \(reason)"
        }
    }
}
