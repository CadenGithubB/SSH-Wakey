import Darwin
import Foundation
import Security

/// Fixed signed-bundle locations, never paths supplied in a password request.
enum HelperLayout {
    static let adapterName = "SSH-Wakey Askpass"
    static let serviceName = "PasswordInput"
    #if SSHWAKEY_MANAGED_DISTRIBUTION
    static let appName = "SSH-Wakey Managed"
    #else
    static let appName = "SSH-Wakey"
    #endif
    static func adapter(in app: URL = Bundle.main.bundleURL) -> URL {
        app.appendingPathComponent("Contents/Helpers/\(adapterName).app")
    }
    static func executable(in bundle: URL, name: String) -> URL {
        bundle.appendingPathComponent("Contents/MacOS/\(name)")
    }
    static var adapterPath: String { executable(in: adapter(), name: adapterName).path }
    static func enclosingBundle(of bundle: URL) -> URL {
        bundle.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }
    static func service(in adapter: URL) -> URL {
        adapter.appendingPathComponent("Contents/XPCServices/\(serviceName).xpc")
    }
}

enum HelperIdentity {
    static let maximumExecutableBytes = 128 * 1024 * 1024

    private static func exactRequirement(_ code: SecStaticCode) -> String? {
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(code, [], &information) == errSecSuccess,
              let values = information as? [String: Any],
              let hash = values[kSecCodeInfoUnique as String] as? Data, hash.count == 20 else { return nil }
        return "cdhash H\"" + hash.map { String(format: "%02x", $0) }.joined() + "\""
    }
    static func requirement(at bundle: URL) -> String? {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(bundle as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess else { return nil }
        return exactRequirement(code)
    }
    /// This descriptor grants no folder access. Security's path-based reader
    /// cannot reopen /dev/fd inside the sandbox, so inspect a private, temporary
    /// copy of public executable bytes. Hash extraction is NOT signature
    /// validation: XPC/the kernel must still validate the peer before UI.
    static func requirement(from file: FileHandle, expectedExecutable: URL,
                            temporaryDirectory: URL = FileManager.default.temporaryDirectory) -> String? {
        let fd = file.fileDescriptor
        var info = stat()
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(fd, F_GETFL) & O_ACCMODE == O_RDONLY,
              fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_size > 0, info.st_size <= maximumExecutableBytes,
              fcntl(fd, F_GETPATH, &path) == 0,
              URL(fileURLWithPath: String(cString: path)).standardizedFileURL.path == expectedExecutable.standardizedFileURL.path else { return nil }
        // mkdtemp exclusively creates a mode-0700 directory in this process's
        // sandbox-adjusted temporary location. No user-data path is passed in
        // the password protocol, and no filesystem entitlement is added.
        var template = Array(temporaryDirectory.appendingPathComponent("helper-verification.XXXXXX").path.utf8CString)
        guard mkdtemp(&template) != nil else { return nil }
        let directory = URL(fileURLWithPath: String(cString: template), isDirectory: true)
        defer { _ = rmdir(directory.path) }
        let copy = directory.appendingPathComponent("executable")
        let copyFD = open(copy.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard copyFD >= 0 else { return nil }
        defer { close(copyFD); _ = unlink(copy.path) }

        // pread leaves the shared descriptor's offset unchanged. Bound memory
        // and total bytes, and refuse truncated or concurrently modified input.
        var offset: off_t = 0
        var bytes = [UInt8](repeating: 0, count: 65_536)
        while offset < info.st_size {
            let count = pread(fd, &bytes, min(bytes.count, Int(info.st_size - offset)), offset)
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { return nil }
            var written = 0
            while written < count {
                let countWritten = bytes.withUnsafeBytes {
                    pwrite(copyFD, $0.baseAddress!.advanced(by: written), count - written, offset + off_t(written))
                }
                if countWritten < 0 && errno == EINTR { continue }
                guard countWritten > 0 else { return nil }
                written += countWritten
            }
            offset += off_t(count)
        }
        var after = stat()
        guard fstat(fd, &after) == 0, after.st_size == info.st_size,
              after.st_mtimespec.tv_sec == info.st_mtimespec.tv_sec,
              after.st_mtimespec.tv_nsec == info.st_mtimespec.tv_nsec,
              after.st_ctimespec.tv_sec == info.st_ctimespec.tv_sec,
              after.st_ctimespec.tv_nsec == info.st_ctimespec.tv_nsec,
              fchmod(copyFD, 0o400) == 0 else { return nil }

        // Keep the original Mach-O and all architecture slices intact. The
        // detached copy is only a source of the exact signed code hash; the
        // actual running peer is checked separately against that requirement.
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(copy as CFURL, [], &code) == errSecSuccess, let code,
              let requirement = exactRequirement(code),
              unlink(copy.path) == 0, rmdir(directory.path) == 0 else { return nil }
        return requirement
    }
    static func peer(on fd: Int32, matches text: String, infoPlist: Data? = nil) -> Bool {
        var token = audit_token_t()
        var size = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size) == 0,
              size == MemoryLayout<audit_token_t>.size else { return false }
        var attributes: [String: Any] = [kSecGuestAttributeAudit as String: withUnsafeBytes(of: &token) { Data($0) }]
        if let infoPlist {
            guard !infoPlist.isEmpty, infoPlist.count <= 65_536 else { return false }
            // Security verifies these bytes against the running peer's signed
            // Info.plist hash, without needing access to the peer's filesystem.
            attributes[kSecGuestAttributeDynamicCode as String] = true
            attributes[kSecGuestAttributeDynamicCodeInfoPlist as String] = infoPlist
        }
        var code: SecCode?, requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              let requirement,
              SecCodeCopyGuestWithAttributes(nil, attributes as CFDictionary, [], &code) == errSecSuccess,
              let code else { return false }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }
    static func readInfoPlist(in bundle: URL) throws -> Data {
        let file = try FileHandle(forReadingFrom: bundle.appendingPathComponent("Contents/Info.plist"))
        defer { try? file.close() }
        guard let data = try file.read(upToCount: 65_537), !data.isEmpty, data.count <= 65_536
        else { throw AskpassError.invalidProcess }
        return data
    }
}
