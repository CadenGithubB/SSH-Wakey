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
    /// This descriptor grants no folder access. Hash extraction is NOT signature
    /// validation: XPC/the kernel must validate the peer against it before UI.
    static func requirement(from file: FileHandle, expectedExecutable: URL) -> String? {
        let fd = file.fileDescriptor
        var info = stat()
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(fd, F_GETFL) & O_ACCMODE == O_RDONLY,
              fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_size > 0, info.st_size <= 128 * 1024 * 1024,
              fcntl(fd, F_GETPATH, &path) == 0,
              URL(fileURLWithPath: String(cString: path)).standardizedFileURL.path == expectedExecutable.standardizedFileURL.path else { return nil }
        var code: SecStaticCode?
        let url = URL(fileURLWithPath: "/dev/fd/\(fd)")
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code else { return nil }
        return exactRequirement(code)
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
