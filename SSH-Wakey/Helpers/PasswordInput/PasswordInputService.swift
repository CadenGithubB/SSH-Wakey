import AppKit
import Darwin
import Foundation
import Security

final class PasswordInputListener: NSObject, NSXPCListenerDelegate {
    private var accepted = false
    private let lock = NSLock()
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !accepted, connection.effectiveUserIdentifier == getuid(),
              let adapter = ProcessIdentity.read(connection.processIdentifier), adapter.uid == getuid(),
              let ssh = ProcessIdentity.read(adapter.parent), ssh.isAppleSSH else { return false }
        accepted = true
        connection.exportedInterface = NSXPCInterface(with: PasswordInputProtocol.self)
        connection.exportedObject = PasswordInputService(connection: connection, adapter: adapter)
        // Loss of the adapter destroys the entire secret-owning process.
        connection.invalidationHandler = { exit(1) }
        connection.interruptionHandler = { exit(1) }
        connection.resume()
        return true
    }
}

final class PasswordInputService: NSObject, PasswordInputProtocol {
    private let connection: NSXPCConnection
    private let adapter: ProcessIdentity
    private var prepared = false
    private var consumed = false
    private let lock = NSLock()
    private let adapterBundle = HelperLayout.enclosingBundle(of: Bundle.main.bundleURL)
    init(connection: NSXPCConnection, adapter: ProcessIdentity) {
        self.connection = connection; self.adapter = adapter
    }
    static var hasExpectedSandbox: Bool {
        var own: SecCode?, code: SecStaticCode?, info: CFDictionary?
        guard SecCodeCopySelf([], &own) == errSecSuccess, let own,
              SecCodeCopyStaticCode(own, [], &code) == errSecSuccess, let code,
              SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let values = info as? [String: Any],
              let entitlements = values[kSecCodeInfoEntitlementsDict as String] as? [String: Any]
        else { return false }
        // No network, file, group, inheritance, debugging or exception entitlement.
        return entitlements.count == 1 && (entitlements["com.apple.security.app-sandbox"] as? Bool) == true
    }
    func prepare(_ adapterCode: FileHandle, reply: @escaping (Bool) -> Void) {
        lock.lock(); defer { lock.unlock() }
        guard !prepared, !consumed, adapter.isCurrent,
              URL(fileURLWithPath: adapter.path).standardizedFileURL.path == HelperLayout.executable(in: adapterBundle, name: HelperLayout.adapterName).standardizedFileURL.path,
              let requirement = HelperIdentity.requirement(from: adapterCode,
                expectedExecutable: HelperLayout.executable(in: adapterBundle, name: HelperLayout.adapterName))
        else { reply(false); return }
        connection.setCodeSigningRequirement(requirement)
        prepared = true
        reply(true)
    }
    func collect(_ channel: FileHandle, output: FileHandle, appCode: FileHandle,
                 appInfo: Data, grant text: String, reply: @escaping (Bool) -> Void) {
        guard let (grant, server) = validate(channel, output: output, appCode: appCode, appInfo: appInfo, grant: text)
        else { finish(false, reply: reply); return }
        DispatchQueue.main.async {
            let authorization = PasswordAuthorization(channel: channel, grant: grant, server: server, adapter: self.adapter)
            guard authorization.isValid, let answer = PasswordPromptView.collect(authorization: authorization) else {
                _ = AskpassProtocol.sendLine("cancelled", to: channel.fileDescriptor)
                self.finish(false, reply: reply)
                return
            }
            guard authorization.isValid,
                  AskpassProtocol.sendLine("ready", to: channel.fileDescriptor),
                  AskpassProtocol.readLine(from: channel.fileDescriptor) == "send", authorization.isValid else {
                answer.wipe(); self.finish(false, reply: reply); return
            }
            alarm(3)
            let wrote = answer.withBytes { AskpassProtocol.writeAll(output.fileDescriptor, $0) } ?? false
            answer.wipe()
            var newline: UInt8 = 10
            let ended = wrote && withUnsafeBytes(of: &newline) { AskpassProtocol.writeAll(output.fileDescriptor, $0) }
            if ended { _ = AskpassProtocol.sendLine("sent", to: channel.fileDescriptor) }
            self.finish(ended, reply: reply)
        }
    }
    private func validate(_ channel: FileHandle, output: FileHandle, appCode: FileHandle,
                          appInfo: Data, grant text: String) -> (AskpassProtocol.Grant, ProcessIdentity)? {
        lock.lock()
        let allowed = prepared && !consumed
        consumed = true
        lock.unlock()
        guard allowed, adapter.isCurrent, text.utf8.count < AskpassProtocol.maxRequestBytes,
              let grant = AskpassProtocol.decode(AskpassProtocol.Grant.self, text),
              grant.context.destination.utf8.count <= 1024, grant.context.action.utf8.count <= 128,
              grant.ssh.isAppleSSH, adapter.parent == grant.ssh.pid,
              grant.expiresAt > ProcessInfo.processInfo.systemUptime,
              grant.expiresAt <= ProcessInfo.processInfo.systemUptime + AskpassProtocol.promptLifetime + 1,
              let server = ProcessIdentity.peer(on: channel.fileDescriptor), server.pid == grant.ssh.parent,
              let requirement = HelperIdentity.requirement(from: appCode,
                expectedExecutable: HelperLayout.executable(in: HelperLayout.enclosingBundle(of: adapterBundle),
                                                            name: HelperLayout.appName)),
              HelperIdentity.peer(on: channel.fileDescriptor, matches: requirement, infoPlist: appInfo),
              Self.isWritablePipe(output.fileDescriptor) else { return nil }
        return (grant, server)
    }
    #if DEBUG
    /// Synthetic negative-access audit, compiled out of every release build.
    /// It has the same caller/grant checks and cannot display a password field.
    func probe(_ channel: FileHandle, output: FileHandle, appCode: FileHandle,
               appInfo: Data, grant: String, fixture: String, reply: @escaping (String) -> Void) {
        guard validate(channel, output: output, appCode: appCode, appInfo: appInfo, grant: grant) != nil,
              fixture.utf8.count < 2048 else { reply("SSHWAKEY_SANDBOX_INVALID"); return }
        func deniedFile(_ path: String, flags: Int32) -> Bool {
            let fd = open(path, flags); let error = errno
            if fd >= 0 { close(fd) }
            return fd < 0 && (error == EPERM || error == EACCES)
        }
        func deniedNetwork(_ family: Int32, type: Int32) -> Bool {
            let fd = socket(family, type, 0)
            if fd < 0 { return errno == EPERM || errno == EACCES }
            defer { close(fd) }
            var v4 = sockaddr_in(); v4.sin_family = sa_family_t(AF_INET)
            v4.sin_port = UInt16(9).bigEndian; v4.sin_addr.s_addr = inet_addr("127.0.0.1")
            var v6 = sockaddr_in6(); v6.sin6_family = sa_family_t(AF_INET6)
            v6.sin6_port = UInt16(9).bigEndian; v6.sin6_addr = in6addr_loopback
            func attempt<T>(_ address: inout T) -> Int32 {
                withUnsafePointer(to: &address) { pointer in
                    pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        connect(fd, $0, socklen_t(MemoryLayout<T>.size))
                    }
                }
            }
            let result = family == AF_INET ? attempt(&v4) : attempt(&v6)
            return result < 0 && (errno == EPERM || errno == EACCES)
        }
        let unix = socket(AF_UNIX, SOCK_STREAM, 0)
        let unixResult = try? AskpassProtocol.withSocketAddress(path: URL(fileURLWithPath: fixture)
            .deletingLastPathComponent().appendingPathComponent("0/ask").path) { connect(unix, $0, $1) }
        let unixDenied = unixResult == -1 && (errno == EPERM || errno == EACCES)
        if unix >= 0 { close(unix) }
        let checks = [deniedFile(fixture, flags: O_RDONLY), deniedFile(fixture, flags: O_WRONLY),
            deniedFile(HelperLayout.executable(in: adapterBundle, name: HelperLayout.adapterName).path, flags: O_WRONLY),
            deniedNetwork(AF_INET, type: SOCK_STREAM), deniedNetwork(AF_INET6, type: SOCK_STREAM),
            deniedNetwork(AF_INET, type: SOCK_DGRAM), unixDenied,
            !HelperIdentity.peer(on: channel.fileDescriptor, matches: "cdhash H\"0000000000000000000000000000000000000000\"", infoPlist: appInfo),
            !HelperIdentity.peer(on: channel.fileDescriptor, matches: HelperIdentity.requirement(from: appCode,
                expectedExecutable: HelperLayout.executable(in: HelperLayout.enclosingBundle(of: adapterBundle), name: HelperLayout.appName)) ?? "false",
                infoPlist: Data("invalid signed plist".utf8))]
        let allowedChannel = AskpassProtocol.sendLine("ready", to: channel.fileDescriptor)
            && AskpassProtocol.readLine(from: channel.fileDescriptor) == "send"
        let allowedPipe = allowedChannel && Data("sandbox-probe\n".utf8).withUnsafeBytes {
            AskpassProtocol.writeAll(output.fileDescriptor, $0)
        }
        if allowedPipe { _ = AskpassProtocol.sendLine("sent", to: channel.fileDescriptor) }
        reply(checks.allSatisfy { $0 } && allowedPipe ? "SSHWAKEY_SANDBOX_OK" : "SSHWAKEY_SANDBOX_FAILED \(checks) channel=\(allowedChannel) pipe=\(allowedPipe)")
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) { exit(0) }
    }
    #endif
    private static func isWritablePipe(_ fd: Int32) -> Bool {
        var info = stat()
        return fstat(fd, &info) == 0 && info.st_mode & S_IFMT == S_IFIFO
            && fcntl(fd, F_GETFL) & O_ACCMODE == O_WRONLY
    }
    private func finish(_ sent: Bool, reply: @escaping (Bool) -> Void) {
        reply(sent)
        // Allow the nonsecret reply to leave, then destroy AppKit/Swift heap copies.
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) { exit(sent ? 0 : 1) }
    }
}
