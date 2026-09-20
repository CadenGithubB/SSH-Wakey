import Darwin
import Foundation

/// Out-of-band poke for a sleeping Mac, then SSH can talk to it.
///
/// A sleeping NIC will not complete a TCP handshake on port 22. It will notice
/// a Wake-on-LAN magic packet, and a Bonjour sleep proxy will send that packet
/// when something looks up a `.local` name. This type does those two things.
/// It does not speak Apple Remote Desktop.
enum NetworkWake {

    /// How long to wait after a poke for the machine to dark-wake.
    static let settleNanoseconds: UInt64 = 3_000_000_000

    /// Six-byte Ethernet address used as the Wake-on-LAN target.
    struct MACAddress: Equatable, Sendable {
        let bytes: [UInt8]

        /// Accepts `aa:bb:cc:dd:ee:ff`, hyphens, or 12 bare hex digits.
        init?(parsing raw: String) {
            let hex = raw.lowercased().filter(\.isHexDigit)
            guard hex.count == 12 else { return nil }
            var parsed: [UInt8] = []
            parsed.reserveCapacity(6)
            var index = hex.startIndex
            while index < hex.endIndex {
                let next = hex.index(index, offsetBy: 2)
                guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
                parsed.append(byte)
                index = next
            }
            guard parsed.count == 6, parsed.contains(where: { $0 != 0 }) else { return nil }
            bytes = parsed
        }

        var colonSeparated: String {
            bytes.map { String(format: "%02x", $0) }.joined(separator: ":")
        }

        /// 6 × `0xFF`, then the MAC repeated 16 times.
        var magicPacket: Data {
            var packet = Data(repeating: 0xFF, count: 6)
            let mac = Data(bytes)
            for _ in 0..<16 { packet.append(mac) }
            return packet
        }
    }

    /// True when a poke is worth doing before SSH: the destination is on the
    /// local network, or we already learned a hardware address for it.
    static func shouldPoke(host: String, hardwareAddress: String?) -> Bool {
        MACAddress(parsing: hardwareAddress ?? "") != nil || NetworkScope.isLocal(host)
    }

    /// Best-effort wake: magic packet if we have a MAC, and a name lookup if
    /// the host is not a bare IPv4 address (so a sleep proxy can see it).
    static func poke(host: String, hardwareAddress: String?) async {
        guard !Task.isCancelled else { return }
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        let ipv4 = NetworkScope.ipv4Octets(trimmed).map {
            $0.map(String.init).joined(separator: ".")
        }

        var mac = MACAddress(parsing: hardwareAddress ?? "")
        if mac == nil, let ipv4 {
            mac = await linkAddress(forIPv4: ipv4)
        }

        guard !Task.isCancelled else { return }

        if let mac {
            sendMagicPacket(mac, directedIPv4: ipv4)
        }

        if ipv4 == nil {
            _ = await resolvedIPv4Addresses(trimmed)
        }
    }

    /// Reads the ARP table for a successful TCP peer so the next attempt can
    /// send a magic packet without asking the person for a MAC address.
    static func learnedAddress(for host: String) async -> String? {
        guard !Task.isCancelled else { return nil }
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        let ipv4: String
        if let octets = NetworkScope.ipv4Octets(trimmed) {
            ipv4 = octets.map(String.init).joined(separator: ".")
        } else if let first = await resolvedIPv4Addresses(trimmed).first {
            ipv4 = first
        } else {
            return nil
        }
        guard !Task.isCancelled else { return nil }
        return await linkAddress(forIPv4: ipv4)?.colonSeparated
    }

    static func parseARPOutput(_ text: String) -> MACAddress? {
        if text.localizedCaseInsensitiveContains("incomplete") { return nil }
        for line in text.split(whereSeparator: \.isNewline) {
            let parts = line.split(whereSeparator: \.isWhitespace).map(String.init)
            guard let at = parts.firstIndex(of: "at"), at + 1 < parts.count else { continue }
            return MACAddress(parsing: parts[at + 1])
        }
        return nil
    }

    static func subnetBroadcast(forIPv4 ipv4: String) -> String? {
        guard let octets = NetworkScope.ipv4Octets(ipv4), octets.count == 4 else { return nil }
        switch octets[0] {
        case 10:
            return "10.255.255.255"
        case 172 where (16...31).contains(octets[1]):
            return "172.\(octets[1]).255.255"
        case 192 where octets[1] == 168:
            return "192.168.\(octets[2]).255"
        default:
            return nil
        }
    }

    // MARK: - Transport

    private static func linkAddress(forIPv4 ipv4: String) async -> MACAddress? {
        let result = try? await ProcessRunner.run(
            executable: "/usr/sbin/arp",
            arguments: ["-n", ipv4],
            timeout: 3)
        guard let result, !Task.isCancelled, !result.timedOut, !result.outputLimitExceeded else { return nil }
        return parseARPOutput(result.standardOutput)
            ?? parseARPOutput(result.standardError)
    }

    /// getaddrinfo can block inside the system resolver. Run it off the UI and
    /// Swift cooperative executors, and resume the caller on timeout/cancel.
    /// The OS call itself cannot safely be interrupted, so at most two lookups
    /// may remain outstanding; late answers lose the single-completion race.
    private static let resolverSlots = DispatchSemaphore(value: 2)

    static func resolvedIPv4Addresses(
        _ host: String,
        timeout: TimeInterval = 3,
        lookup: @escaping @Sendable (String) -> [String] = { lookupIPv4Addresses($0) }
    ) async -> [String] {
        guard !Task.isCancelled, timeout > 0 else { return [] }
        let limit = timeout.isFinite ? min(timeout, 3) : 3
        let result = ResolutionResult()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                result.install(continuation)
                guard !Task.isCancelled, !result.hasCompleted else {
                    result.complete([])
                    return
                }
                guard resolverSlots.wait(timeout: .now()) == .success else {
                    result.complete([])
                    return
                }
                DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + limit) {
                    result.complete([])
                }
                DispatchQueue.global(qos: .utility).async {
                    defer { resolverSlots.signal() }
                    guard !result.hasCompleted else { return }
                    result.complete(lookup(host))
                }
            }
        } onCancel: {
            result.complete([])
        }
    }

    /// Synchronous work is private to the bounded resolver worker above.
    static func lookupIPv4Addresses(_ host: String) -> [String] {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_DGRAM
        var info: UnsafeMutablePointer<addrinfo>?
        let status = host.withCString { getaddrinfo($0, nil, &hints, &info) }
        guard status == 0, let first = info else { return [] }
        defer { freeaddrinfo(first) }

        var addresses: [String] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let current = cursor {
            if current.pointee.ai_family == AF_INET,
               let addr = current.pointee.ai_addr {
                addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { pointer in
                    var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                    var ip = pointer.pointee.sin_addr
                    inet_ntop(AF_INET, &ip, &buffer, socklen_t(INET_ADDRSTRLEN))
                    let text = String(cString: buffer)
                    if !text.isEmpty, !addresses.contains(text) {
                        addresses.append(text)
                    }
                }
            }
            cursor = current.pointee.ai_next
        }
        return addresses
    }

    private final class ResolutionResult: @unchecked Sendable {
        private let lock = NSLock()
        private var completed: [String]?
        private var continuation: CheckedContinuation<[String], Never>?

        var hasCompleted: Bool {
            lock.lock(); defer { lock.unlock() }
            return completed != nil
        }

        func install(_ continuation: CheckedContinuation<[String], Never>) {
            lock.lock()
            if let value = completed {
                lock.unlock()
                continuation.resume(returning: value)
            } else {
                self.continuation = continuation
                lock.unlock()
            }
        }

        func complete(_ value: [String]) {
            lock.lock()
            guard completed == nil else { lock.unlock(); return }
            completed = value
            let waiting = continuation
            continuation = nil
            lock.unlock()
            waiting?.resume(returning: value)
        }
    }

    static func sendMagicPacket(_ mac: MACAddress, directedIPv4: String?) {
        let packet = mac.magicPacket
        var destinations: [String] = ["255.255.255.255"]
        if let directedIPv4 {
            destinations.append(directedIPv4)
            if let broadcast = subnetBroadcast(forIPv4: directedIPv4) {
                destinations.append(broadcast)
            }
        }
        for address in destinations {
            sendUDP(packet, to: address, port: 9)
            sendUDP(packet, to: address, port: 7)
        }
    }

    private static func sendUDP(_ packet: Data, to address: String, port: UInt16) {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { return }
        defer { close(fd) }

        var broadcast: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &broadcast, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        let parsed = address.withCString { inet_pton(AF_INET, $0, &addr.sin_addr) }
        guard parsed == 1 else { return }

        packet.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            withUnsafePointer(to: &addr) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sock in
                    _ = sendto(fd, base, packet.count, 0, sock, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
    }
}
