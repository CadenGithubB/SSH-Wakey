import Foundation

/// Works out whether a destination only exists on the local network.
///
/// macOS gates local network access behind a privacy permission, and when that
/// permission is missing a connection fails in the same way as a machine that
/// is switched off. Knowing the address is local is what lets the app offer the
/// right advice instead of a generic "could not be reached".
enum NetworkScope {

    static func isLocal(_ host: String) -> Bool {
        let trimmed = host
            .trimmingCharacters(in: .whitespaces)
            .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            .lowercased()
        guard !trimmed.isEmpty else { return false }

        // Bonjour names, and bare names with no dots, are resolved on the link.
        if trimmed.hasSuffix(".local") { return true }
        if !trimmed.contains(".") && !trimmed.contains(":") { return true }

        if let octets = ipv4Octets(trimmed) { return isPrivateIPv4(octets) }
        if trimmed.contains(":") { return isLocalIPv6(trimmed) }
        return false
    }

    static func ipv4Octets(_ host: String) -> [Int]? {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        let octets = parts.compactMap { Int($0) }
        guard octets.count == 4, octets.allSatisfy({ (0...255).contains($0) }) else { return nil }
        return octets
    }

    /// RFC 1918 private ranges, link-local, and loopback.
    static func isPrivateIPv4(_ octets: [Int]) -> Bool {
        switch octets[0] {
        case 10, 127: return true
        case 172: return (16...31).contains(octets[1])
        case 192: return octets[1] == 168
        case 169: return octets[1] == 254
        default: return false
        }
    }

    /// Loopback, link-local (fe80::/10) and unique local (fc00::/7).
    static func isLocalIPv6(_ host: String) -> Bool {
        let address = host.split(separator: "%").first.map(String.init) ?? host
        if address == "::1" { return true }
        if address.hasPrefix("fe8") || address.hasPrefix("fe9")
            || address.hasPrefix("fea") || address.hasPrefix("feb") { return true }
        if address.hasPrefix("fc") || address.hasPrefix("fd") { return true }
        return false
    }
}
