import Foundation

/// A heap buffer for a password that is overwritten with zeros as soon as the
/// connection attempt ends.
///
/// Swift's `String` cannot be wiped: its storage is immutable, reference
/// counted and may already have been copied by the time we see it. So the
/// password is copied into raw memory we own the moment it leaves the text
/// field, the text binding is cleared, and this buffer is what the rest of the
/// app passes around. SECURITY.md documents the residual limitation.
final class SecureBuffer: @unchecked Sendable {

    private var base: UnsafeMutableRawPointer?
    private var allocated: Int = 0
    private var count: Int = 0
    private let lock = NSLock()

    init(_ string: String) {
        var bytes = Array(string.utf8)
        allocated = max(bytes.count, 1)
        let pointer = UnsafeMutableRawPointer.allocate(byteCount: allocated, alignment: 1)
        bytes.withUnsafeBytes { source in
            if let sourceBase = source.baseAddress, source.count > 0 {
                pointer.copyMemory(from: sourceBase, byteCount: source.count)
            }
        }
        base = pointer
        count = bytes.count
        // Wipe the intermediate copy too. The original String is beyond reach.
        bytes.withUnsafeMutableBytes { buffer in
            if let address = buffer.baseAddress, buffer.count > 0 {
                memset_s(address, buffer.count, 0, buffer.count)
            }
        }
        bytes.removeAll(keepingCapacity: false)
    }

    var isEmpty: Bool {
        lock.lock(); defer { lock.unlock() }
        return base == nil || count == 0
    }

    /// Gives temporary access to the raw bytes. Returns nil once wiped.
    func withBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R? {
        lock.lock(); defer { lock.unlock() }
        guard let base else { return nil }
        return try body(UnsafeRawBufferPointer(start: base, count: count))
    }

    /// Overwrites the bytes and frees them. Safe to call more than once.
    func wipe() {
        lock.lock(); defer { lock.unlock() }
        guard let pointer = base else { return }
        memset_s(pointer, allocated, 0, allocated)
        pointer.deallocate()
        base = nil
        count = 0
        allocated = 0
    }

    deinit { wipe() }
}
