import Darwin
import Foundation

/// Owns bounded page-aligned memory. Cocoa input and cryptographic framework
/// storage remain outside this owner. Failure to lock memory is an error.
final class SecureBuffer: @unchecked Sendable {
    enum BufferError: LocalizedError, Equatable {
        case invalidCapacity, allocationFailed, memoryLockFailed
        var errorDescription: String? {
            switch self {
            case .invalidCapacity: return "The secret exceeds the supported size."
            case .allocationFailed: return "Could not allocate protected memory."
            case .memoryLockFailed: return "Could not lock protected memory. No password was sent."
            }
        }
    }

    static let maximumCapacity = 1_048_576
    private var base: UnsafeMutableRawPointer?
    private var mappedSize = 0
    private var capacity = 0
    private var count = 0
    private let lock = NSLock()

    convenience init(_ string: String) throws {
        let length = string.utf8.count
        try self.init(capacity: max(length, 1))
        // Iterate the existing UTF-8 view without making a plaintext Array.
        withFreeSpace { bytes in
            var offset = 0
            for byte in string.utf8 { bytes[offset] = byte; offset += 1 }
        }
        advance(by: length)
    }

    init(capacity: Int) throws {
        guard capacity > 0, capacity <= Self.maximumCapacity else { throw BufferError.invalidCapacity }
        let page = Int(getpagesize())
        let length = ((capacity + page - 1) / page) * page
        guard let pointer = mmap(nil, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0),
              pointer != MAP_FAILED else { throw BufferError.allocationFailed }
        guard mlock(pointer, length) == 0 else {
            munmap(pointer, length)
            throw BufferError.memoryLockFailed
        }
        self.base = pointer
        self.mappedSize = length
        self.capacity = capacity
    }

    var isMemoryLocked: Bool { lock.lock(); defer { lock.unlock() }; return base != nil }
    var byteCount: Int { lock.lock(); defer { lock.unlock() }; return count }
    var isEmpty: Bool { lock.lock(); defer { lock.unlock() }; return count == 0 }

    func withFreeSpace<R>(_ body: (UnsafeMutableRawBufferPointer) throws -> R) rethrows -> R? {
        lock.lock(); defer { lock.unlock() }
        guard let base, count < capacity else { return nil }
        return try body(UnsafeMutableRawBufferPointer(start: base.advanced(by: count), count: capacity - count))
    }

    func advance(by written: Int) {
        lock.lock(); defer { lock.unlock() }
        count += min(max(written, 0), capacity - count)
    }

    func withBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R? {
        lock.lock(); defer { lock.unlock() }
        guard let base else { return nil }
        return try body(UnsafeRawBufferPointer(start: base, count: count))
    }

    func wipe() {
        lock.lock(); defer { lock.unlock() }
        guard let pointer = base else { return }
        memset_s(pointer, mappedSize, 0, mappedSize)
        munlock(pointer, mappedSize)
        munmap(pointer, mappedSize)
        base = nil
        count = 0
        capacity = 0
        mappedSize = 0
    }

    deinit { wipe() }
}
