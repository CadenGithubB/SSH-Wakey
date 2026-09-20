import XCTest
@testable import SSH_Wakey

final class SecureBufferTests: XCTestCase {

    func testInvalidCapacitiesAreRejectedBeforeAllocationOrArithmetic() {
        for capacity in [0, -1, Int.max, SecureBuffer.maximumCapacity + 1] {
            XCTAssertThrowsError(try SecureBuffer(capacity: capacity)) {
                XCTAssertEqual($0 as? SecureBuffer.BufferError, .invalidCapacity)
            }
        }
    }

    func testTheOwnedAllocationIsPageAligned() throws {
        let buffer = try SecureBuffer("fixture")
        XCTAssertEqual(buffer.withBytes { UInt(bitPattern: $0.baseAddress!) % UInt(getpagesize()) }, 0)
    }

    func testNegativeAdvanceDoesNotMoveTheBufferBackwards() throws {
        let buffer = try SecureBuffer("fixture")
        buffer.advance(by: -100)
        XCTAssertEqual(buffer.byteCount, 7)
    }

    func testTheBytesAreTheUTF8OfTheString() throws {
        let buffer = try SecureBuffer("hunter2")
        let bytes = buffer.withBytes { Array($0) }
        XCTAssertEqual(bytes, Array("hunter2".utf8))
    }

    func testWipingClearsTheContents() throws {
        let buffer = try SecureBuffer("hunter2")
        XCTAssertFalse(buffer.isEmpty)

        buffer.wipe()
        XCTAssertTrue(buffer.isEmpty)
        XCTAssertNil(buffer.withBytes { Array($0) })
    }

    func testWipingTwiceIsHarmless() throws {
        let buffer = try SecureBuffer("hunter2")
        buffer.wipe()
        buffer.wipe()
        XCTAssertTrue(buffer.isEmpty)
    }

    func testAnEmptyPasswordIsHandled() throws {
        let buffer = try SecureBuffer("")
        XCTAssertTrue(buffer.isEmpty)
        buffer.wipe()
    }

    /// The bytes owned by this buffer must not be eligible for swap.
    func testThePasswordPagesArePinnedInMemory() throws {
        let buffer = try SecureBuffer("hunter2")
        XCTAssertTrue(buffer.isMemoryLocked, "mlock should succeed for a buffer this small")

        buffer.wipe()
        XCTAssertFalse(buffer.isMemoryLocked, "the pages must be released along with the memory")
    }

    // MARK: - Filled in place

    /// Controlled storage can be filled in place. A growing Array would
    /// copy itself on each reallocation and free the old block without
    /// overwriting it, scattering stale plaintext through the heap.
    func testABufferCanBeFilledInPlaceWithoutGrowing() throws {
        let buffer = try SecureBuffer(capacity: 64)
        XCTAssertTrue(buffer.isEmpty)
        XCTAssertEqual(buffer.byteCount, 0)
        XCTAssertTrue(buffer.isMemoryLocked)

        for piece in ["hun", "ter", "2"] {
            let written = buffer.withFreeSpace { space -> Int in
                let bytes = Array(piece.utf8)
                space.copyBytes(from: bytes)
                return bytes.count
            }
            buffer.advance(by: try! XCTUnwrap(written))
        }

        XCTAssertEqual(buffer.byteCount, 7)
        XCTAssertEqual(String(decoding: buffer.withBytes { Array($0) } ?? [], as: UTF8.self), "hunter2")
    }

    func testAFullBufferOffersNoMoreSpace() throws {
        let buffer = try SecureBuffer(capacity: 4)
        buffer.advance(by: 4)
        XCTAssertNil(buffer.withFreeSpace { $0.count })
        XCTAssertEqual(buffer.byteCount, 4)
    }

    func testAdvancingPastTheEndIsClamped() throws {
        let buffer = try SecureBuffer(capacity: 8)
        buffer.advance(by: 1_000)
        XCTAssertEqual(buffer.byteCount, 8)
    }

    func testAFilledBufferWipesLikeAnyOther() throws {
        let buffer = try SecureBuffer(capacity: 32)
        buffer.advance(by: 10)
        buffer.wipe()

        XCTAssertTrue(buffer.isEmpty)
        XCTAssertNil(buffer.withBytes { Array($0) })
        XCTAssertNil(buffer.withFreeSpace { $0.count })
        XCTAssertFalse(buffer.isMemoryLocked)
    }

    func testMultiByteCharactersSurviveIntact() throws {
        let password = "pässwörd–✓"
        let buffer = try SecureBuffer(password)
        let bytes = buffer.withBytes { Array($0) }
        XCTAssertEqual(String(decoding: bytes ?? [], as: UTF8.self), password)
    }
}
