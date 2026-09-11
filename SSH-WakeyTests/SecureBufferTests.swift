import XCTest
@testable import SSH_Wakey

final class SecureBufferTests: XCTestCase {

    func testTheBytesAreTheUTF8OfTheString() {
        let buffer = SecureBuffer("hunter2")
        let bytes = buffer.withBytes { Array($0) }
        XCTAssertEqual(bytes, Array("hunter2".utf8))
    }

    func testWipingClearsTheContents() {
        let buffer = SecureBuffer("hunter2")
        XCTAssertFalse(buffer.isEmpty)

        buffer.wipe()
        XCTAssertTrue(buffer.isEmpty)
        XCTAssertNil(buffer.withBytes { Array($0) })
    }

    func testWipingTwiceIsHarmless() {
        let buffer = SecureBuffer("hunter2")
        buffer.wipe()
        buffer.wipe()
        XCTAssertTrue(buffer.isEmpty)
    }

    func testAnEmptyPasswordIsHandled() {
        let buffer = SecureBuffer("")
        XCTAssertTrue(buffer.isEmpty)
        buffer.wipe()
    }

    /// The plaintext should never be eligible to be written to swap.
    func testThePasswordPagesArePinnedInMemory() {
        let buffer = SecureBuffer("hunter2")
        XCTAssertTrue(buffer.isMemoryLocked, "mlock should succeed for a buffer this small")

        buffer.wipe()
        XCTAssertFalse(buffer.isMemoryLocked, "the pages must be released along with the memory")
    }

    // MARK: - Filled in place

    /// The helper reads the password a chunk at a time. A growing Array would
    /// copy itself on each reallocation and free the old block without
    /// overwriting it, scattering stale plaintext through the heap.
    func testABufferCanBeFilledInPlaceWithoutGrowing() {
        let buffer = SecureBuffer(capacity: 64)
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

    func testAFullBufferOffersNoMoreSpace() {
        let buffer = SecureBuffer(capacity: 4)
        buffer.advance(by: 4)
        XCTAssertNil(buffer.withFreeSpace { $0.count })
        XCTAssertEqual(buffer.byteCount, 4)
    }

    func testAdvancingPastTheEndIsClamped() {
        let buffer = SecureBuffer(capacity: 8)
        buffer.advance(by: 1_000)
        XCTAssertEqual(buffer.byteCount, 8)
    }

    func testAFilledBufferWipesLikeAnyOther() {
        let buffer = SecureBuffer(capacity: 32)
        buffer.advance(by: 10)
        buffer.wipe()

        XCTAssertTrue(buffer.isEmpty)
        XCTAssertNil(buffer.withBytes { Array($0) })
        XCTAssertNil(buffer.withFreeSpace { $0.count })
        XCTAssertFalse(buffer.isMemoryLocked)
    }

    func testMultiByteCharactersSurviveIntact() {
        let password = "pässwörd–✓"
        let buffer = SecureBuffer(password)
        let bytes = buffer.withBytes { Array($0) }
        XCTAssertEqual(String(decoding: bytes ?? [], as: UTF8.self), password)
    }
}
