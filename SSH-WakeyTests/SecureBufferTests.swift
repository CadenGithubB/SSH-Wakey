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

    func testMultiByteCharactersSurviveIntact() {
        let password = "pässwörd–✓"
        let buffer = SecureBuffer(password)
        let bytes = buffer.withBytes { Array($0) }
        XCTAssertEqual(String(decoding: bytes ?? [], as: UTF8.self), password)
    }
}
