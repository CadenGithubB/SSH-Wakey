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

    func testMultiByteCharactersSurviveIntact() {
        let password = "pässwörd–✓"
        let buffer = SecureBuffer(password)
        let bytes = buffer.withBytes { Array($0) }
        XCTAssertEqual(String(decoding: bytes ?? [], as: UTF8.self), password)
    }
}
