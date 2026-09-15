import XCTest
@testable import SSH_Wakey

final class NetworkWakeTests: XCTestCase {

    func testColonMACAddressesParse() throws {
        let mac = try XCTUnwrap(NetworkWake.MACAddress(parsing: "A4:83:E7:12:34:56"))
        XCTAssertEqual(mac.colonSeparated, "a4:83:e7:12:34:56")
        XCTAssertEqual(mac.bytes, [0xA4, 0x83, 0xE7, 0x12, 0x34, 0x56])
    }

    func testHyphenAndBareHexParseTheSame() {
        let colon = NetworkWake.MACAddress(parsing: "aa:bb:cc:dd:ee:ff")
        let hyphen = NetworkWake.MACAddress(parsing: "aa-bb-cc-dd-ee-ff")
        let bare = NetworkWake.MACAddress(parsing: "AABBCCDDEEFF")
        XCTAssertEqual(colon, hyphen)
        XCTAssertEqual(colon, bare)
    }

    func testGarbageAndZeroAddressesAreRejected() {
        XCTAssertNil(NetworkWake.MACAddress(parsing: "aa:bb:cc"))
        XCTAssertNil(NetworkWake.MACAddress(parsing: "not-a-mac"))
        XCTAssertNil(NetworkWake.MACAddress(parsing: "00:00:00:00:00:00"))
        XCTAssertNil(NetworkWake.MACAddress(parsing: ""))
    }

    func testMagicPacketIsSixOnesThenSixteenCopies() throws {
        let mac = try XCTUnwrap(NetworkWake.MACAddress(parsing: "01:02:03:04:05:06"))
        let packet = mac.magicPacket
        XCTAssertEqual(packet.count, 102)
        XCTAssertEqual(Array(packet.prefix(6)), Array(repeating: UInt8(0xFF), count: 6))
        for index in 0..<16 {
            let slice = packet[(6 + index * 6)..<(12 + index * 6)]
            XCTAssertEqual(Array(slice), mac.bytes)
        }
    }

    func testARPOutputYieldsTheAddress() {
        let line = "? (192.168.22.109) at a4:83:e7:12:34:56 on en0 ifscope [ethernet]\n"
        XCTAssertEqual(
            NetworkWake.parseARPOutput(line)?.colonSeparated,
            "a4:83:e7:12:34:56")
    }

    func testIncompleteARPIsIgnored() {
        let line = "? (192.168.22.109) at (incomplete) on en0 ifscope [ethernet]\n"
        XCTAssertNil(NetworkWake.parseARPOutput(line))
    }

    func testPrivateIPv4GetsASubnetBroadcast() {
        XCTAssertEqual(NetworkWake.subnetBroadcast(forIPv4: "192.168.22.109"), "192.168.22.255")
        XCTAssertEqual(NetworkWake.subnetBroadcast(forIPv4: "10.4.5.6"), "10.255.255.255")
        XCTAssertNil(NetworkWake.subnetBroadcast(forIPv4: "8.8.8.8"))
    }

    func testALocalHostIsWorthPokingEvenWithoutAStoredMAC() {
        XCTAssertTrue(NetworkWake.shouldPoke(host: "192.168.22.109", hardwareAddress: nil))
        XCTAssertTrue(NetworkWake.shouldPoke(host: "mini.local", hardwareAddress: nil))
        XCTAssertFalse(NetworkWake.shouldPoke(host: "example.com", hardwareAddress: nil))
        XCTAssertTrue(NetworkWake.shouldPoke(
            host: "example.com", hardwareAddress: "aa:bb:cc:dd:ee:ff"))
    }
}
