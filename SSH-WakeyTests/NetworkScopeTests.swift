import XCTest
@testable import SSH_Wakey

/// Knowing an address is local is what lets the app blame the Local Network
/// permission instead of shrugging.
final class NetworkScopeTests: XCTestCase {

    func testPrivateIPv4RangesAreLocal() {
        for host in ["192.168.1.24", "192.168.1.24", "10.0.0.4", "10.255.255.255",
                     "172.16.0.1", "172.31.255.254", "169.254.3.4", "127.0.0.1"] {
            XCTAssertTrue(NetworkScope.isLocal(host), host)
        }
    }

    func testPublicIPv4IsNotLocal() {
        for host in ["8.8.8.8", "172.32.0.1", "172.15.0.1", "1.1.1.1", "93.184.216.34"] {
            XCTAssertFalse(NetworkScope.isLocal(host), host)
        }
    }

    func testBonjourAndBareNamesAreLocal() {
        XCTAssertTrue(NetworkScope.isLocal("studio.local"))
        XCTAssertTrue(NetworkScope.isLocal("Studio.Local"))
        XCTAssertTrue(NetworkScope.isLocal("studio"))
    }

    func testOrdinaryHostnamesAreNotLocal() {
        XCTAssertFalse(NetworkScope.isLocal("example.com"))
        XCTAssertFalse(NetworkScope.isLocal("build.example.internal"))
    }

    func testLinkLocalAndUniqueLocalIPv6AreLocal() {
        for host in ["::1", "fe80::1", "fe80::1%en0", "[fe80::1]", "fd00::1", "fc00::1"] {
            XCTAssertTrue(NetworkScope.isLocal(host), host)
        }
    }

    func testGlobalIPv6IsNotLocal() {
        XCTAssertFalse(NetworkScope.isLocal("2001:4860:4860::8888"))
    }

    func testEmptyInputIsNotLocal() {
        XCTAssertFalse(NetworkScope.isLocal(""))
        XCTAssertFalse(NetworkScope.isLocal("   "))
    }

    @MainActor
    func testALocalAddressThatCannotBeReachedBlamesThePermission() {
        let failure = SSHFailure(
            kind: .hostUnreachable, headline: "That machine could not be reached.",
            guidance: "Check the address.", detail: nil)

        let annotated = SSHSessionManager.annotated(
            failure, with: AskpassChannel.Outcome(), host: "192.168.1.24")

        XCTAssertTrue(annotated.suggestsLocalNetworkPermission)
        XCTAssertTrue(annotated.guidance?.contains("permission") ?? false, annotated.guidance ?? "")
        XCTAssertTrue(annotated.guidance?.contains("your own network") ?? false, annotated.guidance ?? "")
    }

    @MainActor
    func testAPublicAddressDoesNotBlameThePermission() {
        let failure = SSHFailure(
            kind: .hostUnreachable, headline: "That machine could not be reached.",
            guidance: "Check the address.", detail: nil)

        let annotated = SSHSessionManager.annotated(
            failure, with: AskpassChannel.Outcome(), host: "example.com")

        XCTAssertFalse(annotated.suggestsLocalNetworkPermission)
        XCTAssertEqual(annotated.guidance, "Check the address.")
    }

    @MainActor
    func testAnAuthenticationFailureIsNotBlamedOnThePermission() {
        let failure = SSHFailure(
            kind: .authentication, headline: "Authentication failed.",
            guidance: "Check the password.", detail: nil)

        let annotated = SSHSessionManager.annotated(
            failure, with: AskpassChannel.Outcome(), host: "192.168.1.24")

        XCTAssertFalse(annotated.suggestsLocalNetworkPermission)
    }
}
