import CryptoKit
import XCTest
@testable import SSH_Wakey

/// Touches the real login keychain, under a throwaway account name that is
/// removed again afterwards.
final class KeychainKeyStoreTests: XCTestCase {

    private var account: String!

    override func setUpWithError() throws {
        account = "test-\(UUID().uuidString)"
    }

    override func tearDownWithError() throws {
        try? KeychainKeyStore.delete(account: account)
    }

    func testNothingIsStoredToBeginWith() throws {
        XCTAssertNil(try KeychainKeyStore.load(account: account))
    }

    func testAKeySurvivesASaveAndLoad() throws {
        let key = KeychainKeyStore.makeKey()
        try KeychainKeyStore.save(key, account: account)

        let loaded = try XCTUnwrap(try KeychainKeyStore.load(account: account))
        XCTAssertEqual(loaded, key)
    }

    func testSavingTwiceReplacesRatherThanDuplicates() throws {
        try KeychainKeyStore.save(KeychainKeyStore.makeKey(), account: account)
        let replacement = KeychainKeyStore.makeKey()
        try KeychainKeyStore.save(replacement, account: account)

        XCTAssertEqual(try KeychainKeyStore.load(account: account), replacement)
    }

    func testDeletingLeavesNothingBehind() throws {
        try KeychainKeyStore.save(KeychainKeyStore.makeKey(), account: account)
        try KeychainKeyStore.delete(account: account)

        XCTAssertNil(try KeychainKeyStore.load(account: account))
    }

    func testDeletingSomethingThatIsNotThereIsNotAnError() {
        XCTAssertNoThrow(try KeychainKeyStore.delete(account: account))
    }

    func testTheGeneratedKeyIsTheRightSizeAndNotPredictable() {
        let first = KeychainKeyStore.makeKey()
        let second = KeychainKeyStore.makeKey()
        XCTAssertEqual(first.bitCount, 256)
        XCTAssertNotEqual(first, second)
    }
}
