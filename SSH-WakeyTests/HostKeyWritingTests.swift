import Darwin
import XCTest
@testable import SSH_Wakey

final class HostKeyWritingTests: XCTestCase {
    private var directory: URL!
    private var knownHosts: URL!
    private let realLine = "192.168.1.24 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH1kL2PmQk8vB3nZxq7cTfW5aYh0jRsGpXeMvNbUdOiK"

    override func setUpWithError() throws {
        directory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("SSH-WakeyHostKeys-\(UUID().uuidString)", isDirectory: true)
        try ProtectedFile.createPrivateDirectory(at: directory)
        knownHosts = directory.appendingPathComponent("known_hosts")
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: directory) }

    private func key(_ line: String? = nil) throws -> HostKeyCandidate {
        try XCTUnwrap(HostKeyService.candidate(for: line ?? realLine))
    }

    private func write(_ text: String, to url: URL? = nil) throws {
        try ProtectedFile.write(Data(text.utf8), to: url ?? knownHosts)
    }

    private var contents: String { (try? String(contentsOf: knownHosts, encoding: .utf8)) ?? "" }

    func testAddingOneVerifiedKeyCreatesPrivateFile() throws {
        try HostKeyService.trust([key()], at: knownHosts)
        XCTAssertEqual(contents, realLine + "\n")
        let attrs = try FileManager.default.attributesOfItem(atPath: knownHosts.path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }

    func testExistingDestinationsArePreserved() throws {
        let existing = realLine.replacingOccurrences(of: "192.168.1.24", with: "previous.local")
        try write(existing + "\n")
        try HostKeyService.trust([key()], at: knownHosts)
        XCTAssertEqual(contents, existing + "\n" + realLine + "\n")
    }

    func testExistingLineWithoutNewlineRemainsSeparate() throws {
        let existing = realLine.replacingOccurrences(of: "192.168.1.24", with: "previous.local")
        try write(existing)
        try HostKeyService.trust([key()], at: knownHosts)
        XCTAssertEqual(contents.split(separator: "\n").count, 2)
    }

    func testRepeatedApprovalDoesNotDuplicateKey() throws {
        try HostKeyService.trust([key()], at: knownHosts)
        try HostKeyService.trust([key()], at: knownHosts)
        XCTAssertEqual(contents, realLine + "\n")
    }

    func testApprovalCannotBlessSeveralKeysAtOnce() throws {
        XCTAssertThrowsError(try HostKeyService.trust([key(), key()], at: knownHosts))
        XCTAssertFalse(FileManager.default.fileExists(atPath: knownHosts.path))
    }

    func testChangedKeyIsNotAppendedAsTrustedAlternative() throws {
        try HostKeyService.trust([key()], at: knownHosts)
        var bytes = try XCTUnwrap(Data(base64Encoded: String(realLine.split(separator: " ")[2])))
        bytes[bytes.count - 1] ^= 1
        let changed = "192.168.1.24 ssh-ed25519 \(bytes.base64EncodedString())"
        XCTAssertThrowsError(try HostKeyService.trust([key(changed)], at: knownHosts))
        XCTAssertEqual(contents, realLine + "\n")
    }

    func testFingerprintIsTiedToExactBlob() throws {
        let valid = try key()
        let forged = HostKeyCandidate(knownHostsLine: realLine, algorithm: "ED25519", bits: "256", fingerprint: "SHA256:forged")
        XCTAssertThrowsError(try HostKeyService.trust([forged], at: knownHosts))
        XCTAssertTrue(valid.fingerprint.hasPrefix("SHA256:"))
        XCTAssertFalse(valid.fingerprint.hasSuffix("="))
    }

    func testFingerprintMatchesSystemSSHKeygen() throws {
        try write(realLine + "\n")
        let result = Process()
        result.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        result.arguments = ["-l", "-f", knownHosts.path]
        let output = Pipe()
        result.standardOutput = output
        result.standardError = FileHandle.nullDevice
        try result.run()
        let text = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        result.waitUntilExit()
        XCTAssertEqual(result.terminationStatus, 0)
        XCTAssertTrue(text.contains(try key().fingerprint), text)
    }

    func testOnlySingleEd25519HostEntriesAreAccepted() {
        for host in ["mac.local", "[192.168.1.24]:2222", "::1", "[::1]:2222"] {
            XCTAssertTrue(HostKeyService.isWellFormed(realLine.replacingOccurrences(of: "192.168.1.24", with: host)))
        }
        for host in ["*", "mac.local,*", "*.example.com", "@cert-authority", "[mac.local]:0", "[mac.local]:99999"] {
            XCTAssertFalse(HostKeyService.isWellFormed(realLine.replacingOccurrences(of: "192.168.1.24", with: host)), host)
        }
        for line in ["", "host ssh-ed25519 AAAA", realLine + "\n", realLine + " comment",
                     realLine.replacingOccurrences(of: "ssh-ed25519", with: "ssh-rsa")] {
            XCTAssertFalse(HostKeyService.isWellFormed(line), line)
        }
    }

    func testSymlinkToOwnedRegularFileIsRefused() throws {
        let target = directory.appendingPathComponent("target")
        try write("", to: target)
        try FileManager.default.createSymbolicLink(at: knownHosts, withDestinationURL: target)
        XCTAssertThrowsError(try HostKeyService.trust([key()], at: knownHosts))
        XCTAssertEqual(try Data(contentsOf: target), Data())
    }

    func testSymlinkIntoWritableDestinationParentIsRefused() throws {
        let writable = directory.appendingPathComponent("writable")
        try FileManager.default.createDirectory(at: writable, withIntermediateDirectories: false)
        let target = writable.appendingPathComponent("target")
        try Data().write(to: target)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: target.path)
        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: writable.path)
        try FileManager.default.createSymbolicLink(at: knownHosts, withDestinationURL: target)
        XCTAssertThrowsError(try HostKeyService.trust([key()], at: knownHosts))
        XCTAssertEqual(try Data(contentsOf: target), Data())
    }

    func testSymlinkedParentIsRefused() throws {
        let target = directory.appendingPathComponent("target")
        try ProtectedFile.createPrivateDirectory(at: target)
        let linked = directory.appendingPathComponent("linked")
        try FileManager.default.createSymbolicLink(at: linked, withDestinationURL: target)
        XCTAssertThrowsError(try HostKeyService.trust([key()], at: linked.appendingPathComponent("known_hosts")))
    }

    func testBrokenSymlinkIsNotReplaced() throws {
        let target = directory.appendingPathComponent("missing")
        try FileManager.default.createSymbolicLink(at: knownHosts, withDestinationURL: target)
        XCTAssertThrowsError(try HostKeyService.trust([key()], at: knownHosts))
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: knownHosts.path), target.path)
    }

    func testFifoAndDirectoryAreRefused() throws {
        XCTAssertEqual(mkfifo(knownHosts.path, 0o600), 0)
        XCTAssertThrowsError(try HostKeyService.trust([key()], at: knownHosts))
        try FileManager.default.removeItem(at: knownHosts)
        try FileManager.default.createDirectory(at: knownHosts, withIntermediateDirectories: false)
        XCTAssertThrowsError(try HostKeyService.trust([key()], at: knownHosts))
    }

    func testNonPrivateModesRefuseBothTrustAndReads() throws {
        for mode in [0o644, 0o640, 0o664, 0o666] {
            try? FileManager.default.removeItem(at: knownHosts)
            try write(realLine + "\n")
            try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: knownHosts.path)
            XCTAssertThrowsError(try HostKeyService.trust([key()], at: knownHosts), String(mode))
            XCTAssertThrowsError(try HostKeyService.prepareTrustSnapshot(in: directory.appendingPathComponent("attempt"), from: knownHosts), String(mode))
        }
    }

    func testWritableParentIsRefused() throws {
        try FileManager.default.setAttributes([.posixPermissions: 0o770], ofItemAtPath: directory.path)
        XCTAssertThrowsError(try HostKeyService.trust([key()], at: knownHosts))
    }

    func testSnapshotMissingStoreIsEmptyAndStrict() throws {
        let snapshot = try HostKeyService.prepareTrustSnapshot(in: directory.appendingPathComponent("attempt"), from: knownHosts)
        XCTAssertEqual(try Data(contentsOf: snapshot), Data())
        XCTAssertFalse(FileManager.default.fileExists(atPath: knownHosts.path))
        let attrs = try FileManager.default.attributesOfItem(atPath: snapshot.path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o400)
    }

    func testSnapshotIsIndependentOfLaterStoreChanges() throws {
        try HostKeyService.trust([key()], at: knownHosts)
        let snapshot = try HostKeyService.prepareTrustSnapshot(in: directory.appendingPathComponent("attempt"), from: knownHosts)
        try write("")
        XCTAssertEqual(try String(contentsOf: snapshot, encoding: .utf8), realLine + "\n")
    }

    func testMalformedAndDuplicateStoresAreRefusedBeforeConnection() throws {
        for text in ["not a host key", realLine + "\n" + realLine + "\n", "\u{0}"] {
            try write(text)
            XCTAssertThrowsError(try HostKeyService.prepareTrustSnapshot(in: directory.appendingPathComponent("attempt"), from: knownHosts))
            XCTAssertEqual(contents, text)
        }
    }

    func testOversizedStoreIsRefusedBeforeConnection() throws {
        try ProtectedFile.write(Data(repeating: 65, count: HostKeyService.maximumStoreBytes + 1), to: knownHosts)
        XCTAssertThrowsError(try HostKeyService.prepareTrustSnapshot(in: directory.appendingPathComponent("attempt"), from: knownHosts))
    }

    func testTrustStoreIsAppSpecific() {
        XCTAssertTrue(HostKeyService.knownHostsURL.path.contains("Application Support/" + AppDistribution.supportFolderName))
        XCTAssertFalse(HostKeyService.knownHostsURL.path.contains("/.ssh/"))
    }

    func testLocalScanFailureExplainsNetworkPermission() throws {
        let message = try XCTUnwrap(HostKeyService.HostKeyError.noKeysOffered("192.168.22.109").errorDescription)
        XCTAssertTrue(message.contains("permission prompt"))
        XCTAssertTrue(message.contains("try again"))
        XCTAssertGreaterThan(HostKeyService.scanAttempts, 1)
    }
}
