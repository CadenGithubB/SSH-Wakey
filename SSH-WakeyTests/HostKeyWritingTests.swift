import Darwin
import XCTest
@testable import SSH_Wakey

/// `known_hosts` decides which servers are trusted, and the lines being added
/// come from another machine. Both halves of that deserve care.
final class HostKeyWritingTests: XCTestCase {

    private var directory: URL!
    private var knownHosts: URL!

    private let realLine =
        "192.168.1.24 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH1kL2PmQk8vB3nZxq7cTfW5aYh0jRsGpXeMvNbUdOiK"

    override func setUpWithError() throws {
        directory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("SSH-WakeyHostKeys-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: directory.path)
        knownHosts = directory.appendingPathComponent("known_hosts")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func candidate(_ line: String) -> HostKeyCandidate {
        HostKeyCandidate(knownHostsLine: line, algorithm: "ED25519", bits: "256",
                         fingerprint: "SHA256:abc")
    }

    private var contents: String {
        (try? String(contentsOf: knownHosts, encoding: .utf8)) ?? ""
    }

    // MARK: - Appending

    func testAddingToANewFileCreatesItPrivate() throws {
        let previous = umask(0o022)
        defer { _ = umask(previous) }

        try HostKeyService.trust([candidate(realLine)], at: knownHosts)

        XCTAssertEqual(contents, realLine + "\n")
        let permissions = try FileManager.default
            .attributesOfItem(atPath: knownHosts.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(permissions?.int16Value, 0o600)
    }

    /// The old version read the file, added a line and wrote the whole thing
    /// back, which threw away anything ssh had recorded in the meantime.
    func testExistingEntriesAreKept() throws {
        let existing = "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"
        try Data(existing.utf8).write(to: knownHosts)

        try HostKeyService.trust([candidate(realLine)], at: knownHosts)

        XCTAssertTrue(contents.hasPrefix(existing), contents)
        XCTAssertTrue(contents.hasSuffix(realLine + "\n"), contents)
        XCTAssertEqual(contents.split(separator: "\n").count, 2)
    }

    func testAFileWithNoTrailingNewlineDoesNotGetAJoinedLine() throws {
        try Data("somehost ssh-rsa AAAAB3NzaC1yc2E".utf8).write(to: knownHosts)

        try HostKeyService.trust([candidate(realLine)], at: knownHosts)

        let lines = contents.split(separator: "\n")
        XCTAssertEqual(lines.count, 2)
        XCTAssertEqual(String(lines[1]), realLine)
    }

    func testTheFileKeepsItsIdentityRatherThanBeingReplaced() throws {
        try Data("somehost ssh-rsa AAAAB3NzaC1yc2E\n".utf8).write(to: knownHosts)
        let before = try FileManager.default.attributesOfItem(atPath: knownHosts.path)[.systemFileNumber] as? NSNumber

        try HostKeyService.trust([candidate(realLine)], at: knownHosts)

        let after = try FileManager.default.attributesOfItem(atPath: knownHosts.path)[.systemFileNumber] as? NSNumber
        XCTAssertEqual(before, after, "appending must not replace the file with a new one")
    }

    func testSeveralKeysForOneHostAllGoIn() throws {
        let second = "192.168.1.24 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDZ9kL2PmQk8vB3nZxq7cTfW"
        try HostKeyService.trust([candidate(realLine), candidate(second)], at: knownHosts)

        XCTAssertEqual(contents.split(separator: "\n").count, 2)
    }

    // MARK: - Refusing what should not go in

    func testRealKeyscanOutputIsAccepted() {
        for line in [
            realLine,
            "[192.168.1.24]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH1kL2PmQk8vB3nZxq7cTfW",
            "mac.local ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTY=",
            "host sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t",
        ] {
            XCTAssertTrue(HostKeyService.isWellFormed(line), line)
        }
    }

    func testAnythingThatIsNotAHostKeyLineIsRefused() {
        for line in [
            "",
            "onlyonefield",
            "host ssh-ed25519",
            "host not-a-key-type AAAAC3Nz",
            "host ssh-ed25519 not base64!",
            "host ssh-ed25519 AAAA\nevil.com ssh-ed25519 AAAA",
            "host ssh-ed25519 AAAA\u{0}",
        ] {
            XCTAssertFalse(HostKeyService.isWellFormed(line), line.debugDescription)
        }
    }

    // MARK: - Failure messages

    /// The first approach to a machine on the local network is the one macOS
    /// interrupts with its permission prompt, and that attempt fails. Saying so
    /// turns a dead end into something the reader can act on.
    func testAFailureOnTheLocalNetworkNamesThePermissionPrompt() throws {
        let message = try XCTUnwrap(
            HostKeyService.HostKeyError.noKeysOffered("192.168.22.109").errorDescription)

        XCTAssertTrue(message.contains("permission prompt"), message)
        XCTAssertTrue(message.contains("try again"), message)
    }

    func testAFailureOnAPublicHostDoesNotBlameThePrompt() throws {
        let message = try XCTUnwrap(
            HostKeyService.HostKeyError.noKeysOffered("build.example.com").errorDescription)

        XCTAssertFalse(message.contains("permission prompt"), message)
        XCTAssertTrue(message.contains("SSH server"), message)
    }

    func testItAsksMoreThanOnceBeforeGivingUp() {
        XCTAssertGreaterThan(HostKeyService.scanAttempts, 1)
    }

    func testOneBadLineStopsTheWholeWrite() throws {
        try Data("existing ssh-rsa AAAAB3NzaC1yc2E\n".utf8).write(to: knownHosts)

        XCTAssertThrowsError(
            try HostKeyService.trust([candidate(realLine), candidate("rubbish")], at: knownHosts))

        XCTAssertEqual(contents, "existing ssh-rsa AAAAB3NzaC1yc2E\n",
                       "nothing is added when any line is suspect")
    }

    // MARK: - The path we write through

    func testAnExistingWorldReadableFileIsStillAccepted() throws {
        try Data("somehost ssh-rsa AAAAB3NzaC1yc2E\n".utf8).write(to: knownHosts)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o644], ofItemAtPath: knownHosts.path)

        try HostKeyService.trust([candidate(realLine)], at: knownHosts)

        XCTAssertTrue(contents.contains(realLine), contents)
        let permissions = try FileManager.default
            .attributesOfItem(atPath: knownHosts.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(permissions?.int16Value, 0o644, "an existing mode is not rewritten")
    }

    func testAGroupWritableFileIsRefused() throws {
        try Data("somehost ssh-rsa AAAAB3NzaC1yc2E\n".utf8).write(to: knownHosts)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o664], ofItemAtPath: knownHosts.path)
        let before = contents

        XCTAssertThrowsError(try HostKeyService.trust([candidate(realLine)], at: knownHosts))
        XCTAssertEqual(contents, before)
    }

    func testAWorldWritableFileIsRefused() throws {
        try Data("somehost ssh-rsa AAAAB3NzaC1yc2E\n".utf8).write(to: knownHosts)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o666], ofItemAtPath: knownHosts.path)
        let before = contents

        XCTAssertThrowsError(try HostKeyService.trust([candidate(realLine)], at: knownHosts))
        XCTAssertEqual(contents, before)
    }

    func testADirectoryAtTheKnownHostsPathIsRefused() throws {
        try FileManager.default.createDirectory(at: knownHosts, withIntermediateDirectories: false)

        XCTAssertThrowsError(try HostKeyService.trust([candidate(realLine)], at: knownHosts))
    }

    func testASymlinkToARegularFileIsFollowed() throws {
        let target = directory.appendingPathComponent("real_hosts")
        try Data("somehost ssh-rsa AAAAB3NzaC1yc2E\n".utf8).write(to: target)
        try FileManager.default.createSymbolicLink(
            atPath: knownHosts.path, withDestinationPath: target.path)

        try HostKeyService.trust([candidate(realLine)], at: knownHosts)

        XCTAssertEqual(
            try FileManager.default.destinationOfSymbolicLink(atPath: knownHosts.path),
            target.path)
        let targetText = try String(contentsOf: target, encoding: .utf8)
        XCTAssertTrue(targetText.contains(realLine), targetText)
    }

    func testASymlinkToAFifoIsRefused() throws {
        let fifo = directory.appendingPathComponent("pipe")
        XCTAssertEqual(mkfifo(fifo.path, 0o600), 0)
        try FileManager.default.createSymbolicLink(
            atPath: knownHosts.path, withDestinationPath: fifo.path)

        XCTAssertThrowsError(try HostKeyService.trust([candidate(realLine)], at: knownHosts))
        XCTAssertEqual(
            try FileManager.default.destinationOfSymbolicLink(atPath: knownHosts.path),
            fifo.path)
    }

    func testASymlinkToAWorldWritableFileIsRefused() throws {
        let target = directory.appendingPathComponent("world_hosts")
        try Data("somehost ssh-rsa AAAAB3NzaC1yc2E\n".utf8).write(to: target)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o666], ofItemAtPath: target.path)
        try FileManager.default.createSymbolicLink(
            atPath: knownHosts.path, withDestinationPath: target.path)
        let before = try String(contentsOf: target, encoding: .utf8)

        XCTAssertThrowsError(try HostKeyService.trust([candidate(realLine)], at: knownHosts))
        XCTAssertEqual(try String(contentsOf: target, encoding: .utf8), before)
        XCTAssertEqual(
            try FileManager.default.destinationOfSymbolicLink(atPath: knownHosts.path),
            target.path)
    }

    func testABrokenSymlinkIsNotReplaced() throws {
        let missing = directory.appendingPathComponent("not_there")
        try FileManager.default.createSymbolicLink(
            atPath: knownHosts.path, withDestinationPath: missing.path)

        XCTAssertThrowsError(try HostKeyService.trust([candidate(realLine)], at: knownHosts))
        XCTAssertEqual(
            try FileManager.default.destinationOfSymbolicLink(atPath: knownHosts.path),
            missing.path)
        XCTAssertFalse(FileManager.default.fileExists(atPath: missing.path))
    }

    func testAGroupWritableFolderIsRefused() throws {
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o770], ofItemAtPath: directory.path)

        XCTAssertThrowsError(try HostKeyService.trust([candidate(realLine)], at: knownHosts))
        XCTAssertFalse(FileManager.default.fileExists(atPath: knownHosts.path))
    }
}
