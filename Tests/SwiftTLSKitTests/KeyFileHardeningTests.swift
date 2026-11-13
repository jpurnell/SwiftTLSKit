import Foundation
@testable import SwiftTLSKit
import SwiftTLSKitTestSupport
import Testing
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// Who may replace a private key, beyond who may read it: its owner, and every directory it
/// sits in. A key at mode 0600 that someone else can swap for their own is a key that serves
/// their identity at the next reload.
@Suite("Who can replace a private key")
struct KeyFileHardeningTests {
    let authority: TestAuthority
    let fixture: Fixture

    init() throws {
        authority = try TestAuthority(commonName: "SwiftTLSKit Test Authority", generator: SeededGenerator(seed: TestSeed.authority))
        fixture = try Fixture()
    }

    private func key(in directory: URL) throws -> (identity: ServerIdentity, key: String) {
        let leaf = try authority.issueLeaf()
        let chain = directory.appendingPathComponent("fullchain.pem").path
        let key = directory.appendingPathComponent("privkey.pem").path
        try Data(leaf.chainPEM.utf8).write(to: URL(fileURLWithPath: chain))
        try Data(leaf.privateKeyPEM.utf8).write(to: URL(fileURLWithPath: key))
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: key)
        return (ServerIdentity(certificateChainPath: chain, privateKeyPath: key), key)
    }

    private func subdirectory(_ name: String, in parent: URL, mode: Int) throws -> URL {
        let url = parent.appendingPathComponent(name, isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
        return url
    }

    /// Where a path really is, by `realpath`: the form the error names, since symbolic links are
    /// followed. Not `URL.resolvingSymlinksInPath`, which drops the `/private` that macOS puts
    /// before `/var`, so the two name the same directory differently.
    private func resolved(_ url: URL) -> String {
        guard let pointer = realpath(url.path, nil) else { return url.path }
        defer { free(pointer) }
        return String(cString: pointer)
    }

    // MARK: Owner

    @Test(
        "A key is the process's to keep if the process's user or root owns it, and not otherwise",
        arguments: [
            (UInt32(0), UInt32(1000), true), (1000, 1000, true), (1001, 1000, false),
            // A process running as root does not trust a key somebody else owns.
            (1000, 0, false), (0, 0, true),
        ] as [(UInt32, UInt32, Bool)])
    func ownerRule(owner: UInt32, effective: UInt32, trusted: Bool) {
        #expect(PEMFile.ownerIsTrusted(owner: owner, effectiveUserID: effective) == trusted)
    }

    @Test("A key owned by another user is refused, naming the owner", .enabled(if: geteuid() != 0))
    func ownedByAnotherUser() throws {
        let (identity, key) = try key(in: fixture.directory)
        let me = geteuid()

        #expect(throws: ServerIdentityError.privateKeyOwnedByAnotherUser(path: key, ownerID: UInt32(me))) {
            try PEMFile.read(path: identity.privateKeyPath, mustBeOwnerOnly: true, effectiveUserID: me &+ 1)
        }
        // And the real user is fine.
        #expect(try !PEMFile.read(path: identity.privateKeyPath, mustBeOwnerOnly: true, effectiveUserID: me).isEmpty)
    }

    /// Run as root, which is what a CI container is: chown the key to someone else.
    @Test("A key owned by an unprivileged user is refused when root loads it", .enabled(if: geteuid() == 0))
    func ownedByAnotherUserAsRoot() throws {
        let (identity, key) = try key(in: fixture.directory)
        #expect(chown(key, 1234, gid_t.max) == 0)

        #expect(throws: ServerIdentityError.privateKeyOwnedByAnotherUser(path: key, ownerID: 1234)) {
            try identity.load(now: TestInstant.now)
        }
    }

    @Test("The certificate chain's owner is not checked: it is public")
    func chainOwnerIsNotChecked() throws {
        let (identity, _) = try key(in: fixture.directory)
        let me = geteuid()
        #expect(try !PEMFile.read(path: identity.certificateChainPath, mustBeOwnerOnly: false, effectiveUserID: me &+ 1).isEmpty)
    }

    // MARK: Directories

    @Test(
        "A key in a directory that group or others can write is refused, naming the directory",
        arguments: [0o777, 0o775, 0o757, 0o722, 0o770 | 0o002])
    func writableDirectory(mode: Int) throws {
        let directory = try subdirectory("writable", in: fixture.directory, mode: mode)
        let (identity, key) = try key(in: directory)

        #expect(
            throws: ServerIdentityError.privateKeyDirectoryWritable(
                path: key, directory: resolved(directory), mode: UInt16(mode))
        ) { try identity.load(now: TestInstant.now) }
    }

    @Test("A directory above the key counts, however deep the key is", arguments: [1, 2, 3])
    func writableAncestor(depth: Int) throws {
        let unsafe = try subdirectory("unsafe", in: fixture.directory, mode: 0o777)
        var directory = unsafe
        for level in 0..<depth {
            directory = try subdirectory("level\(level)", in: directory, mode: 0o700)
        }
        let (identity, key) = try key(in: directory)

        #expect(
            throws: ServerIdentityError.privateKeyDirectoryWritable(
                path: key, directory: resolved(unsafe), mode: 0o777)
        ) { try identity.load(now: TestInstant.now) }
    }

    @Test("A directory everyone can write but only an owner can rename within is fine")
    func stickyDirectory() throws {
        let directory = try subdirectory("sticky", in: fixture.directory, mode: 0o1777)
        let (identity, _) = try key(in: directory)

        #expect(try identity.load(now: TestInstant.now).leaf.subjectAlternativeNames == ["localhost"])
    }

    @Test("A directory that only its owner can write is fine", arguments: [0o700, 0o750, 0o755, 0o500])
    func ownerOnlyDirectory(mode: Int) throws {
        let directory = try subdirectory("safe", in: fixture.directory, mode: 0o700)
        let (identity, _) = try key(in: directory)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: directory.path)

        #expect(try identity.load(now: TestInstant.now).leaf.subjectAlternativeNames == ["localhost"])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    }

    @Test("A link to a key is judged by where the key is, not where the link is")
    func linkIntoWritableDirectory() throws {
        let unsafe = try subdirectory("unsafe", in: fixture.directory, mode: 0o777)
        let (real, realKey) = try key(in: unsafe)
        let link = fixture.path("privkey.link.pem")
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: realKey)
        let identity = ServerIdentity(certificateChainPath: real.certificateChainPath, privateKeyPath: link)

        #expect(
            throws: ServerIdentityError.privateKeyDirectoryWritable(
                path: link, directory: resolved(unsafe), mode: 0o777)
        ) { try identity.load(now: TestInstant.now) }
    }

    @Test("The certificate chain's directory is not checked: the chain is public")
    func chainDirectoryIsNotChecked() throws {
        let unsafe = try subdirectory("unsafe", in: fixture.directory, mode: 0o777)
        let leaf = try authority.issueLeaf()
        let chain = unsafe.appendingPathComponent("fullchain.pem").path
        try Data(leaf.chainPEM.utf8).write(to: URL(fileURLWithPath: chain))
        let key = try fixture.write(leaf.privateKeyPEM, to: "privkey.pem", mode: 0o600)

        #expect(try ServerIdentity(certificateChainPath: chain, privateKeyPath: key).load(now: TestInstant.now).leaf.certificateSHA256 == leaf.certificateSHA256)
    }

    // MARK: Access control lists (macOS)

    #if os(macOS)
    /// macOS keeps an access control list apart from the mode, so `ls -l` can say `-rw-------`
    /// over a key everyone can read. (Linux folds a POSIX ACL's mask into the group bits, which
    /// the mode check already refuses.)
    @Test("A key with an access control list is refused, though its mode is 0600")
    func accessControlList() throws {
        let (identity, key) = try key(in: fixture.directory)
        try addEveryoneReadACL(to: key)
        var status = stat()
        #expect(stat(key, &status) == 0)
        #expect(status.st_mode & 0o777 == 0o600)

        #expect(throws: ServerIdentityError.privateKeyHasAccessControlList(path: key)) {
            try identity.load(now: TestInstant.now)
        }
    }

    @Test("A key without one is not")
    func noAccessControlList() throws {
        let (identity, _) = try key(in: fixture.directory)
        #expect(try identity.load(now: TestInstant.now).leaf.subjectAlternativeNames == ["localhost"])
    }

    /// `chmod +a "everyone allow read" path`, through the C interface.
    private func addEveryoneReadACL(to path: String) throws {
        // The well-known GUID of "everyone": ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C.
        var everyone: [UInt8] = [0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF, 0, 0, 0, 0x0C]
        var acl: acl_t? = acl_init(1)
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        try #require(acl_create_entry(&acl, &entry) == 0)
        try #require(acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) == 0)
        try #require(acl_set_qualifier(entry, &everyone) == 0)
        var permissions: acl_permset_t?
        try #require(acl_get_permset(entry, &permissions) == 0)
        try #require(acl_add_perm(permissions, ACL_READ_DATA) == 0)
        try #require(acl_set_file(path, ACL_TYPE_EXTENDED, acl) == 0)
    }
    #endif

    // MARK: A path in a message cannot break the line it is in

    private static let hostile = "/etc/ssl/a\nFORGED LOG LINE\r\u{1b}[31m\u{7f}\u{0}/key.pem"

    @Test("No description holds a control character, whatever the path holds")
    func descriptionsArePrintable() {
        let path = Self.hostile
        let errors: [ServerIdentityError] = [
            .unreadable(path: path, reason: "No such file or directory"),
            .notRegularFile(path: path),
            .fileTooLarge(path: path, limit: 1),
            .privateKeyPermissionsTooOpen(path: path, mode: 0o644),
            .privateKeyOwnedByAnotherUser(path: path, ownerID: 7),
            .privateKeyDirectoryWritable(path: path, directory: path, mode: 0o777),
            .privateKeyHasAccessControlList(path: path),
            .emptyCertificateChain(path: path),
            .invalidCertificateChain(path: path),
            .invalidPrivateKey(path: path),
            .privateKeyDoesNotMatchCertificate(certificateChainPath: path, privateKeyPath: path),
            .expired(path: path, notValidAfter: Date(timeIntervalSince1970: 0)),
            .notYetValid(path: path, notValidBefore: Date(timeIntervalSince1970: 0)),
        ]
        for error in errors {
            let unprintable = error.description.unicodeScalars.filter { $0.value < 0x20 || $0.value == 0x7f }
            #expect(unprintable.isEmpty, "\(error)")
        }
    }

    @Test("A path with ordinary characters in a message is as it was written")
    func ordinaryPathUnchanged() {
        #expect(
            ServerIdentityError.notRegularFile(path: "/etc/ssl/private/privkey.pem").description
                == "/etc/ssl/private/privkey.pem is not a regular file.")
        #expect(
            ServerIdentityError.notRegularFile(path: "/etc/ssl/café/key.pem").description
                == "/etc/ssl/café/key.pem is not a regular file.")
    }

    @Test("A control character is written out, not dropped")
    func controlCharactersWrittenOut() {
        #expect(
            ServerIdentityError.notRegularFile(path: "/a\nb\tc\rd").description
                == "/a\\nb\\tc\\rd is not a regular file.")
        #expect(
            ServerIdentityError.notRegularFile(path: "/a\u{1b}b\u{0}c").description
                == "/a\\u{1B}b\\u{0}c is not a regular file.")
    }

    @Test("The pasted command for a path with a control character is one line")
    func hintForControlCharacters() {
        let hint = ServerIdentityError.privateKeyPermissionsTooOpen(path: "/a\nb", mode: 0o644).description
        #expect(hint.hasSuffix("Run: chmod 600 $'/a\\nb'"))
    }
}
