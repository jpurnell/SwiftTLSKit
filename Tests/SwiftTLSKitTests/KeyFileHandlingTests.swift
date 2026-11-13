import Foundation
import SwiftTLSKit
import SwiftTLSKitTestSupport
import Testing

/// What an independent review of the key-file path found. Every test here fails on the code as
/// it stood when the review was made.
@Suite("Key file handling")
struct KeyFileHandlingTests {
    let authority: TestAuthority
    let fixture: Fixture

    init() throws {
        authority = try TestAuthority(commonName: "SwiftTLSKit Test Authority", generator: SeededGenerator(seed: TestSeed.authority))
        fixture = try Fixture()
    }

    // MARK: A path is the whole string

    /// `open` takes a C string, which ends at the first NUL. Without a check, a path of
    /// `privkey.pem` + NUL + anything opens `privkey.pem`, and the error and the log name a path
    /// that is not the one that was read.
    @Test("A path with a NUL in it is refused, not truncated to the file before the NUL")
    func nulInKeyPath() throws {
        let leaf = try authority.issueLeaf()
        let identity = try fixture.install(leaf)
        let truncated = ServerIdentity(
            certificateChainPath: identity.certificateChainPath, privateKeyPath: identity.privateKeyPath + "\u{0}.junk")

        #expect(throws: ServerIdentityError.self) { try truncated.load(now: TestInstant.now) }
    }

    @Test("A certificate chain path with a NUL in it is refused too")
    func nulInChainPath() throws {
        let leaf = try authority.issueLeaf()
        let identity = try fixture.install(leaf)
        let truncated = ServerIdentity(
            certificateChainPath: identity.certificateChainPath + "\u{0}.junk", privateKeyPath: identity.privateKeyPath)

        #expect(throws: ServerIdentityError.self) { try truncated.load(now: TestInstant.now) }
    }

    // MARK: A file that cannot be opened, whoever is running

    /// The test that refuses an unreadable chain is skipped when the process is root, which is
    /// what a CI container is, because root reads a mode-0 file. A link that loops cannot be
    /// opened by anyone, so this holds on every platform and for every user.
    @Test("A key that cannot be opened is unreadable, whoever is asking")
    func loopingKeyLink() throws {
        let leaf = try authority.issueLeaf()
        let identity = try fixture.install(leaf)
        let loop = fixture.path("loop.pem")
        try FileManager.default.createSymbolicLink(atPath: loop, withDestinationPath: loop)
        let looping = ServerIdentity(certificateChainPath: identity.certificateChainPath, privateKeyPath: loop)

        do {
            _ = try looping.load(now: TestInstant.now)
            Issue.record("A key behind a link that loops was loaded")
        } catch ServerIdentityError.unreadable(let path, _) {
            #expect(path == loop)
        } catch {
            Issue.record("Expected .unreadable, got \(error)")
        }
    }

    // MARK: The hint is a command someone pastes

    @Test("An ordinary path is in the hint as it is")
    func hintPlainPath() {
        let error = ServerIdentityError.privateKeyPermissionsTooOpen(path: "/etc/ssl/private/privkey.pem", mode: 0o644)
        #expect(error.description.hasSuffix("Run: chmod 600 /etc/ssl/private/privkey.pem"))
    }

    @Test(
        "A path the shell would read as more than one word, or as a command, is quoted in the hint",
        arguments: [
            ("/etc/ssl/a b/key.pem", "'/etc/ssl/a b/key.pem'"),
            ("/etc/ssl/a; rm -rf ~", "'/etc/ssl/a; rm -rf ~'"),
            ("/etc/ssl/$(id)/key.pem", "'/etc/ssl/$(id)/key.pem'"),
            ("/etc/ssl/`id`/key.pem", "'/etc/ssl/`id`/key.pem'"),
            ("/etc/ssl/it's/key.pem", "'/etc/ssl/it'\\''s/key.pem'"),
            // A path that begins with a dash is an option to chmod, quoted or not: `--` ends them.
            ("-rf", "-- -rf"),
            ("-a b", "-- '-a b'"),
            ("/etc/ssl/-rf", "/etc/ssl/-rf"),
        ])
    func hintQuoted(path: String, quoted: String) {
        let error = ServerIdentityError.privateKeyPermissionsTooOpen(path: path, mode: 0o644)
        #expect(error.description.hasSuffix("Run: chmod 600 \(quoted)"))
    }
}
