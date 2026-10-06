import Foundation
import Testing
import SwiftTLSKit

@Suite("Loading a server identity")
struct ServerIdentityLoadingTests {
    let authority: TestAuthority
    let fixture: Fixture

    init() throws {
        authority = try TestAuthority(commonName: "SwiftTLSKit Test Authority")
        fixture = try Fixture()
    }

    // MARK: - What a good identity reports

    @Test("A valid pair loads, and reports the leaf it will serve")
    func loadsAndSummarises() throws {
        let leaf = try authority.issueLeaf(dnsNames: ["localhost", "tls.example"], ipv4Addresses: [[127, 0, 0, 1]])
        let identity = try fixture.install(leaf)

        let loaded = try identity.load(now: TestInstant.now)

        #expect(loaded.identity == identity)
        #expect(loaded.certificateChain.count == 2)
        #expect(loaded.leaf.subjectAlternativeNames == ["localhost", "tls.example", "127.0.0.1"])
        #expect(loaded.leaf.notValidBefore == TestInstant.longLivedStart)
        #expect(loaded.leaf.notValidAfter == TestInstant.longLivedEnd)
        #expect(loaded.leaf.certificateSHA256 == (try leaf.certificateSHA256))
        #expect(loaded.leaf.publicKeySHA256 == leaf.publicKeySHA256)
    }

    @Test("The summary is one line: names, validity, and the fingerprint openssl prints")
    func summaryDescription() throws {
        let leaf = try authority.issueLeaf(dnsNames: ["localhost"], ipv4Addresses: [[127, 0, 0, 1]])
        let loaded = try fixture.install(leaf).load(now: TestInstant.now)

        #expect(
            loaded.leaf.description
                == "localhost, 127.0.0.1; valid 2020-01-01T00:00:00Z to 2090-01-01T00:00:00Z; "
                + "SHA-256 \(try leaf.certificateSHA256)")
    }

    // MARK: - Files that cannot be used

    @Test("A missing certificate chain is refused, naming the path")
    func missingCertificateChain() throws {
        let leaf = try authority.issueLeaf()
        let identity = ServerIdentity(
            certificateChainPath: fixture.path("absent.pem"),
            privateKeyPath: try fixture.write(leaf.keyPEM, to: "privkey.pem", mode: 0o600))

        #expect(throws: ServerIdentityError.unreadable(path: fixture.path("absent.pem"), reason: "No such file or directory")) {
            try identity.load(now: TestInstant.now)
        }
    }

    @Test("A missing private key is refused, naming the path")
    func missingPrivateKey() throws {
        let leaf = try authority.issueLeaf()
        let identity = ServerIdentity(
            certificateChainPath: try fixture.write(try leaf.chainPEM, to: "fullchain.pem", mode: 0o644),
            privateKeyPath: fixture.path("absent.pem"))

        #expect(throws: ServerIdentityError.unreadable(path: fixture.path("absent.pem"), reason: "No such file or directory")) {
            try identity.load(now: TestInstant.now)
        }
    }

    @Test("A certificate chain the process may not read is refused", .enabled(if: geteuid() != 0))
    func unreadableCertificateChain() throws {
        let leaf = try authority.issueLeaf()
        let identity = ServerIdentity(
            certificateChainPath: try fixture.write(try leaf.chainPEM, to: "fullchain.pem", mode: 0o000),
            privateKeyPath: try fixture.write(leaf.keyPEM, to: "privkey.pem", mode: 0o600))

        #expect(throws: ServerIdentityError.unreadable(path: identity.certificateChainPath, reason: "Permission denied")) {
            try identity.load(now: TestInstant.now)
        }
    }

    @Test("A directory where the certificate chain should be is refused")
    func directoryAsCertificateChain() throws {
        let leaf = try authority.issueLeaf()
        let identity = ServerIdentity(
            certificateChainPath: fixture.directory.path,
            privateKeyPath: try fixture.write(leaf.keyPEM, to: "privkey.pem", mode: 0o600))

        #expect(throws: ServerIdentityError.notRegularFile(path: fixture.directory.path)) {
            try identity.load(now: TestInstant.now)
        }
    }

    @Test("A FIFO where the private key should be is refused rather than waited on")
    func fifoAsPrivateKey() throws {
        let leaf = try authority.issueLeaf()
        let fifo = fixture.path("privkey.fifo")
        try #require(mkfifo(fifo, 0o600) == 0)
        let identity = ServerIdentity(
            certificateChainPath: try fixture.write(try leaf.chainPEM, to: "fullchain.pem", mode: 0o644),
            privateKeyPath: fifo)

        #expect(throws: ServerIdentityError.notRegularFile(path: fifo)) {
            try identity.load(now: TestInstant.now)
        }
    }

    @Test("A file far larger than any PEM is refused before it is read in")
    func oversizedFile() throws {
        let leaf = try authority.issueLeaf()
        let padding = String(repeating: "#", count: 1_048_577)
        let identity = ServerIdentity(
            certificateChainPath: try fixture.write(padding, to: "fullchain.pem", mode: 0o644),
            privateKeyPath: try fixture.write(leaf.keyPEM, to: "privkey.pem", mode: 0o600))

        #expect(throws: ServerIdentityError.fileTooLarge(path: identity.certificateChainPath, limit: 1_048_576)) {
            try identity.load(now: TestInstant.now)
        }
    }

    // MARK: - Private key permissions

    @Test(
        "A private key that group or others can read or write is refused, naming its mode",
        arguments: [0o644, 0o640, 0o604, 0o620, 0o602, 0o660, 0o601, 0o610, 0o666])
    func openPrivateKey(mode: Int) throws {
        let identity = try fixture.install(try authority.issueLeaf(), keyMode: mode)

        #expect(
            throws: ServerIdentityError.privateKeyPermissionsTooOpen(
                path: identity.privateKeyPath, mode: UInt16(mode))
        ) {
            try identity.load(now: TestInstant.now)
        }
    }

    @Test("A private key only its owner can reach is accepted", arguments: [0o600, 0o400])
    func ownerOnlyPrivateKey(mode: Int) throws {
        let leaf = try authority.issueLeaf()
        let identity = try fixture.install(leaf, keyMode: mode)

        #expect(try identity.load(now: TestInstant.now).leaf.publicKeySHA256 == leaf.publicKeySHA256)
    }

    @Test("The mode checked is the file's, not a symbolic link's")
    func symbolicLinkToPrivateKey() throws {
        let leaf = try authority.issueLeaf()
        let real = try fixture.install(leaf, keyMode: 0o644)
        let link = fixture.path("privkey.link.pem")
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: real.privateKeyPath)
        let identity = ServerIdentity(certificateChainPath: real.certificateChainPath, privateKeyPath: link)

        #expect(throws: ServerIdentityError.privateKeyPermissionsTooOpen(path: link, mode: 0o644)) {
            try identity.load(now: TestInstant.now)
        }

        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: real.privateKeyPath)
        #expect(try identity.load(now: TestInstant.now).leaf.publicKeySHA256 == leaf.publicKeySHA256)
    }

    @Test("The certificate chain may be world-readable; it is public")
    func worldReadableCertificateChain() throws {
        let leaf = try authority.issueLeaf()
        let identity = try fixture.install(leaf)
        try FileManager.default.setAttributes([.posixPermissions: 0o666], ofItemAtPath: identity.certificateChainPath)

        #expect(try identity.load(now: TestInstant.now).leaf.certificateSHA256 == (try leaf.certificateSHA256))
    }

    // MARK: - Contents that cannot be used

    @Test("A chain file holding no certificate is refused", arguments: ["", "not a certificate\n"])
    func emptyChain(contents: String) throws {
        let leaf = try authority.issueLeaf()
        let identity = ServerIdentity(
            certificateChainPath: try fixture.write(contents, to: "fullchain.pem", mode: 0o644),
            privateKeyPath: try fixture.write(leaf.keyPEM, to: "privkey.pem", mode: 0o600))

        #expect(throws: ServerIdentityError.emptyCertificateChain(path: identity.certificateChainPath)) {
            try identity.load(now: TestInstant.now)
        }
    }

    @Test("A chain file holding a damaged certificate is refused")
    func damagedChain() throws {
        let leaf = try authority.issueLeaf()
        let damaged = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
        let identity = ServerIdentity(
            certificateChainPath: try fixture.write(damaged, to: "fullchain.pem", mode: 0o644),
            privateKeyPath: try fixture.write(leaf.keyPEM, to: "privkey.pem", mode: 0o600))

        #expect(throws: ServerIdentityError.invalidCertificateChain(path: identity.certificateChainPath)) {
            try identity.load(now: TestInstant.now)
        }
    }

    @Test("A key file that is not a private key is refused, and its contents are not repeated")
    func damagedKey() throws {
        let leaf = try authority.issueLeaf()
        let identity = ServerIdentity(
            certificateChainPath: try fixture.write(try leaf.chainPEM, to: "fullchain.pem", mode: 0o644),
            privateKeyPath: try fixture.write("MARKER-THAT-MUST-NOT-APPEAR\n", to: "privkey.pem", mode: 0o600))

        let expected = ServerIdentityError.invalidPrivateKey(path: identity.privateKeyPath)
        #expect(throws: expected) {
            try identity.load(now: TestInstant.now)
        }
        #expect(
            expected.description
                == "\(identity.privateKeyPath) does not hold a private key that can be read as unencrypted PEM.")
    }

    @Test("A key that belongs to a different certificate is refused")
    func mismatchedKey() throws {
        let served = try authority.issueLeaf()
        let other = try authority.issueLeaf()
        let identity = ServerIdentity(
            certificateChainPath: try fixture.write(try served.chainPEM, to: "fullchain.pem", mode: 0o644),
            privateKeyPath: try fixture.write(other.keyPEM, to: "privkey.pem", mode: 0o600))

        #expect(
            throws: ServerIdentityError.privateKeyDoesNotMatchCertificate(
                certificateChainPath: identity.certificateChainPath, privateKeyPath: identity.privateKeyPath)
        ) {
            try identity.load(now: TestInstant.now)
        }
    }

    // MARK: - Validity, against the time the caller supplies

    @Test("An expired leaf is refused, and it is the supplied time that decides")
    func expiredLeaf() throws {
        let leaf = try authority.issueLeaf(notValidAfter: TestInstant.shortLivedEnd)
        let identity = try fixture.install(leaf)

        #expect(
            throws: ServerIdentityError.expired(
                path: identity.certificateChainPath, notValidAfter: TestInstant.shortLivedEnd)
        ) {
            try identity.load(now: TestInstant.now)
        }
        #expect(try identity.load(now: TestInstant.duringShortLived).leaf.notValidAfter == TestInstant.shortLivedEnd)
    }

    @Test("The last second of validity is still valid; the next is not")
    func expiryBoundary() throws {
        let leaf = try authority.issueLeaf(notValidAfter: TestInstant.shortLivedEnd)
        let identity = try fixture.install(leaf)

        #expect(try identity.load(now: TestInstant.shortLivedEnd).leaf.notValidAfter == TestInstant.shortLivedEnd)
        #expect(
            throws: ServerIdentityError.expired(
                path: identity.certificateChainPath, notValidAfter: TestInstant.shortLivedEnd)
        ) {
            try identity.load(now: TestInstant.shortLivedEnd.addingTimeInterval(1))
        }
    }

    @Test("A leaf that is not valid yet is refused")
    func notYetValidLeaf() throws {
        let identity = try fixture.install(try authority.issueLeaf())

        #expect(
            throws: ServerIdentityError.notYetValid(
                path: identity.certificateChainPath, notValidBefore: TestInstant.longLivedStart)
        ) {
            try identity.load(now: TestInstant.beforeAnything)
        }
        #expect(try identity.load(now: TestInstant.longLivedStart).leaf.notValidBefore == TestInstant.longLivedStart)
    }

    // MARK: - Messages

    @Test("Every refusal says what to do, and none repeats a file's contents")
    func messages() {
        #expect(
            ServerIdentityError.unreadable(path: "/c/fullchain.pem", reason: "No such file or directory").description
                == "Cannot read /c/fullchain.pem: No such file or directory.")
        #expect(
            ServerIdentityError.notRegularFile(path: "/c/privkey.pem").description
                == "/c/privkey.pem is not a regular file.")
        #expect(
            ServerIdentityError.fileTooLarge(path: "/c/fullchain.pem", limit: 1_048_576).description
                == "/c/fullchain.pem is larger than 1048576 bytes, which no certificate chain or private key is.")
        #expect(
            ServerIdentityError.privateKeyPermissionsTooOpen(path: "/c/privkey.pem", mode: 0o644).description
                == "The private key at /c/privkey.pem has mode 0644, which lets group or others read or write it. "
                + "Run: chmod 600 /c/privkey.pem")
        #expect(
            ServerIdentityError.emptyCertificateChain(path: "/c/fullchain.pem").description
                == "/c/fullchain.pem holds no certificates.")
        #expect(
            ServerIdentityError.invalidCertificateChain(path: "/c/fullchain.pem").description
                == "/c/fullchain.pem holds a certificate that cannot be read as PEM.")
        #expect(
            ServerIdentityError.privateKeyDoesNotMatchCertificate(
                certificateChainPath: "/c/fullchain.pem", privateKeyPath: "/c/privkey.pem"
            ).description
                == "The private key at /c/privkey.pem does not match the leaf certificate in /c/fullchain.pem.")
        #expect(
            ServerIdentityError.expired(path: "/c/fullchain.pem", notValidAfter: TestInstant.shortLivedEnd).description
                == "The leaf certificate in /c/fullchain.pem expired at 2021-01-01T00:00:00Z.")
        #expect(
            ServerIdentityError.notYetValid(path: "/c/fullchain.pem", notValidBefore: TestInstant.longLivedStart)
                .description
                == "The leaf certificate in /c/fullchain.pem is not valid until 2020-01-01T00:00:00Z.")
        #expect(
            ServerIdentityError.contextRejected(reason: "unsupported key").description
                == "The TLS library refused this identity: unsupported key.")
    }
}
