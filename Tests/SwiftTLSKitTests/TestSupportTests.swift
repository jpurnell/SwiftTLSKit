import Crypto
import Foundation
import NIOSSL
import SwiftASN1
import SwiftTLSKit
import SwiftTLSKitTestSupport
import Testing
import X509

/// A generator that returns the values it was given, in order, and then one value for ever.
///
/// Not a random number generator in any useful sense: it is how a test says exactly which
/// bytes the code under test will be handed.
struct ScriptedGenerator: RandomNumberGenerator, Sendable {
    private let script: [UInt64]
    private let thereafter: UInt64
    private var position = 0

    init(_ script: [UInt64], thereafter: UInt64) {
        self.script = script
        self.thereafter = thereafter
    }

    mutating func next() -> UInt64 {
        defer { position += 1 }
        return position < script.count ? script[position] : thereafter
    }
}

/// The published points of P-256, for stating which key a given scalar must produce without
/// asking the library under test.
enum P256Vector {
    /// The DER that precedes the point in a P-256 SubjectPublicKeyInfo: `id-ecPublicKey` with
    /// the `prime256v1` curve, then a BIT STRING header (RFC 5480 §2).
    static let subjectPublicKeyInfoPrefix: [UInt8] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ]

    /// The base point G — the public key of the private key 1 (FIPS 186-4 §D.1.2.3).
    static let basePoint =
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"

    /// 2G — the public key of the private key 2. From NIST's P-256 point multiplication
    /// vectors, and re-derived by doubling G with integer arithmetic outside this package.
    static let twiceBasePoint =
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
        + "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"

    /// SHA-256 of the SubjectPublicKeyInfo whose uncompressed point is `point`, lowercase hex.
    static func publicKeySHA256(ofPoint point: String) throws -> String {
        var bytes = subjectPublicKeyInfoPrefix + [0x04]
        var remaining = Substring(point)
        while !remaining.isEmpty {
            bytes.append(try #require(UInt8(remaining.prefix(2), radix: 16)))
            remaining = remaining.dropFirst(2)
        }
        return SHA256.hash(data: bytes).map { byte in
            let text = String(byte, radix: 16)
            return text.count == 1 ? "0" + text : text
        }.joined()
    }
}

@Suite("The test-support product", .timeLimit(.minutes(1)))
struct TestSupportTests {
    /// Words that make a valid authority key (the scalar 7) and its serial number, so that a
    /// script can go on to say what the leaf is given.
    private static let authorityDraws: [UInt64] = [0, 0, 0, 7, 0x1111_1111_1111_1111, 0x2222_2222_2222_2222]

    private func systemAuthority() throws -> TestAuthority {
        try TestAuthority(commonName: "Support Test Authority", generator: SeededGenerator(seed: TestSeed.authority))
    }

    // MARK: - The shipped generator

    /// The first five outputs for the seed 1234567, from the reference implementation's
    /// published test values (the same five the Rosetta Code SplitMix64 task lists).
    @Test("The shipped seeded generator is SplitMix64")
    func seededGeneratorIsSplitMix64() {
        var generator = SwiftTLSKitTestSupport.SeededGenerator(seed: 1_234_567)
        let outputs = (0..<5).map { _ in generator.next() }

        #expect(
            outputs == [
                6_457_827_717_110_365_317, 3_203_168_211_198_807_973, 9_817_491_932_198_370_423,
                4_593_380_528_125_082_431, 16_408_922_859_458_223_821,
            ])
    }

    /// The seed zero is the stream xoshiro's authors publish for seeding their generators; its
    /// first values are the most widely reproduced SplitMix64 outputs there are. Re-derived
    /// with integer arithmetic outside this package.
    @Test("Seed zero gives the published stream, so zero is a seed like any other")
    func seededGeneratorFromZero() {
        var generator = SwiftTLSKitTestSupport.SeededGenerator(seed: 0)
        let outputs = (0..<5).map { _ in generator.next() }

        #expect(
            outputs == [
                0xE220_A839_7B1D_CDAF, 0x6E78_9E6A_A1B9_65F4, 0x06C4_5D18_8009_454F,
                0xF88B_B8A8_724C_81EC, 0x1B39_896A_51A8_749B,
            ])
    }

    @Test("A copy continues from where the original was, and neither moves the other")
    func seededGeneratorIsAValue() {
        var original = SwiftTLSKitTestSupport.SeededGenerator(seed: 1_234_567)
        #expect(original.next() == 6_457_827_717_110_365_317)

        var copy = original
        #expect(copy.next() == 3_203_168_211_198_807_973)
        #expect(copy.next() == 9_817_491_932_198_370_423)
        #expect(original.next() == 3_203_168_211_198_807_973)
    }

    @Test("Authorities from different seeds have different keys, and the same seed the same key")
    func seedsSeparateAuthorities() throws {
        let authority = try TestAuthority(commonName: "A", generator: SeededGenerator(seed: TestSeed.authority))
        let again = try TestAuthority(commonName: "A", generator: SeededGenerator(seed: TestSeed.authority))
        let stranger = try TestAuthority(commonName: "A", generator: SeededGenerator(seed: TestSeed.stranger))
        let authorityKey = try Certificate(pemEncoded: authority.certificatePEM).publicKey

        #expect(try Certificate(pemEncoded: again.certificatePEM).publicKey == authorityKey)
        #expect(try Certificate(pemEncoded: stranger.certificatePEM).publicKey != authorityKey)
    }

    // MARK: - Fixed instants

    @Test("The fixed instants are the dates their names say")
    func instants() {
        #expect(TestInstant.longLivedStart.formatted(.iso8601) == "2019-01-01T00:00:00Z")
        #expect(TestInstant.longLivedEnd.formatted(.iso8601) == "2090-01-01T00:00:00Z")
        #expect(TestInstant.shortLivedEnd.formatted(.iso8601) == "2021-01-01T00:00:00Z")
        #expect(TestInstant.duringShortLived.formatted(.iso8601) == "2020-07-01T00:00:00Z")
        #expect(TestInstant.beforeAnything.formatted(.iso8601) == "2018-01-01T00:00:00Z")
        #expect(TestInstant.now.formatted(.iso8601) == "2026-10-06T00:00:00Z")
    }

    // MARK: - The injected generator

    /// The contract: a key's scalar is the next 32 bytes, each generated word contributing
    /// its bytes most significant first. So the words 0, 0, 0, 1 are the private key 1, whose
    /// public key is the curve's base point — a value published with the curve.
    @Test("A leaf's key is the scalar the generator supplied")
    func keyComesFromTheGenerator() throws {
        let generator = ScriptedGenerator(
            Self.authorityDraws + [0, 0, 0, 1, 0x3333, 0x4444] + [0, 0, 0, 2], thereafter: 0x5555)
        let authority = try TestAuthority(commonName: "Scripted", generator: generator)

        let first = try authority.issueLeaf()
        let second = try authority.issueLeaf()

        #expect(first.publicKeySHA256 == (try P256Vector.publicKeySHA256(ofPoint: P256Vector.basePoint)))
        #expect(second.publicKeySHA256 == (try P256Vector.publicKeySHA256(ofPoint: P256Vector.twiceBasePoint)))
    }

    @Test("A draw that is not a valid scalar is discarded and the next one used")
    func invalidScalarsAreSkipped() throws {
        let zero: [UInt64] = [0, 0, 0, 0]
        let aboveTheOrder: [UInt64] = [.max, .max, .max, .max]
        let generator = ScriptedGenerator(
            Self.authorityDraws + zero + aboveTheOrder + [0, 0, 0, 1], thereafter: 0x5555)
        let authority = try TestAuthority(commonName: "Scripted", generator: generator)

        #expect(
            try authority.issueLeaf().publicKeySHA256 == (try P256Vector.publicKeySHA256(ofPoint: P256Vector.basePoint)))
    }

    @Test("A generator that never yields a valid scalar is an error, not a loop")
    func exhaustedGenerator() {
        #expect(throws: TestCertificateError.keyGenerationExhausted(attempts: 16)) {
            try TestAuthority(commonName: "Stuck", generator: ScriptedGenerator([], thereafter: 0))
        }
        #expect(
            TestCertificateError.keyGenerationExhausted(attempts: 16).description
                == "The generator produced no usable P-256 private key in 16 attempts. "
                + "It is probably not producing random bytes.")
    }

    @Test("The same generator gives the same keys, on any run")
    func sameGeneratorSameKeys() throws {
        let script = Self.authorityDraws + [0x0123_4567_89ab_cdef, 1, 2, 3]
        let one = try TestAuthority(commonName: "Seeded", generator: ScriptedGenerator(script, thereafter: 9))
        let other = try TestAuthority(commonName: "Seeded", generator: ScriptedGenerator(script, thereafter: 9))

        #expect(try one.issueLeaf().publicKeySHA256 == (try other.issueLeaf().publicKeySHA256))
    }

    // MARK: - What is issued, read back by swift-certificates

    @Test("A leaf is a server certificate for the names asked for, dated before Apple's 825-day rule")
    func leafContents() throws {
        let generator = ScriptedGenerator(
            Self.authorityDraws + [0, 0, 0, 1, 0xffff_ffff_ffff_ffff, 0x0102_0304_0506_0708], thereafter: 0x5555)
        let authority = try TestAuthority(commonName: "Scripted Authority", generator: generator)

        let leaf = try authority.issueLeaf(dnsNames: ["localhost", "tls.example"], ipv4Addresses: [[127, 0, 0, 1]])
        let certificate = try Certificate(pemEncoded: leaf.certificatePEM)

        #expect(certificate.notValidBefore == TestInstant.longLivedStart)
        #expect(certificate.notValidAfter == TestInstant.longLivedEnd)
        // 2019-07-01T00:00:00Z, the first instant Apple's limit applies to.
        #expect(certificate.notValidBefore < Date(timeIntervalSince1970: 1_561_939_200))
        #expect(certificate.issuer == (try DistinguishedName { CommonName("Scripted Authority") }))
        #expect(certificate.subject == (try DistinguishedName { CommonName("localhost") }))
        #expect(
            try certificate.extensions.subjectAlternativeNames == SubjectAlternativeNames([
                .dnsName("localhost"), .dnsName("tls.example"),
                .ipAddress(ASN1OctetString(contentBytes: [127, 0, 0, 1])),
            ]))
        #expect(try certificate.extensions.extendedKeyUsage == (try ExtendedKeyUsage([.serverAuth])))
        #expect(try certificate.extensions.basicConstraints == .notCertificateAuthority)
        // Sixteen bytes from the generator, the top bit cleared and the next set: 0xff → 0x7f.
        #expect(
            Array(certificate.serialNumber.bytes)
                == [0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    }

    @Test("The authority is a certificate authority, self-signed, with the dates it was given")
    func authorityContents() throws {
        let authority = try TestAuthority(
            commonName: "Dated Authority", notValidBefore: TestInstant.beforeAnything,
            notValidAfter: TestInstant.shortLivedEnd, generator: SeededGenerator(seed: TestSeed.authority))
        let certificate = try Certificate(pemEncoded: authority.certificatePEM)

        #expect(certificate.subject == (try DistinguishedName { CommonName("Dated Authority") }))
        #expect(certificate.issuer == certificate.subject)
        #expect(certificate.notValidBefore == TestInstant.beforeAnything)
        #expect(certificate.notValidAfter == TestInstant.shortLivedEnd)
        #expect(try certificate.extensions.basicConstraints == .isCertificateAuthority(maxPathLength: nil))
    }

    @Test("The chain is the leaf then the authority, as fullchain.pem is")
    func chainOrder() throws {
        let authority = try systemAuthority()
        let leaf = try authority.issueLeaf()

        #expect(leaf.chainPEM == leaf.certificatePEM + "\n" + authority.certificatePEM + "\n")
        let parsed = try NIOSSLCertificate.fromPEMBytes(Array(leaf.chainPEM.utf8))
        #expect(parsed.count == 2)
    }

    @Test("A renewal that reuses a key has the same public key and a different certificate")
    func reusedKey() throws {
        let authority = try systemAuthority()
        let original = try authority.issueLeaf()

        let renewed = try authority.issueLeaf(reusingKeyOf: original)

        #expect(renewed.publicKeySHA256 == original.publicKeySHA256)
        #expect(renewed.privateKeyPEM == original.privateKeyPEM)
        #expect(renewed.certificateSHA256 != original.certificateSHA256)
        #expect(renewed.certificateSHA256.count == 64)
    }

    // MARK: - Trusting the authority

    @Test("The authority's trust is itself and nothing else, and its fingerprint is the one SwiftTLSKit reports")
    func trust() throws {
        let authority = try systemAuthority()

        #expect(authority.asRoot == .pem(authority.certificatePEM))
        #expect(authority.clientTrust == .onlyRoots([.pem(authority.certificatePEM)]))
        // Two computations of the same digest: swift-certificates and swift-crypto in the
        // support product, NIOSSL and SwiftTLSKit in the library.
        #expect(try authority.clientContext().rootFingerprints == [authority.certificateSHA256])
    }

    // MARK: - A server context without a key on disk

    @Test("A leaf is served from memory, and a client trusting its authority connects")
    func servedFromMemory() async throws {
        let authority = try systemAuthority()
        let leaf = try authority.issueLeaf(dnsNames: ["localhost", "tls.example"])
        let context = try leaf.serverContext(options: ServerTLSOptions(minimumVersion: .tls13), now: TestInstant.now)
        let server = try await LoopbackServer.start(serving: context)

        let client = try await LoopbackClient.connect(
            port: server.port, context: try authority.clientContext(), serverHostname: "tls.example")

        #expect(client.report.peerCertificateSHA256 == leaf.certificateSHA256)
        #expect(client.report.tlsVersion == .tlsv13)
        #expect(context.leaf.subjectAlternativeNames == ["localhost", "tls.example"])
        #expect(context.leaf.certificateSHA256 == leaf.certificateSHA256)
        #expect(context.leaf.publicKeySHA256 == leaf.publicKeySHA256)
        #expect(try leaf.summary(now: TestInstant.now) == context.leaf)
        try await client.close()
        try await server.stop()
    }

    @Test("Memory is not a way round validation: an expired or premature leaf is still refused")
    func inMemoryStillValidates() throws {
        let authority = try systemAuthority()
        let shortLived = try authority.issueLeaf(notValidAfter: TestInstant.shortLivedEnd)

        #expect(try shortLived.serverContext(now: TestInstant.duringShortLived).leaf.notValidAfter == TestInstant.shortLivedEnd)
        #expect(
            throws: ServerIdentityError.expired(
                path: "<in-memory certificate chain>", notValidAfter: TestInstant.shortLivedEnd)
        ) {
            try shortLived.serverContext(now: TestInstant.now)
        }
        #expect(
            throws: ServerIdentityError.notYetValid(
                path: "<in-memory certificate chain>", notValidBefore: TestInstant.longLivedStart)
        ) {
            try shortLived.summary(now: TestInstant.beforeAnything)
        }
    }

    // MARK: - Reloading from memory

    @Test("An in-memory identity reloads like files do: unchanged, renewed, and refused")
    func reloadFromMemory() async throws {
        let authority = try systemAuthority()
        let first = try authority.issueLeaf()
        let second = try authority.issueLeaf()
        let expiring = try authority.issueLeaf(notValidAfter: TestInstant.shortLivedEnd)
        let identity = InMemoryServerIdentity(first)
        let tls = try identity.reloadableServerTLS(now: { TestInstant.now })
        let server = try await LoopbackServer.start { pipeline in try tls.addHandler(to: pipeline) }
        let firstSummary = try first.summary(now: TestInstant.now)
        let secondSummary = try second.summary(now: TestInstant.now)

        #expect(
            tls.identity == ServerIdentity(
                certificateChainPath: "<in-memory certificate chain>", privateKeyPath: "<in-memory private key>"))
        #expect(identity.leaf.certificateSHA256 == first.certificateSHA256)
        #expect(tls.reloadIfChanged() == .unchanged(serving: firstSummary))

        identity.replace(with: second)
        #expect(identity.leaf.certificateSHA256 == second.certificateSHA256)
        // Replacing is the renewal, not the reload: until asked, the old one is still served.
        #expect(tls.current.leaf == firstSummary)
        #expect(tls.reloadIfChanged() == .reloaded(serving: secondSummary, replacing: firstSummary))
        #expect(tls.reload() == .reloaded(serving: secondSummary, replacing: secondSummary))

        let client = try await LoopbackClient.connect(
            port: server.port, context: try authority.clientContext(), serverHostname: "localhost")
        #expect(client.report.peerCertificateSHA256 == second.certificateSHA256)
        try await client.close()

        identity.replace(with: expiring)
        #expect(
            tls.reload() == .failed(
                .expired(path: "<in-memory certificate chain>", notValidAfter: TestInstant.shortLivedEnd),
                stillServing: secondSummary))
        #expect(tls.current.leaf == secondSummary)
        try await server.stop()
    }

    @Test("An in-memory identity that is not valid at the start is an error")
    func reloadableFromMemoryValidatesAtStart() throws {
        let authority = try systemAuthority()
        let identity = InMemoryServerIdentity(try authority.issueLeaf(notValidAfter: TestInstant.shortLivedEnd))

        #expect(
            throws: ServerIdentityError.expired(
                path: "<in-memory certificate chain>", notValidAfter: TestInstant.shortLivedEnd)
        ) {
            try identity.reloadableServerTLS(now: { TestInstant.now })
        }
    }

    // MARK: - The 825-day rule the dates are chosen around

    /// The reason every default date is what it is, shown rather than asserted in a comment.
    /// A long-lived leaf dated after 1 July 2019 is refused where the system's roots are
    /// consulted on an Apple platform; one with the default dates, and otherwise identical, is
    /// accepted; and where only supplied roots are trusted, neither is refused.
    ///
    /// The refused leaf is dated 2 July 2019, a day inside the rule, not at its first second.
    /// Where exactly Security.framework draws the line is Apple's to move — measured by
    /// bisection on macOS 27 it is 2019-06-30T23:00:00Z, an hour before 1 July in UTC — and a
    /// test pinned to that second would be a test of Apple's constant.
    @Test("A long-lived leaf is accepted with the system's roots consulted only if it is dated before 1 July 2019")
    func eightHundredAndTwentyFiveDays() async throws {
        let authority = try systemAuthority()
        let secondOfJuly2019 = Date(timeIntervalSince1970: 1_562_025_600)
        let datedBeforeTheRule = try authority.issueLeaf()
        let datedUnderTheRule = try authority.issueLeaf(notValidBefore: secondOfJuly2019)
        let consultingSystemRoots = try ClientTLSContext(trust: .additionalRoots([authority.asRoot]))
        let onlyAuthority = try authority.clientContext()
        #if canImport(Darwin)
        let expectedUnderTheRule: ClientHandshakeFailure? = .certificateNotTrusted
        #else
        let expectedUnderTheRule: ClientHandshakeFailure? = nil
        #endif

        #expect(secondOfJuly2019.formatted(.iso8601) == "2019-07-02T00:00:00Z")
        for (leaf, expected) in [(datedBeforeTheRule, nil), (datedUnderTheRule, expectedUnderTheRule)] {
            let server = try await LoopbackServer.start(serving: try leaf.serverContext(now: TestInstant.now))
            let withSystemRoots = await handshakeFailure {
                try await LoopbackClient.connect(port: server.port, context: consultingSystemRoots, serverHostname: "localhost")
            }
            let withOnlyAuthority = await handshakeFailure {
                try await LoopbackClient.connect(port: server.port, context: onlyAuthority, serverHostname: "localhost")
            }
            #expect(withSystemRoots == expected)
            #expect(withOnlyAuthority == nil)
            try await server.stop()
        }
    }
}
