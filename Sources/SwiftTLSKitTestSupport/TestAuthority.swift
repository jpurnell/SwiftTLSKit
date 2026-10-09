import Crypto
import Foundation
import SwiftASN1
import SwiftTLSKit
import X509

/// A certificate authority made when a test runs, for issuing server certificates to test
/// against.
///
/// Its private key is generated in the test process and is never written anywhere. Nothing
/// trusts it except a client that is told to: ``clientTrust`` is that instruction.
///
/// ```swift
/// import SwiftTLSKit
/// import SwiftTLSKitTestSupport
///
/// let authority = try TestAuthority(commonName: "Test Authority", generator: SeededGenerator(seed: 1))
/// let leaf = try authority.issueLeaf(dnsNames: ["localhost"])
/// let server = try leaf.serverContext(now: TestInstant.now)
/// let client = try authority.clientContext()
/// print(server.leaf.subjectAlternativeNames, client.rootFingerprints.count)
/// // Prints "["localhost"] 1"
/// ```
///
/// ## The generator is the caller's
///
/// Every key and serial number comes from the generator passed to
/// ``init(commonName:notValidBefore:notValidAfter:generator:)``; this module never uses the
/// system's on its own account. Which generator is the test's decision:
///
/// - A **seeded** generator — ``SeededGenerator`` is one, so a test target need not write its
///   own — gives the same keys on every run, so a failure can be reproduced
///   exactly. Treat those keys as published — a key that can be derived from a seed in a
///   repository is a key in that repository. That is acceptable for a test authority because
///   nothing trusts it except a client a test builds to trust it.
/// - `SystemRandomNumberGenerator()` gives keys nobody can predict, and a suite that issues
///   different certificates on every run.
///
/// A seeded generator makes the *keys* and *serial numbers* reproducible. It does not make the
/// certificates byte-for-byte reproducible, because the signature on a certificate is made by
/// the platform's ECDSA, which is randomised and takes no generator. So ``TestLeaf/publicKeySHA256``
/// repeats under a seed and ``TestLeaf/certificateSHA256`` does not.
///
/// Two authorities made from generators in the same state have the same key. Tests that need
/// two different authorities need two seeds.
///
/// ## Dates
///
/// Everything is valid from ``TestInstant/longLivedStart`` to ``TestInstant/longLivedEnd``
/// unless a test says otherwise. The start is before 1 July 2019 so that Apple's 825-day limit
/// on server certificates does not apply; see ``TestInstant``.
public struct TestAuthority: Sendable {
    /// The authority's certificate, PEM-encoded — what a client is given to trust it.
    public let certificatePEM: String

    /// SHA-256 of the authority's certificate in DER, as lowercase hex.
    ///
    /// Computed by swift-certificates and swift-crypto, not by SwiftTLSKit, so that it can be
    /// compared with what SwiftTLSKit reports — ``SwiftTLSKit/ClientTLSContext/rootFingerprints``
    /// for one.
    public let certificateSHA256: String

    private let name: DistinguishedName
    private let key: P256.Signing.PrivateKey
    private let randomness: InjectedRandomness

    /// Makes an authority with a new key and a self-signed certificate.
    ///
    /// - Parameters:
    ///   - commonName: The authority's name, as certificates it issues will show it.
    ///   - notValidBefore: The start of the authority's own validity.
    ///   - notValidAfter: The end of the authority's own validity.
    ///   - generator: Where every key and serial number comes from, for this authority and
    ///     for every leaf it issues.
    /// - Throws: ``TestCertificateError`` if the generator yields no usable key, or
    ///   swift-certificates' error if the certificate cannot be built.
    public init(
        commonName: String,
        notValidBefore: Date = TestInstant.longLivedStart,
        notValidAfter: Date = TestInstant.longLivedEnd,
        generator: some RandomNumberGenerator & Sendable
    ) throws {
        let randomness = InjectedRandomness(generator)
        let key = try randomness.signingKey()
        let name = try DistinguishedName { CommonName(commonName) }
        let certificate = try Certificate(
            version: .v3,
            serialNumber: Self.serialNumber(from: randomness),
            publicKey: Certificate.PublicKey(key.publicKey),
            notValidBefore: notValidBefore,
            notValidAfter: notValidAfter,
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
                Critical(KeyUsage(keyCertSign: true))
            },
            issuerPrivateKey: Certificate.PrivateKey(key))
        self.name = name
        self.key = key
        self.randomness = randomness
        self.certificatePEM = try certificate.serializeAsPEM().pemString
        self.certificateSHA256 = try Self.sha256(of: certificate)
    }

    /// This authority's certificate, as a root a client can be told to trust.
    public var asRoot: CertificateSource {
        .pem(certificatePEM)
    }

    /// A trust that accepts this authority and nothing else.
    ///
    /// ``SwiftTLSKit/ClientTrust/onlyRoots(_:)``, so the system's roots are not consulted and
    /// the chain is verified by BoringSSL on every platform.
    public var clientTrust: ClientTrust {
        .onlyRoots([asRoot])
    }

    /// A client context that trusts this authority and nothing else.
    ///
    /// - Parameters:
    ///   - minimumVersion: The oldest TLS version accepted.
    ///   - applicationProtocols: The ALPN protocols offered, most preferred first.
    /// - Returns: The context.
    /// - Throws: ``SwiftTLSKit/ClientTrustError`` if the TLS library refuses the configuration.
    public func clientContext(
        minimumVersion: MinimumTLSVersion = .tls12,
        applicationProtocols: [String] = []
    ) throws(ClientTrustError) -> ClientTLSContext {
        try ClientTLSContext(
            trust: clientTrust, minimumVersion: minimumVersion, applicationProtocols: applicationProtocols)
    }

    /// Issues a server certificate.
    ///
    /// The certificate carries the server-authentication extended key usage and its names as
    /// subject alternative names, both of which Apple's policy requires of a server
    /// certificate.
    ///
    /// - Parameters:
    ///   - dnsNames: The DNS names the certificate is for. The first is also its common name.
    ///   - ipv4Addresses: IPv4 addresses the certificate is for, each as four bytes.
    ///   - notValidBefore: The start of validity. Leave it at ``TestInstant/longLivedStart``,
    ///     or anything before 1 July 2019, for a certificate that is to be long-lived and
    ///     still accepted where the system's roots are consulted on an Apple platform.
    ///   - notValidAfter: The end of validity.
    ///   - previous: A leaf whose key the new certificate is to be issued for, as a renewal
    ///     that keeps its key does. `nil` — the default — generates a new key.
    /// - Returns: The certificate and its key.
    /// - Throws: ``TestCertificateError`` if the generator yields no usable key, or
    ///   swift-certificates' error if the certificate cannot be built.
    public func issueLeaf(
        dnsNames: [String] = ["localhost"],
        ipv4Addresses: [[UInt8]] = [],
        notValidBefore: Date = TestInstant.longLivedStart,
        notValidAfter: Date = TestInstant.longLivedEnd,
        reusingKeyOf previous: TestLeaf? = nil
    ) throws -> TestLeaf {
        let leafKey = try previous?.key ?? randomness.signingKey()
        let names = dnsNames.map { GeneralName.dnsName($0) }
            + ipv4Addresses.map { GeneralName.ipAddress(ASN1OctetString(contentBytes: $0[...])) }
        let certificate = try Certificate(
            version: .v3,
            serialNumber: Self.serialNumber(from: randomness),
            publicKey: Certificate.PublicKey(leafKey.publicKey),
            notValidBefore: notValidBefore,
            notValidAfter: notValidAfter,
            issuer: name,
            subject: try DistinguishedName { CommonName(dnsNames.first ?? Self.unnamedSubject) },
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                Critical(KeyUsage(digitalSignature: true))
                try ExtendedKeyUsage([.serverAuth])
                SubjectAlternativeNames(names)
            },
            issuerPrivateKey: Certificate.PrivateKey(key))
        let certificatePEM = try certificate.serializeAsPEM().pemString
        return TestLeaf(
            certificatePEM: certificatePEM,
            chainPEM: certificatePEM + "\n" + self.certificatePEM + "\n",
            certificateSHA256: try Self.sha256(of: certificate),
            key: leafKey)
    }

    private static let unnamedSubject = "unnamed"
    private static let serialByteCount = 16
    /// Clears the top bit of a serial number's first byte, so that the number is positive
    /// however DER comes to encode it.
    private static let positiveMask: UInt8 = 0x7f
    /// Sets the bit below it, so that the number is never zero and always the same length.
    private static let nonZeroBit: UInt8 = 0x40

    private static func serialNumber(from randomness: InjectedRandomness) -> Certificate.SerialNumber {
        var bytes = randomness.bytes(count: serialByteCount)
        bytes[0] = (bytes[0] & positiveMask) | nonZeroBit
        return Certificate.SerialNumber(bytes: bytes)
    }

    private static func sha256(of certificate: Certificate) throws -> String {
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return LowercaseHex.encode(SHA256.hash(data: serializer.serializedBytes))
    }
}

/// Two lowercase hexadecimal digits per byte: the form `openssl` prints, without the colons.
enum LowercaseHex {
    private static let radix = 16
    private static let digitsPerByte = 2

    static func encode(_ bytes: some Sequence<UInt8>) -> String {
        bytes.map { byte in
            let digits = String(byte, radix: radix)
            return String(repeating: "0", count: digitsPerByte - digits.count) + digits
        }.joined()
    }
}
