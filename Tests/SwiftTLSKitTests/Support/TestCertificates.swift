import Crypto
import Foundation
import SwiftASN1
import X509

/// Fixed instants. Nothing in the tests reads the clock: certificates carry these, and the
/// library is handed one of them as "now".
enum TestInstant {
    /// 2019-01-01T00:00:00Z — the start of every long-lived test certificate.
    ///
    /// Before 1 July 2019 on purpose. On Apple platforms a client that consults the system
    /// root store verifies through Security.framework, which refuses a TLS server certificate
    /// issued on or after that date if it is valid for more than 825 days — whoever signed it.
    /// A certificate that short would have to be issued relative to the day the suite runs,
    /// which means reading the clock; one dated before the rule is long-lived and fixed.
    static let longLivedStart = Date(timeIntervalSince1970: 1_546_300_800)
    /// 2090-01-01T00:00:00Z — the end of every long-lived test certificate. Real handshakes
    /// are verified by BoringSSL against the machine's own clock, so this has to be later
    /// than any day the suite will run on.
    static let longLivedEnd = Date(timeIntervalSince1970: 3_786_912_000)
    /// 2021-01-01T00:00:00Z — the end of the short-lived certificate.
    static let shortLivedEnd = Date(timeIntervalSince1970: 1_609_459_200)
    /// 2020-07-01T00:00:00Z — inside the short-lived certificate's validity.
    static let duringShortLived = Date(timeIntervalSince1970: 1_593_561_600)
    /// 2018-01-01T00:00:00Z — before any test certificate is valid.
    static let beforeAnything = Date(timeIntervalSince1970: 1_514_764_800)
    /// 2026-10-06T00:00:00Z — the "now" handed to the library unless a test says otherwise.
    static let now = Date(timeIntervalSince1970: 1_791_244_800)
}

/// A certificate authority made when a test runs. Its key never leaves the test process.
struct TestAuthority {
    let name: DistinguishedName
    let key: P256.Signing.PrivateKey
    let certificate: Certificate

    init(commonName: String) throws {
        let key = P256.Signing.PrivateKey()
        let name = try DistinguishedName { CommonName(commonName) }
        self.key = key
        self.name = name
        self.certificate = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: Certificate.PublicKey(key.publicKey),
            notValidBefore: TestInstant.longLivedStart,
            notValidAfter: TestInstant.longLivedEnd,
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
                Critical(KeyUsage(keyCertSign: true))
            },
            issuerPrivateKey: Certificate.PrivateKey(key))
    }

    var certificatePEM: String {
        get throws { try certificate.serializeAsPEM().pemString }
    }

    /// Issues a server certificate naming `dnsNames` and `ipv4Addresses`.
    func issueLeaf(
        dnsNames: [String] = ["localhost"],
        ipv4Addresses: [[UInt8]] = [],
        notValidBefore: Date = TestInstant.longLivedStart,
        notValidAfter: Date = TestInstant.longLivedEnd,
        key existingKey: P256.Signing.PrivateKey? = nil
    ) throws -> TestLeaf {
        let leafKey = existingKey ?? P256.Signing.PrivateKey()
        let names = dnsNames.map { GeneralName.dnsName($0) }
            + ipv4Addresses.map { GeneralName.ipAddress(ASN1OctetString(contentBytes: $0[...])) }
        let leaf = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: Certificate.PublicKey(leafKey.publicKey),
            notValidBefore: notValidBefore,
            notValidAfter: notValidAfter,
            issuer: name,
            subject: try DistinguishedName { CommonName(dnsNames.first ?? "unnamed") },
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                Critical(KeyUsage(digitalSignature: true))
                try ExtendedKeyUsage([.serverAuth])
                SubjectAlternativeNames(names)
            },
            issuerPrivateKey: Certificate.PrivateKey(key))
        return TestLeaf(certificate: leaf, key: leafKey, issuerPEM: try certificatePEM)
    }
}

/// A server certificate and its key, made when a test runs.
struct TestLeaf {
    let certificate: Certificate
    let key: P256.Signing.PrivateKey
    let issuerPEM: String

    var certificatePEM: String {
        get throws { try certificate.serializeAsPEM().pemString }
    }

    /// Leaf first, then the issuer — the order `fullchain.pem` uses.
    var chainPEM: String {
        get throws { try certificatePEM + "\n" + issuerPEM + "\n" }
    }

    var keyPEM: String { key.pemRepresentation }

    /// SHA-256 of the certificate's DER, lowercase hex — what
    /// `openssl x509 -fingerprint -sha256` prints, without the colons. Derived from
    /// swift-certificates' own serialisation, not from the library under test.
    var certificateSHA256: String {
        get throws {
            var serializer = DER.Serializer()
            try serializer.serialize(certificate)
            return hex(SHA256.hash(data: serializer.serializedBytes))
        }
    }

    /// SHA-256 of the SubjectPublicKeyInfo DER, lowercase hex.
    var publicKeySHA256: String {
        hex(SHA256.hash(data: key.publicKey.derRepresentation))
    }

    private func hex(_ digest: SHA256.Digest) -> String {
        digest.map { byte in
            let text = String(byte, radix: 16)
            return text.count == 1 ? "0" + text : text
        }.joined()
    }
}

/// SHA-256 fingerprints computed by swift-certificates and swift-crypto, independently of the
/// library under test.
enum SHA256Fingerprint {
    static func ofPEMCertificate(_ pem: String) throws -> String {
        let certificate = try Certificate(pemEncoded: pem)
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return SHA256.hash(data: serializer.serializedBytes).map { byte in
            let text = String(byte, radix: 16)
            return text.count == 1 ? "0" + text : text
        }.joined()
    }
}
