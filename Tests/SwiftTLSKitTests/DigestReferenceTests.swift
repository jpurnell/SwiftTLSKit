import NIOSSL
@testable import SwiftTLSKit
import Testing

/// The digests a pin is compared with, against the tool an operator copies them from.
///
/// Every other test that touches a digest computes it with this package on both sides, so a
/// systematic error — hashing the wrong bytes — would agree with itself. These two constants
/// were computed by OpenSSL 4.1.0 from the certificate below, and nothing else:
///
///     openssl x509 -in leaf.pem -noout -fingerprint -sha256
///     openssl x509 -in leaf.pem -noout -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256
///
/// The certificate is a leaf the test-support product issued (seed `TestSeed.authority`, name
/// `pin.example`). It is public, and there is no key with it.
@Suite("Digests against openssl")
struct DigestReferenceTests {
    private static let certificate = """
-----BEGIN CERTIFICATE-----
MIIBbjCCARWgAwIBAgIQecE4zhs91ZD3UxI7pEcUjDAKBggqhkjOPQQDAjAMMQow
CAYDVQQDDAFBMCAXDTE5MDEwMTAwMDAwMFoYDzIwOTAwMTAxMDAwMDAwWjAWMRQw
EgYDVQQDDAtwaW4uZXhhbXBsZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHor
YzstiLSAjuoWgvZPb5WrxBLDpgD8WqMyrTWnpJDfiKZZU3t3IP5f/TOTf8eE4Pk6
FsTEcBrNKc11tubFIbGjTTBLMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA
MBMGA1UdJQQMMAoGCCsGAQUFBwMBMBYGA1UdEQQPMA2CC3Bpbi5leGFtcGxlMAoG
CCqGSM49BAMCA0cAMEQCICDwEegKTR33Lytjv9JlDA4J22TFG2owlZpCqveVwqM+
AiAUwVdz9zgjerfOOvIIhlnCSH/qhSshl3g2ppqig1CTyA==
-----END CERTIFICATE-----
"""
    private static let opensslCertificateSHA256 = "31733cb60d17299bf29dcc659648c5336c04984f909c4039531145139205a346"
    private static let opensslPublicKeySHA256 = "5cb1c614f591a9eaf606ac5b7b47379bf4e5cf71493b078c1e561f67a3aee6d8"

    private func summary() throws -> CertificateSummary {
        try CertificateSummary(NIOSSLCertificate(bytes: Array(Self.certificate.utf8), format: .pem))
    }

    @Test("A certificate's SHA-256 is the one openssl prints")
    func certificateDigest() throws {
        #expect(try summary().certificateSHA256 == Self.opensslCertificateSHA256)
    }

    @Test("A public key's SHA-256 is the one openssl computes over its SubjectPublicKeyInfo")
    func publicKeyDigest() throws {
        #expect(try summary().publicKeySHA256 == Self.opensslPublicKeySHA256)
    }

    @Test("A pin written from openssl's output is a pin on that certificate")
    func pinFromOpenSSLOutput() throws {
        let colons = stride(from: 0, to: 64, by: 2).map { index -> String in
            let start = Self.opensslCertificateSHA256.index(Self.opensslCertificateSHA256.startIndex, offsetBy: index)
            return String(Self.opensslCertificateSHA256[start..<Self.opensslCertificateSHA256.index(start, offsetBy: 2)]).uppercased()
        }.joined(separator: ":")
        let pin = try CertificatePin.certificate(sha256: colons)
        #expect(pin.sha256 == Self.opensslCertificateSHA256)
        #expect(try summary().certificateSHA256 == pin.sha256)
    }
}
