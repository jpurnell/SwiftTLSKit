import Crypto
import Foundation
import NIOSSL

/// What a certificate says about itself: who it names, when it is valid, and its fingerprints.
///
/// Meant for a start-up log line, so that what a server is serving — and when it stops being
/// valid — is on record without anyone running `openssl` against the port.
public struct CertificateSummary: Sendable, Hashable {
    /// The DNS names and IP addresses in the certificate's subject alternative names, in the
    /// order the certificate lists them.
    ///
    /// Written as RFC 5952 writes an IPv6 address (`::1`). A DNS name that is empty or holds
    /// anything but printable ASCII is left out, so that a name cannot forge or hide a line in the
    /// log this is printed to.
    ///
    /// The common name is not included. Hostname verification ignores it when alternative
    /// names are present, so it says nothing about which names a client will accept.
    public let subjectAlternativeNames: [String]

    /// The first instant at which the certificate is valid.
    public let notValidBefore: Date

    /// The last instant at which the certificate is valid.
    public let notValidAfter: Date

    /// SHA-256 of the certificate's DER encoding, as lowercase hex.
    ///
    /// The value `openssl x509 -noout -fingerprint -sha256` prints, without the colons.
    public let certificateSHA256: String

    /// SHA-256 of the certificate's SubjectPublicKeyInfo, as lowercase hex.
    ///
    /// Unlike ``certificateSHA256`` this survives a renewal that keeps the same key.
    public let publicKeySHA256: String

    /// Reads a certificate.
    ///
    /// - Parameter certificate: The certificate.
    /// - Throws: Whatever NIOSSL throws if the certificate cannot be re-encoded.
    init(_ certificate: NIOSSLCertificate) throws {
        let der = try certificate.toDERBytes()
        subjectAlternativeNames = DERSubjectAlternativeNames.names(inCertificateDER: der)
        notValidBefore = Date(timeIntervalSince1970: TimeInterval(certificate.notValidBefore))
        notValidAfter = Date(timeIntervalSince1970: TimeInterval(certificate.notValidAfter))
        certificateSHA256 = SHA256Hex.digest(of: der)
        publicKeySHA256 = SHA256Hex.digest(of: try certificate.extractPublicKey().toSPKIBytes())
    }
}

extension CertificateSummary: CustomStringConvertible {
    /// One line: the names, the validity period, and the certificate's SHA-256.
    public var description: String {
        let names = subjectAlternativeNames.isEmpty ? "(no names)" : subjectAlternativeNames.joined(separator: ", ")
        return "\(names); valid \(notValidBefore.formatted(.iso8601)) to \(notValidAfter.formatted(.iso8601)); "
            + "SHA-256 \(certificateSHA256)"
    }
}

/// SHA-256 as the lowercase hex an operator compares against `openssl`.
enum SHA256Hex {
    private static let hexRadix = 16
    private static let hexDigitsPerByte = 2

    static func digest(of bytes: [UInt8]) -> String {
        encode(Array(SHA256.hash(data: bytes)))
    }

    static func encode(_ bytes: [UInt8]) -> String {
        bytes.map { byte in
            let digits = String(byte, radix: hexRadix)
            return String(repeating: "0", count: hexDigitsPerByte - digits.count) + digits
        }.joined()
    }
}
