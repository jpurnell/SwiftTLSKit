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
        subjectAlternativeNames = certificate._subjectAlternativeNames().compactMap(Self.name)
        notValidBefore = Date(timeIntervalSince1970: TimeInterval(certificate.notValidBefore))
        notValidAfter = Date(timeIntervalSince1970: TimeInterval(certificate.notValidAfter))
        certificateSHA256 = SHA256Hex.digest(of: try certificate.toDERBytes())
        publicKeySHA256 = SHA256Hex.digest(of: try certificate.extractPublicKey().toSPKIBytes())
    }

    private static let ipv4ByteCount = 4
    private static let ipv6ByteCount = 16
    private static let ipv6GroupByteCount = 2

    /// A subject alternative name as text, or `nil` for the kinds that do not name a host.
    private static func name(_ alternativeName: _SubjectAlternativeName) -> String? {
        let bytes = Array(alternativeName.contents)
        switch alternativeName.nameType {
        case .dnsName:
            return String(decoding: bytes, as: UTF8.self)
        case .ipAddress where bytes.count == ipv4ByteCount:
            return bytes.map { String($0) }.joined(separator: ".")
        case .ipAddress where bytes.count == ipv6ByteCount:
            return stride(from: 0, to: ipv6ByteCount, by: ipv6GroupByteCount).map { index in
                String(UInt16(bytes[index]) << 8 | UInt16(bytes[index + 1]), radix: 16)
            }.joined(separator: ":")
        default:
            return nil
        }
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
