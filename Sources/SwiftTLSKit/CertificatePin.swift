import Foundation

/// The SHA-256 digest a server's certificate, or its public key, must have.
///
/// A pin is an extra condition, never a replacement: a pinned connection still validates the
/// chain and the hostname, and then also requires the leaf to match. See
/// ``ClientTrust/pinned(_:additionalRoots:)``.
///
/// ```swift
/// import SwiftTLSKit
///
/// let pin = try CertificatePin.publicKey(
///     sha256: "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF")
/// print(pin)
/// // Prints "public key SHA-256 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
/// ```
public struct CertificatePin: Sendable, Hashable {
    /// What a pin's digest is taken over.
    public enum Subject: Sendable, Hashable {
        /// The whole certificate, DER-encoded. Changes at every renewal.
        case certificate
        /// The certificate's SubjectPublicKeyInfo. Survives a renewal that keeps the same key.
        case publicKey
    }

    /// What the digest is taken over.
    public let subject: Subject

    /// The digest, as 64 lowercase hexadecimal digits.
    public let sha256: String

    /// Pins the server's leaf certificate.
    ///
    /// The digest is the one `openssl x509 -noout -fingerprint -sha256` prints, and the one
    /// ``CertificateSummary/certificateSHA256`` reports.
    ///
    /// - Parameter sha256: The digest: 64 hexadecimal digits in either case, with or without
    ///   `:` between bytes, or 44 characters of base64.
    /// - Returns: The pin.
    /// - Throws: ``ClientTrustError/invalidPin(_:)`` if `sha256` is not a SHA-256 digest.
    public static func certificate(sha256: String) throws(ClientTrustError) -> CertificatePin {
        CertificatePin(subject: .certificate, sha256: try normalise(sha256))
    }

    /// Pins the server's public key.
    ///
    /// The digest is over the SubjectPublicKeyInfo, as ``CertificateSummary/publicKeySHA256``
    /// reports it.
    ///
    /// - Parameter sha256: The digest: 64 hexadecimal digits in either case, with or without
    ///   `:` between bytes, or 44 characters of base64.
    /// - Returns: The pin.
    /// - Throws: ``ClientTrustError/invalidPin(_:)`` if `sha256` is not a SHA-256 digest.
    public static func publicKey(sha256: String) throws(ClientTrustError) -> CertificatePin {
        CertificatePin(subject: .publicKey, sha256: try normalise(sha256))
    }

    private static let digestByteCount = 32
    private static let hexDigitCount = 64
    private static let separator: Character = ":"
    private static let digitsPerByte = 2

    private static func isHexDigest(_ text: String) -> Bool {
        text.count == hexDigitCount && text.allSatisfy { $0.isASCII && $0.isHexDigit }
    }

    /// `text` without the colons, if there is one between each pair of digits and nowhere else —
    /// the way `openssl` prints a digest — and `nil` if there is a colon anywhere else.
    private static func removingByteSeparators(from text: String) -> String? {
        let pairs = text.split(separator: separator, omittingEmptySubsequences: false)
        guard pairs.count == digestByteCount, pairs.allSatisfy({ $0.count == digitsPerByte }) else { return nil }
        return pairs.joined()
    }

    private static func normalise(_ text: String) throws(ClientTrustError) -> String {
        let hex = text.lowercased()
        if isHexDigest(hex) { return hex }
        if let unseparated = removingByteSeparators(from: hex), isHexDigest(unseparated) { return unseparated }
        if let decoded = Data(base64Encoded: text), decoded.count == digestByteCount {
            return SHA256Hex.encode(Array(decoded))
        }
        throw .invalidPin(text)
    }
}

extension CertificatePin: CustomStringConvertible {
    /// The pin as a phrase: what is pinned, then the digest.
    public var description: String {
        switch subject {
        case .certificate: return "certificate SHA-256 \(sha256)"
        case .publicKey: return "public key SHA-256 \(sha256)"
        }
    }
}
