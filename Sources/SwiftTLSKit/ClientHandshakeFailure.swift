import NIOSSL

/// Why a client's TLS handshake failed, as one of a few things a caller can act on.
///
/// A failed handshake reaches a client as whatever error came down the channel pipeline — from
/// NIOSSL, from BoringSSL underneath it, or from this package's pin check. Telling them apart
/// means naming NIOSSL's error types and reading BoringSSL's reason codes, which a consumer
/// should not have to take a dependency on swift-nio-ssl to do, and should not have to copy.
/// This does it once:
///
/// ```swift
/// import SwiftTLSKit
///
/// func explain(_ error: any Error, host: String) -> String {
///     switch ClientHandshakeFailure(error) {
///     case .certificateNotTrusted: return "\(host) presented a certificate this client does not trust."
///     case .hostnameMismatch: return "The certificate was not issued for \(host)."
///     case .pinMismatch(let certificate, _): return "\(host) served \(certificate), which is not pinned."
///     case .peerDoesNotSpeakTLS: return "\(host) is not serving TLS on that port."
///     case .noSharedProtocolVersion: return "\(host) and this client share no TLS version."
///     case .other(let reason): return "The handshake with \(host) failed: \(reason)"
///     }
/// }
/// print(explain(ClientTrustError.pinMismatch(certificateSHA256: "ab12", publicKeySHA256: "cd34"), host: "example.com"))
/// // Prints "example.com served ab12, which is not pinned."
/// ```
///
/// Classify an error from a connection whose handshake had not completed. An error that
/// arrives later is not a handshake failure, and nothing here can tell: the caller knows
/// whether the handshake finished, and this type does not.
///
/// ## A wrong hostname on Apple platforms
///
/// A certificate that is trusted but was issued for a different host is
/// ``hostnameMismatch`` — **except** on Apple platforms when the system's root store is part
/// of the trust, where it is ``certificateNotTrusted``.
///
/// The reason is who does the verifying. When only supplied roots are trusted
/// (``ClientTrust/onlyRoots(_:)``), BoringSSL validates the chain and NIOSSL then checks the
/// name, as two steps with two errors. When the system's roots are consulted —
/// ``ClientTrust/systemRoots``, ``ClientTrust/additionalRoots(_:)`` and
/// ``ClientTrust/pinned(_:additionalRoots:)`` — an Apple platform verifies through
/// Security.framework, which judges the chain and the name together and returns one verdict.
/// The connection is refused either way; only the classification differs.
///
/// So on an Apple platform ``certificateNotTrusted`` under those three trusts means "not
/// trusted, *or* trusted and issued for another host", and a message built on it should not
/// claim the first alone. ``ClientTrust/consultsSystemRoots`` says which trusts are affected,
/// and ``wrongHostname(under:)`` says which case a wrong hostname produces for a given trust
/// on the platform the code is running on.
///
/// The same path has a second consequence that looks like an untrusted chain and is not:
/// Security.framework refuses a server certificate issued on or after 1 July 2019 that is
/// valid for more than 825 days, whoever signed it. A long-lived certificate from a private
/// authority trusted with ``ClientTrust/additionalRoots(_:)`` is ``certificateNotTrusted`` for
/// that reason alone.
public enum ClientHandshakeFailure: Sendable, Hashable {
    /// Certificate verification refused the server: the chain does not lead to a trusted root,
    /// or a certificate in it is expired, not yet valid, or otherwise unacceptable.
    ///
    /// On an Apple platform, when the system's roots are consulted, a certificate issued for a
    /// different host is reported as this case too. See the discussion on
    /// ``ClientHandshakeFailure``.
    case certificateNotTrusted

    /// The chain was trusted, and the certificate was not issued for the host that was dialled.
    case hostnameMismatch

    /// The chain and the hostname were valid, and the leaf matched none of the client's pins.
    ///
    /// - Parameters:
    ///   - certificateSHA256: SHA-256 of the certificate the server presented, lowercase hex.
    ///   - publicKeySHA256: SHA-256 of its SubjectPublicKeyInfo, lowercase hex.
    case pinMismatch(certificateSHA256: String, publicKeySHA256: String)

    /// The peer answered, and what it sent was not TLS.
    ///
    /// The usual cause is a plaintext listener: `wss://` dialled at a `ws://` port, or `https`
    /// at an `http` one. A peer that closes the connection without sending anything is *not*
    /// this case — nothing arrived to judge — and is ``other(_:)``.
    case peerDoesNotSpeakTLS

    /// The two sides support no TLS version in common.
    case noSharedProtocolVersion

    /// Anything else.
    ///
    /// - Parameter reason: `String(describing:)` of the error, for a log line. It is the TLS
    ///   library's wording and is not stable across its versions; match on the cases above,
    ///   not on this text.
    case other(String)

    /// Classifies an error from a client connection whose TLS handshake did not complete.
    ///
    /// - Parameter error: The error the pipeline delivered — to `errorCaught`, or as the
    ///   failure of the future or task that was waiting for the handshake.
    public init(_ error: any Error) {
        if case .pinMismatch(let certificateSHA256, let publicKeySHA256)? = error as? ClientTrustError {
            self = .pinMismatch(certificateSHA256: certificateSHA256, publicKeySHA256: publicKeySHA256)
        } else if let extra = error as? NIOSSLExtraError, extra == .failedToValidateHostname {
            self = .hostnameMismatch
        } else if let reason = Self.boringSSLErrors(in: error).lazy.compactMap(Self.classify).first {
            self = reason
        } else {
            self = .other(String(describing: error))
        }
    }

    /// What a certificate that is trusted, but issued for a different host, is classified as
    /// under `trust` on the platform this code is running on.
    ///
    /// ``hostnameMismatch``, unless the system's roots are consulted on an Apple platform, in
    /// which case ``certificateNotTrusted``. See the discussion on ``ClientHandshakeFailure``.
    /// It exists so that a test which dials the wrong name can state its expectation once, for
    /// every trust and every platform.
    ///
    /// - Parameter trust: The trust the client was built with.
    /// - Returns: The case a wrong hostname produces.
    public static func wrongHostname(under trust: ClientTrust) -> ClientHandshakeFailure {
        #if canImport(Darwin)
        return trust.consultsSystemRoots ? .certificateNotTrusted : .hostnameMismatch
        #else
        return .hostnameMismatch
        #endif
    }
}

extension ClientHandshakeFailure: CustomStringConvertible {
    /// A sentence for a log line or an error alert.
    public var description: String {
        switch self {
        case .certificateNotTrusted:
            return "The server's certificate is not trusted: its chain does not lead to a trusted root, or is "
                + "expired or otherwise invalid."
        case .hostnameMismatch:
            return "The server's certificate is trusted, but was not issued for the host that was dialled."
        case .pinMismatch(let certificateSHA256, let publicKeySHA256):
            return ClientTrustError.pinMismatch(
                certificateSHA256: certificateSHA256, publicKeySHA256: publicKeySHA256
            ).description
        case .peerDoesNotSpeakTLS:
            return "The peer answered with something that is not TLS. It is probably a plaintext listener."
        case .noSharedProtocolVersion:
            return "The client and the server support no TLS version in common."
        case .other(let reason):
            return "The TLS handshake failed: \(reason)"
        }
    }
}

// MARK: - Reading BoringSSL's errors

extension ClientHandshakeFailure {
    /// BoringSSL's numbering, from `CNIOBoringSSL_err.h` and `CNIOBoringSSL_ssl.h`. These are
    /// part of its ABI: an error is packed as library in the top byte and reason in the low
    /// twelve bits.
    private enum BoringSSL {
        /// `ERR_LIB_SSL`.
        static let sslLibrary: UInt32 = 16
        static let libraryShift: UInt32 = 24
        static let libraryMask: UInt32 = 0xff
        static let reasonMask: UInt32 = 0xfff

        /// `SSL_R_CERTIFICATE_VERIFY_FAILED`.
        static let certificateVerifyFailed: UInt32 = 125
        /// `SSL_R_WRONG_VERSION_NUMBER`: the bytes received are not a TLS record. What a
        /// client reads when the peer answers in plaintext.
        static let wrongVersionNumber: UInt32 = 247
        /// `SSL_R_UNSUPPORTED_PROTOCOL`: the server chose a version this client does not accept.
        static let unsupportedProtocol: UInt32 = 240
        /// `SSL_R_TLSV1_ALERT_PROTOCOL_VERSION`: the server refused every version this client
        /// offered, and said so with a `protocol_version` alert.
        static let alertProtocolVersion: UInt32 = 1070
    }

    /// The prefix NIOSSL puts before BoringSSL's packed error code in an error's description.
    private static let codePrefix = "Error: "

    /// The BoringSSL errors a handshake failure carries, oldest first, or none if `error` is
    /// not one.
    private static func boringSSLErrors(in error: any Error) -> [BoringSSLInternalError] {
        let underlying: BoringSSLError
        switch error {
        case NIOSSLError.handshakeFailed(let failure):
            underlying = failure
        case let failure as BoringSSLError:
            underlying = failure
        default:
            return []
        }
        guard case .sslError(let stack) = underlying else { return [] }
        return stack
    }

    /// The class one BoringSSL error belongs to, or `nil` if it is none of them.
    ///
    /// NIOSSL keeps the packed code private and prints it first in the description, in decimal,
    /// so that is where it is read from. The number is compared, not the reason's name: the
    /// name comes from a string table, and the number is the thing the table is indexed by.
    private static func classify(_ error: BoringSSLInternalError) -> ClientHandshakeFailure? {
        let description = error.description
        guard description.hasPrefix(codePrefix) else { return nil }
        let digits = description.dropFirst(codePrefix.count).prefix { $0.isASCII && $0.isNumber }
        guard let code = UInt32(digits) else { return nil }
        guard (code >> BoringSSL.libraryShift) & BoringSSL.libraryMask == BoringSSL.sslLibrary else { return nil }
        switch code & BoringSSL.reasonMask {
        case BoringSSL.certificateVerifyFailed:
            return .certificateNotTrusted
        case BoringSSL.wrongVersionNumber:
            return .peerDoesNotSpeakTLS
        case BoringSSL.unsupportedProtocol, BoringSSL.alertProtocolVersion:
            return .noSharedProtocolVersion
        default:
            return nil
        }
    }
}

extension ClientTrust {
    /// Whether the platform's root store is part of this trust.
    ///
    /// `true` for every case except ``onlyRoots(_:)``. Besides saying whose signatures count,
    /// it says who does the verifying on an Apple platform — Security.framework when the
    /// system's roots are consulted, BoringSSL when they are not — which changes how a wrong
    /// hostname is reported. See ``ClientHandshakeFailure``.
    public var consultsSystemRoots: Bool {
        switch self {
        case .systemRoots, .additionalRoots, .pinned: return true
        case .onlyRoots: return false
        }
    }
}
