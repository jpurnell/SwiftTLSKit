import Foundation

/// Why a server identity was refused.
///
/// Every case names the path concerned and the reason. None carries anything read from a file:
/// a refusal is written to logs and shown to operators, and a private key must not follow it
/// there.
public enum ServerIdentityError: Error, Sendable, Hashable {
    /// Which of the two files an identity is made of.
    public enum Component: Sendable, Hashable {
        /// The PEM certificate chain.
        case certificateChain
        /// The PEM private key.
        case privateKey
    }

    /// Exactly one of the certificate chain and the private key was supplied.
    ///
    /// This is the defect the package exists to remove: the code it replaces built a TLS
    /// context only when both were present, so one without the other served plaintext.
    ///
    /// - Parameters:
    ///   - present: The half that was supplied.
    ///   - path: The path supplied for it.
    case incompletePair(present: Component, path: String)

    /// The file could not be opened or read.
    ///
    /// - Parameters:
    ///   - path: The file.
    ///   - reason: The operating system's description of the failure.
    case unreadable(path: String, reason: String)

    /// The path names something other than a regular file — a directory, a FIFO, a device.
    ///
    /// - Parameter path: The path.
    case notRegularFile(path: String)

    /// The file is larger than any certificate chain or private key.
    ///
    /// - Parameters:
    ///   - path: The file.
    ///   - limit: The largest size accepted, in bytes.
    case fileTooLarge(path: String, limit: Int)

    /// The private key can be read or written by its group or by others.
    ///
    /// - Parameters:
    ///   - path: The key file.
    ///   - mode: Its permission bits.
    case privateKeyPermissionsTooOpen(path: String, mode: UInt16)

    /// The certificate chain file holds no certificate.
    ///
    /// - Parameter path: The chain file.
    case emptyCertificateChain(path: String)

    /// The certificate chain file holds a certificate that cannot be parsed.
    ///
    /// - Parameter path: The chain file.
    case invalidCertificateChain(path: String)

    /// The private key file does not hold an unencrypted PEM private key.
    ///
    /// - Parameter path: The key file.
    case invalidPrivateKey(path: String)

    /// The private key is not the one the leaf certificate was issued for.
    ///
    /// - Parameters:
    ///   - certificateChainPath: The chain file.
    ///   - privateKeyPath: The key file.
    case privateKeyDoesNotMatchCertificate(certificateChainPath: String, privateKeyPath: String)

    /// The leaf certificate's validity ended before the time supplied.
    ///
    /// - Parameters:
    ///   - path: The chain file.
    ///   - notValidAfter: The last instant at which the leaf was valid.
    case expired(path: String, notValidAfter: Date)

    /// The leaf certificate's validity begins after the time supplied.
    ///
    /// - Parameters:
    ///   - path: The chain file.
    ///   - notValidBefore: The first instant at which the leaf is valid.
    case notYetValid(path: String, notValidBefore: Date)

    /// The TLS library refused the identity for a reason not covered above.
    ///
    /// - Parameter reason: The library's description. It describes the failure, not the files.
    case contextRejected(reason: String)
}

extension ServerIdentityError: CustomStringConvertible {
    /// A sentence for a log line or a start-up failure, naming the path and what to do.
    public var description: String {
        switch self {
        case .incompletePair(.certificateChain, let path):
            return "A TLS certificate chain was given (\(path)) without a private key. " + Self.pairRemedy
        case .incompletePair(.privateKey, let path):
            return "A TLS private key was given (\(path)) without a certificate chain. " + Self.pairRemedy
        case .unreadable(let path, let reason):
            return "Cannot read \(path): \(reason)."
        case .notRegularFile(let path):
            return "\(path) is not a regular file."
        case .fileTooLarge(let path, let limit):
            return "\(path) is larger than \(limit) bytes, which no certificate chain or private key is."
        case .privateKeyPermissionsTooOpen(let path, let mode):
            return "The private key at \(path) has mode \(Self.octal(mode)), "
                + "which lets group or others read or write it. Run: chmod 600 \(path)"
        case .emptyCertificateChain(let path):
            return "\(path) holds no certificates."
        case .invalidCertificateChain(let path):
            return "\(path) holds a certificate that cannot be read as PEM."
        case .invalidPrivateKey(let path):
            return "\(path) does not hold a private key that can be read as unencrypted PEM."
        case .privateKeyDoesNotMatchCertificate(let certificateChainPath, let privateKeyPath):
            return "The private key at \(privateKeyPath) does not match the leaf certificate in \(certificateChainPath)."
        case .expired(let path, let notValidAfter):
            return "The leaf certificate in \(path) expired at \(notValidAfter.formatted(.iso8601))."
        case .notYetValid(let path, let notValidBefore):
            return "The leaf certificate in \(path) is not valid until \(notValidBefore.formatted(.iso8601))."
        case .contextRejected(let reason):
            return "The TLS library refused this identity: \(reason)."
        }
    }

    private static let pairRemedy =
        "Supply both to serve TLS, or neither to serve plaintext; one without the other is refused."

    /// Permission bits as `chmod` writes them: four octal digits.
    private static func octal(_ mode: UInt16) -> String {
        let digits = String(mode, radix: 8)
        return String(repeating: "0", count: max(0, 4 - digits.count)) + digits
    }
}
