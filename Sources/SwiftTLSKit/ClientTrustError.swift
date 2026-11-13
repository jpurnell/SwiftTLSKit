/// Why client trust could not be established.
///
/// Thrown when the trust is built — a root that cannot be read is a mistake in configuration,
/// reported where the configuration is written — and never resolved by falling back to
/// something weaker.
public enum ClientTrustError: Error, Sendable, Hashable {
    /// A trust that needs certificates was given none.
    ///
    /// Refused rather than interpreted: under ``ClientTrust/onlyRoots(_:)`` an empty list
    /// would be a client that trusts nothing, and under ``ClientTrust/additionalRoots(_:)`` it
    /// would quietly mean ``ClientTrust/systemRoots``.
    case noCertificates

    /// A source yielded no certificate: the text or bytes did not parse, or the file could not
    /// be read, or it held none.
    ///
    /// - Parameter source: The source that failed.
    case unreadable(CertificateSource)

    /// The server hostname was empty.
    case emptyServerHostname

    /// The server hostname cannot be sent as a TLS server name.
    ///
    /// - Parameter name: The name that was refused.
    case invalidServerHostname(String)

    /// The TLS library refused the configuration.
    ///
    /// - Parameter reason: The library's description.
    case contextRejected(reason: String)

    /// The text given for a pin is not a SHA-256 digest.
    ///
    /// - Parameter text: The text that was refused.
    case invalidPin(String)

    /// A pinned trust was given no pins.
    ///
    /// Refused rather than read as "no pinning", which is the opposite of what was asked for.
    case noPins

    /// A pinned trust was asked for a bare `TLSConfiguration`.
    ///
    /// The pin is enforced by a channel handler, so a configuration handed to a library that
    /// builds its own handlers would connect without it.
    case pinsNeedHandlers

    /// The handshake finished and the server presented no certificate, so there is nothing to
    /// compare with a pin.
    ///
    /// Refused, as a pin that cannot be checked is not a pin that matched. It is not the same as
    /// ``pinMismatch(certificateSHA256:publicKeySHA256:)``, which says what was presented.
    case noPeerCertificate

    /// The server's certificate chain and hostname were valid, and its leaf matched no pin.
    ///
    /// Delivered through the channel pipeline as an error, after which the connection is
    /// closed. No application data was sent.
    ///
    /// - Parameters:
    ///   - certificateSHA256: SHA-256 of the certificate the server presented, lowercase hex.
    ///   - publicKeySHA256: SHA-256 of its SubjectPublicKeyInfo, lowercase hex.
    case pinMismatch(certificateSHA256: String, publicKeySHA256: String)

    /// More writes were issued before the handshake finished than a pinned connection holds.
    ///
    /// - Parameter limit: The number of writes held.
    case tooManyWritesBeforeHandshake(limit: Int)
}

extension ClientTrustError: CustomStringConvertible {
    /// A sentence for a log line or an error alert.
    public var description: String {
        switch self {
        case .noCertificates:
            return "No certificates were supplied to trust."
        case .unreadable(.pem):
            return "The supplied PEM text holds no readable certificate."
        case .unreadable(.der):
            return "The supplied DER bytes are not a certificate."
        case .unreadable(.pemFile(let path)):
            return "No certificate could be read from the PEM file at \(path)."
        case .unreadable(.derFile(let path)):
            return "No certificate could be read from the DER file at \(path)."
        case .emptyServerHostname:
            return "No server hostname was given. The server's name is required: "
                + "it is what its certificate is checked against."
        case .invalidServerHostname(let name):
            return "\"\(name)\" cannot be used as a TLS server name."
        case .contextRejected(let reason):
            return "The TLS library refused this client configuration: \(reason)."
        case .invalidPin(let text):
            return "\"\(text)\" is not a SHA-256 digest. "
                + "Give 64 hexadecimal digits (colons allowed) or 44 characters of base64."
        case .noPins:
            return "A pinned trust was given no pins."
        case .pinsNeedHandlers:
            return "A pinned trust cannot be expressed as a TLSConfiguration: the pin is checked by a handler "
                + "after the handshake. Use ClientTLSContext.addHandlers(to:serverHostname:)."
        case .noPeerCertificate:
            return "The server presented no certificate, so there is nothing to compare with the pins. Nothing was sent to it."
        case .pinMismatch(let certificateSHA256, let publicKeySHA256):
            return "The server's certificate matches none of the pins. It presented a certificate with SHA-256 "
                + "\(certificateSHA256) and a public key with SHA-256 \(publicKeySHA256). Nothing was sent to it."
        case .tooManyWritesBeforeHandshake(let limit):
            return "More than \(limit) writes were queued before the TLS handshake finished."
        }
    }
}
