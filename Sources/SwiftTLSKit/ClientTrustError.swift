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
        }
    }
}
