import NIOSSL

/// Where a certificate a client is to trust comes from.
public enum CertificateSource: Sendable, Hashable {
    /// PEM text holding one or more certificates.
    case pem(String)
    /// One DER-encoded certificate.
    case der([UInt8])
    /// The path of a PEM file holding one or more certificates.
    case pemFile(String)
    /// The path of a file holding one DER-encoded certificate.
    case derFile(String)
}

/// What a client is prepared to believe about the server it connects to.
///
/// Every case verifies the server's certificate chain and checks the certificate against the
/// hostname being connected to. The cases differ in *who may have signed* the certificate,
/// never in *whether* it is checked — there is no case that turns verification off, and none
/// can be added without changing this type.
///
/// To trust a private authority, or a self-signed development server, supply its certificate:
///
/// ```swift
/// import SwiftTLSKit
///
/// func developmentTrust(authorityPEMPath: String) -> ClientTrust {
///     .onlyRoots([.pemFile(authorityPEMPath)])
/// }
/// ```
public enum ClientTrust: Sendable, Hashable {
    /// The platform's root store, and nothing else. Right for any publicly certified server.
    case systemRoots

    /// The platform's root store and the supplied certificates.
    ///
    /// - Parameter sources: The certificates to add. An empty list is an error.
    case additionalRoots([CertificateSource])

    /// The supplied certificates and nothing else.
    ///
    /// The server's chain must end at one of them, so supplying a self-signed server's own
    /// certificate ties the connection to that certificate.
    ///
    /// - Parameter sources: The only certificates to trust. An empty list is an error.
    case onlyRoots([CertificateSource])

    /// The platform's root store, any supplied certificates, **and** a pin the server's own
    /// certificate must match.
    ///
    /// A pin narrows trust; it never widens it. The chain is validated and the hostname is
    /// checked exactly as for ``additionalRoots(_:)``, and then the leaf must also match one
    /// of the pins. Several pins are alternatives, which is how a key is rotated: pin the
    /// current one and its successor.
    ///
    /// The pin is checked by a handler directly after the handshake, before any application
    /// byte is sent or delivered, so it is enforced only through
    /// ``ClientTLSContext/addHandlers(to:serverHostname:)``. ``makeTLSConfiguration(minimumVersion:applicationProtocols:)``
    /// throws for this case rather than return a configuration that would silently drop it.
    ///
    /// - Parameters:
    ///   - pins: The digests, any one of which the leaf must match. An empty list is an error.
    ///   - additionalRoots: Certificates to trust besides the platform's, for a server whose
    ///     authority is private. May be empty.
    case pinned([CertificatePin], additionalRoots: [CertificateSource] = [])

    /// The NIOSSL client configuration this trust amounts to.
    ///
    /// For libraries that take a `TLSConfiguration` rather than a handler. Chain and hostname
    /// verification are left exactly as `TLSConfiguration.makeClientConfiguration()` sets them:
    /// full. The server name itself is supplied by whoever makes the connection.
    ///
    /// - Parameters:
    ///   - minimumVersion: The oldest TLS version accepted.
    ///   - applicationProtocols: The ALPN protocols offered, most preferred first.
    /// - Returns: The configuration.
    /// - Throws: ``ClientTrustError`` if a root cannot be read, and
    ///   ``ClientTrustError/pinsNeedHandlers`` for ``pinned(_:additionalRoots:)``, which a
    ///   configuration alone cannot enforce.
    public func makeTLSConfiguration(
        minimumVersion: MinimumTLSVersion = .tls12,
        applicationProtocols: [String] = []
    ) throws(ClientTrustError) -> TLSConfiguration {
        if case .pinned = self { throw .pinsNeedHandlers }
        return try resolve().configuration(minimumVersion: minimumVersion, applicationProtocols: applicationProtocols)
    }

    /// Reads every source. All or nothing: a subset of the roots someone asked for is a
    /// different trust decision from the one they made.
    func resolve() throws(ClientTrustError) -> ResolvedClientTrust {
        switch self {
        case .systemRoots:
            return ResolvedClientTrust(usesSystemRoots: true, roots: [], rootFingerprints: [])
        case .additionalRoots(let sources):
            return try Self.read(sources, usesSystemRoots: true)
        case .onlyRoots(let sources):
            return try Self.read(sources, usesSystemRoots: false)
        case .pinned(let pins, let sources):
            guard !pins.isEmpty else { throw .noPins }
            guard !sources.isEmpty else {
                return ResolvedClientTrust(usesSystemRoots: true, roots: [], rootFingerprints: [], pins: pins)
            }
            let roots = try Self.read(sources, usesSystemRoots: true)
            return ResolvedClientTrust(
                usesSystemRoots: true, roots: roots.roots, rootFingerprints: roots.rootFingerprints, pins: pins)
        }
    }

    private static func read(
        _ sources: [CertificateSource], usesSystemRoots: Bool
    ) throws(ClientTrustError) -> ResolvedClientTrust {
        guard !sources.isEmpty else { throw .noCertificates }
        var roots: [NIOSSLCertificate] = []
        var fingerprints: [String] = []
        for source in sources {
            let loaded = try load(source)
            guard !loaded.isEmpty else { throw .unreadable(source) }
            for certificate in loaded {
                fingerprints.append(try fingerprint(of: certificate, from: source))
                roots.append(certificate)
            }
        }
        return ResolvedClientTrust(usesSystemRoots: usesSystemRoots, roots: roots, rootFingerprints: fingerprints)
    }

    private static func load(_ source: CertificateSource) throws(ClientTrustError) -> [NIOSSLCertificate] {
        do {
            switch source {
            case .pem(let text):
                return try NIOSSLCertificate.fromPEMBytes(Array(text.utf8))
            case .der(let bytes):
                return [try NIOSSLCertificate(bytes: bytes, format: .der)]
            case .pemFile(let path):
                return try NIOSSLCertificate.fromPEMFile(path)
            case .derFile(let path):
                return [try NIOSSLCertificate.fromDERFile(path)]
            }
        } catch {
            // The underlying error is BoringSSL's and says little a caller can act on. Which
            // source it was is the useful part, and the error carries it.
            throw .unreadable(source)
        }
    }

    private static func fingerprint(
        of certificate: NIOSSLCertificate, from source: CertificateSource
    ) throws(ClientTrustError) -> String {
        do {
            return SHA256Hex.digest(of: try certificate.toDERBytes())
        } catch {
            throw .unreadable(source)
        }
    }
}

/// A ``ClientTrust`` whose sources have been read and parsed.
struct ResolvedClientTrust: Sendable {
    let usesSystemRoots: Bool
    let roots: [NIOSSLCertificate]
    let rootFingerprints: [String]
    var pins: [CertificatePin] = []

    /// The one place a client `TLSConfiguration` is built. The only fields written are the
    /// ones that say which roots to verify against, how old a protocol to accept, and which
    /// application protocols to offer; `certificateVerification` is never touched.
    func configuration(minimumVersion: MinimumTLSVersion, applicationProtocols: [String]) -> TLSConfiguration {
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.minimumTLSVersion = minimumVersion.nioValue
        configuration.applicationProtocols = applicationProtocols
        guard !roots.isEmpty else { return configuration }
        if usesSystemRoots {
            configuration.additionalTrustRoots = [.certificates(roots)]
        } else {
            configuration.trustRoots = .certificates(roots)
        }
        return configuration
    }
}
