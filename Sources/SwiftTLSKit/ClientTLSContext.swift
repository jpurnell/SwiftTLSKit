import NIOCore
import NIOSSL

/// A TLS context for a client, built once from a ``ClientTrust`` and used for every connection.
///
/// Building it reads and parses every root, so nothing about what is trusted is left to be
/// discovered when a connection is made.
///
/// ## Adding TLS to a connection
///
/// Inside a `ClientBootstrap`'s `channelInitializer`, one line adds TLS, naming the server:
///
/// ```swift
/// import NIOCore
/// import SwiftTLSKit
///
/// func secure(_ channel: any Channel, with tls: ClientTLSContext, host: String) -> EventLoopFuture<Void> {
///     channel.eventLoop.makeCompletedFuture {
///         try tls.addHandlers(to: channel.pipeline.syncOperations, serverHostname: host)
///     }
/// }
/// ```
///
/// ## The server's name is not optional
///
/// `serverHostname` is a `String`, not a `String?`. A name is sent as SNI and the certificate
/// is checked against it. An IP address cannot be sent as SNI (RFC 6066), so for an address
/// none is sent and the certificate is checked against the address the channel is connected
/// to, which must appear among the certificate's IP subject alternative names.
public struct ClientTLSContext: Sendable {
    /// The trust this context enforces.
    public let trust: ClientTrust

    /// SHA-256 of each supplied root's DER encoding, as lowercase hex, in the order supplied.
    ///
    /// Empty for ``ClientTrust/systemRoots``. The value `openssl x509 -fingerprint -sha256`
    /// prints, without the colons — so what a client trusts can be shown and compared.
    public let rootFingerprints: [String]

    private let sslContext: NIOSSLContext
    private let pins: [CertificatePin]

    /// Reads the trust's roots and builds the context.
    ///
    /// - Parameters:
    ///   - trust: What to trust.
    ///   - minimumVersion: The oldest TLS version accepted. TLS 1.2 unless changed.
    ///   - applicationProtocols: The ALPN protocols offered, most preferred first.
    /// - Throws: ``ClientTrustError`` if a root cannot be read or the TLS library refuses the
    ///   configuration.
    public init(
        trust: ClientTrust,
        minimumVersion: MinimumTLSVersion = .tls12,
        applicationProtocols: [String] = []
    ) throws(ClientTrustError) {
        let resolved = try trust.resolve()
        let configuration = resolved.configuration(
            minimumVersion: minimumVersion, applicationProtocols: applicationProtocols)
        do {
            self.sslContext = try NIOSSLContext(configuration: configuration)
        } catch {
            throw .contextRejected(reason: String(describing: error))
        }
        self.trust = trust
        self.rootFingerprints = resolved.rootFingerprints
        self.pins = resolved.pins
    }

    /// The handlers that secure one connection to `serverHostname`.
    ///
    /// Add all of them, in order, ahead of the application's handlers —
    /// ``addHandlers(to:serverHostname:)`` does exactly that.
    ///
    /// For ``ClientTrust/pinned(_:additionalRoots:)`` there are two: the TLS handler, and the
    /// handler that checks the pin and holds application data until it has. Leaving the second
    /// out leaves the pin unenforced.
    ///
    /// - Parameter serverHostname: The name or IP address of the server being connected to.
    /// - Returns: The handlers, outermost first.
    /// - Throws: ``ClientTrustError/emptyServerHostname`` or
    ///   ``ClientTrustError/invalidServerHostname(_:)``.
    public func makeHandlers(serverHostname: String) throws(ClientTrustError) -> [any ChannelHandler] {
        guard !serverHostname.isEmpty else { throw .emptyServerHostname }
        // An address is not sent as SNI. NIOSSL then verifies the certificate against the
        // address the channel is connected to.
        let serverName: String? = IPAddressLiteral.isAddress(serverHostname) ? nil : serverHostname
        let tls: NIOSSLClientHandler
        do {
            tls = try NIOSSLClientHandler(context: sslContext, serverHostname: serverName)
        } catch {
            throw .invalidServerHostname(serverHostname)
        }
        guard !pins.isEmpty else { return [tls] }
        return [tls, PinVerificationHandler(pins: pins)]
    }

    /// Puts the TLS handlers at the front of a connection's pipeline.
    ///
    /// Call it on the channel's event loop — a channel initializer is.
    ///
    /// - Parameters:
    ///   - pipeline: The connection's pipeline.
    ///   - serverHostname: The name or IP address of the server being connected to.
    /// - Throws: ``ClientTrustError`` for a hostname that cannot be used, or whatever the
    ///   pipeline throws if a handler cannot be added.
    public func addHandlers(to pipeline: ChannelPipeline.SynchronousOperations, serverHostname: String) throws {
        try pipeline.addHandlers(try makeHandlers(serverHostname: serverHostname), position: .first)
    }
}
