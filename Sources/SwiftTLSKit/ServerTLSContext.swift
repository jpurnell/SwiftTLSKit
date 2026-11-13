import Foundation
import NIOCore
import NIOSSL

/// The oldest TLS version a context will speak.
///
/// There are two choices and neither is below TLS 1.2. TLS 1.0 and 1.1 are not offered: both
/// are deprecated by RFC 8996, and a setting that exists is a setting someone will reach for.
public enum MinimumTLSVersion: Sendable, Hashable {
    /// TLS 1.2 and TLS 1.3. The default.
    case tls12
    /// TLS 1.3 only.
    case tls13

    /// The NIOSSL value this stands for.
    var nioValue: TLSVersion {
        switch self {
        case .tls12: return .tlsv12
        case .tls13: return .tlsv13
        }
    }
}

/// How a server's TLS context is configured, apart from its identity.
public struct ServerTLSOptions: Sendable, Hashable {
    /// The oldest TLS version accepted. ``MinimumTLSVersion/tls12`` unless changed.
    public var minimumVersion: MinimumTLSVersion

    /// The ALPN protocols offered, most preferred first. Empty — the default — offers none.
    public var applicationProtocols: [String]

    /// Makes a set of options.
    ///
    /// - Parameters:
    ///   - minimumVersion: The oldest TLS version accepted.
    ///   - applicationProtocols: The ALPN protocols offered, most preferred first.
    public init(minimumVersion: MinimumTLSVersion = .tls12, applicationProtocols: [String] = []) {
        self.minimumVersion = minimumVersion
        self.applicationProtocols = applicationProtocols
    }
}

/// A TLS context for a server, built from an identity that has already been judged fit.
///
/// The one place a server `TLSConfiguration` is written. It can only be made from a
/// ``LoadedServerIdentity``, so there is no path from "two strings" to "a listening TLS
/// server" that skips the checks ``ServerIdentity/load(now:)`` makes.
///
/// Clients are not asked for a certificate. Mutual TLS is not offered in this version.
///
/// ## Adding TLS to a connection
///
/// Inside a `ServerBootstrap`'s `childChannelInitializer`, one line puts TLS at the front of
/// the new connection's pipeline:
///
/// ```swift
/// import NIOCore
/// import SwiftTLSKit
///
/// func secure(_ channel: any Channel, with tls: ServerTLSContext) -> EventLoopFuture<Void> {
///     channel.eventLoop.makeCompletedFuture {
///         try tls.addHandler(to: channel.pipeline.syncOperations)
///     }
/// }
/// ```
public struct ServerTLSContext: Sendable {
    /// What the leaf certificate being served says, for a start-up log line.
    public let leaf: CertificateSummary

    /// The options the context was built with.
    public let options: ServerTLSOptions

    /// The NIOSSL context, for a consumer that builds its own handler.
    public let sslContext: NIOSSLContext

    /// SHA-256 of each certificate served, leaf first.
    let chainFingerprints: [String]

    /// What the key file this context was built from held. Compared, never read.
    let privateKeyFileDigest: PrivateKeyFileDigest

    /// Builds a context that serves `identity`.
    ///
    /// - Parameters:
    ///   - identity: An identity that ``ServerIdentity/load(now:)`` accepted.
    ///   - options: The minimum TLS version and ALPN protocols. Defaults to TLS 1.2 and none.
    /// - Throws: ``ServerIdentityError/contextRejected(reason:)`` if the TLS library refuses
    ///   the configuration.
    public init(
        identity: LoadedServerIdentity,
        options: ServerTLSOptions = ServerTLSOptions()
    ) throws(ServerIdentityError) {
        // `certificateVerification` is left at the server default, `.none`. That setting is about
        // whether the server asks a *client* for a certificate, which this package does not
        // support (no mutual TLS); it is not a verification this package turns off, and nothing
        // here writes it.
        var configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: identity.certificateChain.map { .certificate($0) },
            privateKey: .privateKey(identity.privateKey))
        configuration.minimumTLSVersion = options.minimumVersion.nioValue
        configuration.applicationProtocols = options.applicationProtocols
        do {
            self.sslContext = try NIOSSLContext(configuration: configuration)
        } catch {
            throw .contextRejected(reason: String(describing: error))
        }
        self.leaf = identity.leaf
        self.options = options
        self.chainFingerprints = identity.chainFingerprints
        self.privateKeyFileDigest = identity.privateKeyFileDigest
    }

    /// Reads, validates and builds in one step.
    ///
    /// - Parameters:
    ///   - identity: The files to serve.
    ///   - options: The minimum TLS version and ALPN protocols.
    ///   - now: The current time, against which the leaf's validity is judged.
    /// - Returns: A context serving the identity as it is on disk at this moment.
    /// - Throws: ``ServerIdentityError`` for anything ``ServerIdentity/load(now:)`` refuses.
    public static func load(
        _ identity: ServerIdentity,
        options: ServerTLSOptions = ServerTLSOptions(),
        now: Date
    ) throws(ServerIdentityError) -> ServerTLSContext {
        try ServerTLSContext(identity: try identity.load(now: now), options: options)
    }

    /// A TLS handler for one connection.
    ///
    /// - Returns: A new `NIOSSLServerHandler`. A handler serves one channel; make one per
    ///   connection.
    public func makeHandler() -> NIOSSLServerHandler {
        NIOSSLServerHandler(context: sslContext)
    }

    /// Puts a TLS handler at the front of a connection's pipeline.
    ///
    /// At the front, whatever is already there, because TLS has to be the first thing bytes
    /// from the network meet. Call it on the channel's event loop — a channel initializer is.
    ///
    /// - Parameter pipeline: The connection's pipeline.
    /// - Throws: Whatever the pipeline throws if the handler cannot be added.
    public func addHandler(to pipeline: ChannelPipeline.SynchronousOperations) throws {
        try pipeline.addHandler(makeHandler(), position: .first)
    }
}
