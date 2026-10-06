/// What binding a listener to a host exposes, given whether TLS is configured.
///
/// A pure classification, so that the decision a server makes about plaintext is written down
/// once and is testable without opening a socket. It decides nothing: whether
/// ``exposedPlaintext(host:)`` is a warning or a refusal to start belongs to the server that
/// asked.
///
/// ```swift
/// import SwiftTLSKit
///
/// let exposure = BindExposure.classify(host: "0.0.0.0", tlsConfigured: false)
/// print(exposure.isExposedPlaintext)
/// // Prints "true"
/// ```
///
/// What counts as loopback is decided by ``isLoopback(host:)``, and nowhere else: literal
/// loopback addresses and the name `localhost`. Any other name is treated as exposed, because
/// names are not resolved and a name that resolves to loopback today is a configuration that
/// can change without this code being told.
///
/// This type is about a host a listener *binds*. To ask whether a host a client *dials* is this
/// machine, call ``isLoopback(host:)`` directly.
public enum BindExposure: Sendable, Hashable {
    /// TLS is configured, whatever the host.
    case tls
    /// Plaintext, bound to an address only this machine can reach.
    case loopbackPlaintext
    /// Plaintext, bound to an address other machines can reach.
    ///
    /// - Parameter host: The bind host as it was given, for the message.
    case exposedPlaintext(host: String)

    /// Classifies a bind host.
    ///
    /// - Parameters:
    ///   - host: The host a listener is to bind, as configured: an IPv4 or IPv6 literal
    ///     (optionally in square brackets), or a name.
    ///   - tlsConfigured: Whether the listener will wrap connections in TLS.
    /// - Returns: ``tls`` when `tlsConfigured`; otherwise ``loopbackPlaintext`` when
    ///   ``isLoopback(host:)`` says so, and ``exposedPlaintext(host:)`` for everything else —
    ///   including the empty string and any other name.
    public static func classify(host: String, tlsConfigured: Bool) -> BindExposure {
        guard !tlsConfigured else { return .tls }
        return isLoopback(host: host) ? .loopbackPlaintext : .exposedPlaintext(host: host)
    }

    /// Whether this is plaintext that other machines can reach.
    public var isExposedPlaintext: Bool {
        guard case .exposedPlaintext = self else { return false }
        return true
    }
}

extension BindExposure: CustomStringConvertible {
    /// A sentence for a start-up log line. The host is the only interpolated value.
    public var description: String {
        switch self {
        case .tls:
            return "TLS is configured."
        case .loopbackPlaintext:
            return "Plaintext on loopback only."
        case .exposedPlaintext(let host):
            return "Plaintext on \(host): this listener is reachable from other machines without TLS. "
                + "Supply a certificate chain and private key, or bind to 127.0.0.1."
        }
    }
}
