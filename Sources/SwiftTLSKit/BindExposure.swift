#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

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
/// Only literal loopback addresses and the name `localhost` count as loopback. Any other name
/// is treated as exposed, because this function does not resolve names and a name that resolves
/// to loopback today is a configuration that can change without this code being told.
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
    /// - Returns: ``tls`` when `tlsConfigured`; otherwise ``loopbackPlaintext`` for `localhost`,
    ///   `127.0.0.0/8`, `::1` and IPv4-mapped loopback, and ``exposedPlaintext(host:)`` for
    ///   everything else — including the empty string and any other name.
    public static func classify(host: String, tlsConfigured: Bool) -> BindExposure {
        guard !tlsConfigured else { return .tls }
        return isLoopback(host) ? .loopbackPlaintext : .exposedPlaintext(host: host)
    }

    /// Whether this is plaintext that other machines can reach.
    public var isExposedPlaintext: Bool {
        guard case .exposedPlaintext = self else { return false }
        return true
    }

    private static let loopbackName = "localhost"
    private static let loopbackFirstOctet: UInt8 = 127
    private static let ipv6LoopbackBytes: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    private static let ipv4MappedPrefix: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]

    private static func isLoopback(_ host: String) -> Bool {
        var literal = host
        if literal.hasPrefix("["), literal.hasSuffix("]") {
            literal = String(literal.dropFirst().dropLast())
        }
        if literal.lowercased() == loopbackName { return true }
        if let ipv4 = ipv4Bytes(literal) {
            return ipv4.first == loopbackFirstOctet
        }
        guard let ipv6 = ipv6Bytes(literal) else { return false }
        if ipv6 == ipv6LoopbackBytes { return true }
        guard ipv6.starts(with: ipv4MappedPrefix) else { return false }
        return ipv6.dropFirst(ipv4MappedPrefix.count).first == loopbackFirstOctet
    }

    /// The four bytes of an IPv4 literal in network order, or `nil` if `literal` is not one.
    private static func ipv4Bytes(_ literal: String) -> [UInt8]? {
        var address = in_addr()
        guard inet_pton(AF_INET, literal, &address) == 1 else { return nil }
        let hostOrder = UInt32(bigEndian: address.s_addr)
        return [
            UInt8(truncatingIfNeeded: hostOrder >> 24),
            UInt8(truncatingIfNeeded: hostOrder >> 16),
            UInt8(truncatingIfNeeded: hostOrder >> 8),
            UInt8(truncatingIfNeeded: hostOrder),
        ]
    }

    /// The sixteen bytes of an IPv6 literal in network order, or `nil` if `literal` is not one.
    private static func ipv6Bytes(_ literal: String) -> [UInt8]? {
        var address = in6_addr()
        guard inet_pton(AF_INET6, literal, &address) == 1 else { return nil }
        #if canImport(Darwin)
        let octets = address.__u6_addr.__u6_addr8
        #else
        let octets = address.__in6_u.__u6_addr8
        #endif
        return [
            octets.0, octets.1, octets.2, octets.3, octets.4, octets.5, octets.6, octets.7,
            octets.8, octets.9, octets.10, octets.11, octets.12, octets.13, octets.14, octets.15,
        ]
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
