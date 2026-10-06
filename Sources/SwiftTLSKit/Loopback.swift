/// Whether `host` names this machine and nothing else.
///
/// The one definition of loopback in the package, for both ends of a connection: a server asks
/// it of the host it binds — ``BindExposure`` is built on it — and a client asks it of the host
/// it dials, before deciding whether plaintext to that host is acceptable.
///
/// ```swift
/// import SwiftTLSKit
///
/// print(isLoopback(host: "[::1]"), isLoopback(host: "0.0.0.0"), isLoopback(host: "example.com"))
/// // Prints "true false false"
/// ```
///
/// Loopback is exactly:
///
/// - the name `localhost`, in any case;
/// - an IPv4 literal in `127.0.0.0/8`;
/// - the IPv6 literal `::1`, however it is written, with or without square brackets;
/// - an IPv4-mapped IPv6 literal whose IPv4 part is in `127.0.0.0/8`, such as
///   `::ffff:127.0.0.1`.
///
/// Everything else is not, and every doubt is resolved towards "not", because that is the
/// answer that makes a caller treat the host as reachable by other machines:
///
/// - **Names are not resolved.** A name other than `localhost` is not loopback even if it
///   resolves to this machine today; that is a fact about a resolver's configuration, and it
///   can change without this code being told. `localhost.` with a trailing dot is such a name.
/// - **The wildcard is not loopback.** `0.0.0.0` and `::` bind every interface.
/// - **A spelling two parsers read differently is not loopback.** `0127.0.0.1` is 127.0.0.1 to
///   `inet_pton` on some platforms and 87.0.0.1 to `getaddrinfo`, which reads a leading zero as
///   octal. An octet with a leading zero, a shortened address such as `127.1`, and a zone
///   identifier such as `::1%lo0` are all refused.
/// - **The text must be a host.** No port, no surrounding space, and square brackets only
///   around an IPv6 literal.
///
/// - Parameter host: A host as configured or as parsed from a URL: a name, an IPv4 literal, or
///   an IPv6 literal with or without square brackets.
/// - Returns: `true` only for the forms listed above.
public func isLoopback(host: String) -> Bool {
    if host.hasPrefix(LoopbackLiteral.openBracket) {
        guard host.hasSuffix(LoopbackLiteral.closeBracket) else { return false }
        return isLoopbackIPv6(String(host.dropFirst().dropLast()))
    }
    if host.lowercased() == LoopbackLiteral.name { return true }
    if let ipv4 = IPAddressLiteral.ipv4Bytes(host) {
        return LoopbackLiteral.hasCanonicalOctets(host[...]) && ipv4.first == LoopbackLiteral.firstOctet
    }
    return isLoopbackIPv6(host)
}

/// Whether `literal`, without brackets, is `::1` or IPv4-mapped loopback.
private func isLoopbackIPv6(_ literal: String) -> Bool {
    guard !literal.contains(LoopbackLiteral.zoneSeparator) else { return false }
    // The part after the last colon is a dotted quad in the mixed notation of RFC 4291 §2.2.
    if let lastGroup = literal.split(separator: LoopbackLiteral.groupSeparator, omittingEmptySubsequences: false).last,
        lastGroup.contains(LoopbackLiteral.octetSeparator)
    {
        guard LoopbackLiteral.hasCanonicalOctets(lastGroup) else { return false }
    }
    guard let ipv6 = IPAddressLiteral.ipv6Bytes(literal) else { return false }
    if ipv6 == LoopbackLiteral.ipv6Bytes { return true }
    guard ipv6.starts(with: LoopbackLiteral.ipv4MappedPrefix) else { return false }
    return ipv6.dropFirst(LoopbackLiteral.ipv4MappedPrefix.count).first == LoopbackLiteral.firstOctet
}

/// The constants "loopback" is made of.
private enum LoopbackLiteral {
    static let name = "localhost"
    static let openBracket = "["
    static let closeBracket = "]"
    static let zoneSeparator: Character = "%"
    static let groupSeparator: Character = ":"
    static let octetSeparator: Character = "."
    static let zero = "0"
    /// 127.0.0.0/8, RFC 1122 §3.2.1.3.
    static let firstOctet: UInt8 = 127
    /// `::1`, RFC 4291 §2.5.3.
    static let ipv6Bytes: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    /// `::ffff:0:0/96`, RFC 4291 §2.5.5.2.
    static let ipv4MappedPrefix: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]

    /// Whether every octet of a dotted quad is written the one way all parsers agree on:
    /// decimal digits with no leading zero.
    static func hasCanonicalOctets(_ dottedQuad: Substring) -> Bool {
        dottedQuad.split(separator: octetSeparator, omittingEmptySubsequences: false).allSatisfy { octet in
            octet == zero || !octet.hasPrefix(zero)
        }
    }
}
