#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// Parses IP address literals, so that "is this an address, and which one" has one answer.
enum IPAddressLiteral {
    /// Whether `literal` can be handed to a C function as the whole of itself.
    ///
    /// Swift passes a `String` to `inet_pton` as a C string, which ends at the first NUL, so
    /// `127.0.0.1\0.example.com` would be read as `127.0.0.1`. A literal with a NUL in it is not
    /// an address; it is text that two readers would read differently.
    private static func isWhole(_ literal: String) -> Bool {
        !literal.utf8.contains(0)
    }

    /// The four bytes of an IPv4 literal in network order, or `nil` if `literal` is not one.
    static func ipv4Bytes(_ literal: String) -> [UInt8]? {
        var address = in_addr()
        guard isWhole(literal), inet_pton(AF_INET, literal, &address) == 1 else { return nil }
        let hostOrder = UInt32(bigEndian: address.s_addr)
        return [
            UInt8(truncatingIfNeeded: hostOrder >> 24),
            UInt8(truncatingIfNeeded: hostOrder >> 16),
            UInt8(truncatingIfNeeded: hostOrder >> 8),
            UInt8(truncatingIfNeeded: hostOrder),
        ]
    }

    /// The sixteen bytes of an IPv6 literal in network order, or `nil` if `literal` is not one.
    static func ipv6Bytes(_ literal: String) -> [UInt8]? {
        var address = in6_addr()
        guard isWhole(literal), inet_pton(AF_INET6, literal, &address) == 1 else { return nil }
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

    /// Whether `text` is an IPv4 or IPv6 address rather than a name.
    static func isAddress(_ text: String) -> Bool {
        ipv4Bytes(text) != nil || ipv6Bytes(text) != nil
    }
}
