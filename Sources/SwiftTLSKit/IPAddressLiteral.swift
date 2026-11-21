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

    /// Whether `literal` carries a zone, as in `fe80::1%eth0`.
    ///
    /// A zone names a local interface. It is not part of the address, and no certificate can name
    /// it. Darwin's `inet_pton` accepts one and Glibc's does not, so ``ipv6Bytes(_:)``
    /// refuses it before the C library is asked, and a zoned literal means the same thing on every
    /// platform. ``ClientTLSContext`` refuses it as a server name, because neither NIOSSL nor an
    /// address check can do anything correct with it.
    static func hasZone(_ literal: String) -> Bool {
        literal.utf8.contains(UInt8(ascii: "%"))
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
        // `inet_pton` writes sixteen bytes in network order through a `void *`, so a sixteen-byte
        // array is the destination on every libc. Reading them out of `in6_addr` instead would mean
        // naming the union member, and Darwin, Glibc and Musl each name it differently.
        var bytes = [UInt8](repeating: 0, count: 16)
        guard isWhole(literal), !hasZone(literal), inet_pton(AF_INET6, literal, &bytes) == 1 else { return nil }
        return bytes
    }

    /// Whether `text` is an IPv4 or IPv6 address rather than a name.
    static func isAddress(_ text: String) -> Bool {
        ipv4Bytes(text) != nil || ipv6Bytes(text) != nil
    }
}
