@testable import SwiftTLSKit
import Testing

/// The parser both `isLoopback` and the certificate-name code use. A literal is the whole string,
/// not the part of it a C function would see.
@Suite("IP address literals")
struct IPAddressLiteralTests {
    @Test("An address followed by a NUL and more text is not an address")
    func nulTerminatesNothing() {
        #expect(IPAddressLiteral.ipv4Bytes("1.2.3.4\u{0}x") == nil)
        #expect(IPAddressLiteral.ipv4Bytes("1.2.3.4\u{0}") == nil)
        #expect(IPAddressLiteral.ipv6Bytes("::1\u{0}x") == nil)
        #expect(IPAddressLiteral.ipv6Bytes("::1\u{0}") == nil)
        #expect(IPAddressLiteral.isAddress("1.2.3.4\u{0}x") == false)
    }

    @Test("A plain address still parses")
    func plain() {
        #expect(IPAddressLiteral.ipv4Bytes("1.2.3.4") == [1, 2, 3, 4])
        #expect(IPAddressLiteral.ipv6Bytes("::1") == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        #expect(IPAddressLiteral.isAddress("1.2.3.4"))
    }
}
