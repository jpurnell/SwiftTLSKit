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

    // The expected bytes below are written out by hand from the address forms in RFC 4291 section 2.2
    // and RFC 5952, one group of two bytes at a time. They are not read back from the parser, so a
    // wrong byte order or a wrong place for the run of zeros fails here on every libc.

    @Test("The unspecified address is sixteen zero bytes")
    func unspecified() {
        #expect(IPAddressLiteral.ipv6Bytes("::") == [UInt8](repeating: 0, count: 16))
    }

    @Test("A compressed run of zeros stands for exactly the groups it replaces")
    func compressed() {
        // 2001:db8::1 is 2001, 0db8, five zero groups, 0001.
        #expect(
            IPAddressLiteral.ipv6Bytes("2001:db8::1")
                == [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    }

    @Test("Eight groups are read in order, high byte first")
    func fullForm() {
        #expect(
            IPAddressLiteral.ipv6Bytes("1:2:3:4:5:6:7:8")
                == [0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8])
    }

    @Test("An IPv4-mapped address ends in the four bytes of the dotted quad")
    func ipv4Mapped() {
        // ::ffff:192.0.2.1 is ten zero bytes, ff ff, then c0 00 02 01 (RFC 4291 section 2.5.5.2).
        #expect(
            IPAddressLiteral.ipv6Bytes("::ffff:192.0.2.1")
                == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xc0, 0x00, 0x02, 0x01])
    }

    @Test("Text that is not an IPv6 address is not one")
    func malformed() {
        let notAddresses = [
            "",
            ":",
            ":::",
            "1:2:3:4:5:6:7:8:9",  // nine groups
            "1::2::3",  // two runs of zeros
            "12345::",  // a group of five digits
            "::g",
            "fe80::1%eth0",  // a zone is not part of an address; Darwin's inet_pton would accept it
            "fe80::1%",
            "1.2.3.4",  // an IPv4 literal is not an IPv6 one
        ]
        for text in notAddresses {
            #expect(IPAddressLiteral.ipv6Bytes(text) == nil, "\(text) is not an IPv6 address")
        }
    }

    @Test("A zone suffix makes a literal not an address, on every platform")
    func zoneIsNotAnAddress() {
        #expect(IPAddressLiteral.isAddress("fe80::1") == true)
        #expect(IPAddressLiteral.isAddress("fe80::1%eth0") == false)
        #expect(IPAddressLiteral.isAddress("1.2.3.4%eth0") == false)
    }
}
