import Testing
import SwiftTLSKit

/// One definition of loopback, for a host a server binds and for a host a client dials.
///
/// Every expectation here is a statement about addressing, not about the implementation:
/// 127.0.0.0/8 is loopback by RFC 1122 §3.2.1.3, `::1` by RFC 4291 §2.5.3, and `localhost` by
/// RFC 6761 §6.3. The refusals are the spellings where two parsers disagree, or where the text
/// is not a host.
@Suite("What counts as loopback")
struct LoopbackTests {

    @Test(
        "The name localhost, 127.0.0.0/8, ::1, and IPv4-mapped loopback are loopback",
        arguments: [
            "localhost", "LOCALHOST", "LocalHost",
            "127.0.0.1", "127.0.0.0", "127.8.9.10", "127.255.255.255",
            "::1", "[::1]", "0:0:0:0:0:0:0:1", "0000:0000:0000:0000:0000:0000:0000:0001",
            "::ffff:127.0.0.1", "::FFFF:127.0.0.1", "[::ffff:127.0.0.1]", "::ffff:7f00:1", "::ffff:127.255.255.255",
        ])
    func loopback(host: String) {
        #expect(isLoopback(host: host) == true)
    }

    @Test(
        "Every other address is not, the wildcard included",
        arguments: [
            "0.0.0.0", "::", "[::]", "126.255.255.255", "128.0.0.0", "10.0.1.114", "192.168.1.1", "169.254.0.1",
            "::2", "fe80::1", "::ffff:10.0.0.1", "::ffff:0.0.0.0", "::ffff:128.0.0.1", "::127.0.0.1",
        ])
    func otherAddresses(host: String) {
        #expect(isLoopback(host: host) == false)
    }

    @Test(
        "Names are not resolved: only localhost itself is loopback",
        arguments: [
            "roseclub.org", "localhost.example.com", "localhost.", "localhost4", "ip6-localhost",
            "127.0.0.1.example.com", "",
        ])
    func otherNames(host: String) {
        #expect(isLoopback(host: host) == false)
    }

    @Test(
        "A spelling another parser reads differently is not loopback",
        arguments: [
            // Octal to getaddrinfo and inet_aton: 0127 is 87.
            "0127.0.0.1", "127.0.0.01", "::ffff:0127.0.0.1",
            // Shorthand and other radices that inet_aton accepts and inet_pton does not.
            "127.1", "127.0.0", "0x7f.0.0.1", "2130706433", "1270.0.0.1",
            // A zone identifier names an interface, which is more than an address.
            "::1%lo0",
        ])
    func ambiguousSpellings(host: String) {
        #expect(isLoopback(host: host) == false)
    }

    @Test(
        "Text that is not a host is not loopback",
        arguments: [
            // Brackets belong around an IPv6 literal and nothing else.
            "[127.0.0.1]", "[localhost]", "[::1", "::1]", "[]", "[[::1]]",
            // A host, not a host and port.
            "localhost:8080", "127.0.0.1:80", "[::1]:80",
            " 127.0.0.1", "127.0.0.1 ", "localhost\n",
        ])
    func notAHost(host: String) {
        #expect(isLoopback(host: host) == false)
    }

    @Test("A bind host and a dial host get the same answer", arguments: ["127.0.0.1", "::1", "localhost", "0.0.0.0", "roseclub.org"])
    func agreesWithBindExposure(host: String) {
        #expect(
            (BindExposure.classify(host: host, tlsConfigured: false) == .loopbackPlaintext) == isLoopback(host: host))
    }
}
