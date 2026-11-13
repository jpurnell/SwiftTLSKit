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
            // A leading zero is octal to inet_aton and decimal to inet_pton, so the two give
            // different addresses for the same text. See `leadingZeroOctets` below.
            "0127.0.0.1", "127.0.0.01", "::ffff:0127.0.0.1",
            // Shorthand and other radices that inet_aton accepts and inet_pton does not.
            "127.1", "127.0.0", "0x7f.0.0.1", "2130706433", "1270.0.0.1",
            // A zone identifier names an interface, which is more than an address.
            "::1%lo0",
        ])
    func ambiguousSpellings(host: String) {
        #expect(isLoopback(host: host) == false)
    }

    /// What the package relies on, stated about the text and nothing else: an octet written
    /// with a leading zero is refused wherever it stands, whatever number any parser would
    /// make of it. No resolver is consulted here and none is described — which parser reads
    /// such an octet as octal differs by function and by platform, and that disagreement is
    /// the reason for the rule, not something this suite can hold still.
    ///
    /// `0177` is in the table because it is the spelling that is 127 in octal; `0127` because
    /// it is 127 in decimal. Both are refused, and for the same reason.
    @Test(
        "An octet with a leading zero is refused in every position, bracketed or mapped or not",
        arguments: [
            "0127.0.0.1", "0177.0.0.1", "00127.0.0.1", "0000127.0.0.1",
            "127.00.0.1", "127.01.0.1", "127.0.00.1", "127.0.01.1", "127.0.0.01", "127.0.0.00", "127.0.0.001",
            "0127.00.00.01",
            "::ffff:0127.0.0.1", "::ffff:0177.0.0.1", "::ffff:127.0.0.01", "::ffff:127.00.0.1",
            "[::ffff:0127.0.0.1]", "[::ffff:127.0.0.01]",
        ])
    func leadingZeroOctets(host: String) {
        #expect(isLoopback(host: host) == false)
    }

    /// The other half of the same rule: a zero octet is written `0`, and that is not a
    /// leading zero.
    @Test(
        "An octet that is exactly zero is not a leading zero",
        arguments: ["127.0.0.0", "127.0.0.1", "127.0.10.0", "127.10.0.100", "::ffff:127.0.0.0", "[::ffff:127.0.0.1]"])
    func zeroOctets(host: String) {
        #expect(isLoopback(host: host) == true)
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

    /// `inet_pton` takes a C string, and Swift hands it the `String` up to the first NUL. Without
    /// a check, `127.0.0.1\0.example.com` is read as `127.0.0.1` — a host that a later, NUL-aware
    /// step (a URL, a resolver, a log) reads as something else — and is called loopback.
    @Test(
        "A host with a NUL in it is not loopback, whatever comes before the NUL",
        arguments: [
            "127.0.0.1\u{0}.example.com", "127.0.0.1\u{0}", "\u{0}127.0.0.1", "::1\u{0}x", "[::1\u{0}]",
            "::ffff:127.0.0.1\u{0}.evil", "localhost\u{0}", "local\u{0}host", "\u{0}",
        ])
    func embeddedNUL(host: String) {
        #expect(isLoopback(host: host) == false)
    }

    @Test(
        "Other control characters and non-ASCII are not loopback either",
        arguments: [
            "127.0.0.1\r", "127.0.0.1\t", "127.0.0.1\u{1b}", "\u{7f}127.0.0.1", "127.0.0.1\u{85}",
            "localhost\u{200b}", "127\u{FF0E}0.0.1", "\u{FF11}27.0.0.1",
        ])
    func controlAndNonASCII(host: String) {
        #expect(isLoopback(host: host) == false)
    }

    /// The names that are over-strict against RFC 6761 §6.3 — which makes `*.localhost` loopback —
    /// are pinned, so that widening the rule is a decision and not an accident. They fail closed.
    @Test("Names under localhost, and localhost with a trailing dot, are not loopback", arguments: ["foo.localhost", "localhost.", ".localhost"])
    func overStrictNames(host: String) {
        #expect(isLoopback(host: host) == false)
    }

    @Test("A bind host and a dial host get the same answer", arguments: ["127.0.0.1", "::1", "localhost", "0.0.0.0", "roseclub.org"])
    func agreesWithBindExposure(host: String) {
        #expect(
            (BindExposure.classify(host: host, tlsConfigured: false) == .loopbackPlaintext) == isLoopback(host: host))
    }
}
