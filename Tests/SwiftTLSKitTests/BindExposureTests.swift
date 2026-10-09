import Testing
import SwiftTLSKit

@Suite("Bind exposure")
struct BindExposureTests {

    @Test("TLS is TLS whatever the host", arguments: ["127.0.0.1", "0.0.0.0", "::", "roseclub.org", ""])
    func tlsConfigured(host: String) {
        #expect(BindExposure.classify(host: host, tlsConfigured: true) == .tls)
    }

    @Test(
        "Plaintext on loopback is loopback plaintext",
        arguments: ["127.0.0.1", "127.8.9.10", "::1", "[::1]", "0:0:0:0:0:0:0:1", "localhost", "LOCALHOST", "::ffff:127.0.0.1"])
    func loopbackPlaintext(host: String) {
        #expect(BindExposure.classify(host: host, tlsConfigured: false) == .loopbackPlaintext)
    }

    @Test(
        "Plaintext anywhere else is exposed, and names the host",
        arguments: [
            "0.0.0.0", "::", "10.0.1.114", "128.0.0.1", "::2", "roseclub.org", "", "127.0.0.1.example.com",
            "localhost.example.com", "127.0.0", "1270.0.0.1", "::ffff:10.0.0.1",
            // Spellings another parser reads differently, or that are not a host at all. An octet
            // with a leading zero is octal to `inet_aton` and decimal to `inet_pton`.
            "0127.0.0.1", "127.0.0.01", "::ffff:0127.0.0.1", "[127.0.0.1]", "[localhost]", "::1%lo0",
        ])
    func exposedPlaintext(host: String) {
        #expect(BindExposure.classify(host: host, tlsConfigured: false) == .exposedPlaintext(host: host))
    }

    @Test("Only exposed plaintext is flagged")
    func isExposedPlaintext() {
        #expect(BindExposure.tls.isExposedPlaintext == false)
        #expect(BindExposure.loopbackPlaintext.isExposedPlaintext == false)
        #expect(BindExposure.exposedPlaintext(host: "0.0.0.0").isExposedPlaintext == true)
    }

    @Test("The exposed-plaintext message names the host and the remedy")
    func message() {
        #expect(
            BindExposure.exposedPlaintext(host: "0.0.0.0").description
                == "Plaintext on 0.0.0.0: this listener is reachable from other machines without TLS. "
                + "Supply a certificate chain and private key, or bind to 127.0.0.1.")
        #expect(BindExposure.loopbackPlaintext.description == "Plaintext on loopback only.")
        #expect(BindExposure.tls.description == "TLS is configured.")
    }
}
