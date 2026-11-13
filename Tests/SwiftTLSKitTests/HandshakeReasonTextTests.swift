@testable import SwiftTLSKit
import Testing

/// How `ClientHandshakeFailure` reads a BoringSSL error's description.
///
/// NIOSSL keeps the error's code and reason private and prints both in `description`:
///
///     Error: 268435581 error:1000007d:SSL routines:OPENSSL_internal:CERTIFICATE_VERIFY_FAILED at <file>:<line>
///
/// The first two lines of real text below were captured from a handshake against this build
/// (NIOSSL 2.37.5). The others are the same shape with a different reason, and their numbers are
/// worked out, not copied: the SSL library is 16 and sits in the top byte, so a reason `r` is
/// `16 << 24 | r` = `268435456 + r`, and `error:` prints that in eight hex digits. The reasons
/// are `SSL_R_UNSUPPORTED_PROTOCOL` 240 and `SSL_R_TLSV1_ALERT_PROTOCOL_VERSION` 1070.
///
/// The description is the only thing there is to read. `BoringSSLInternalError` cannot be
/// constructed outside NIOSSL, so a test cannot hand the classifier a renumbered error — it can
/// hand it the text.
@Suite("Reading a BoringSSL error's description")
struct HandshakeReasonTextTests {
    private static func description(number: UInt32?, hex: String?, reason: String, library: String = "SSL routines") -> String {
        let prefix = number.map { "Error: \($0) " } ?? ""
        let code = hex.map { "error:\($0):\(library):OPENSSL_internal:" } ?? ""
        return prefix + code + reason + " at ssl/handshake.cc:288"
    }

    // MARK: The four classes, as NIOSSL prints them now

    @Test(
        "Each class is read from the text NIOSSL prints now",
        arguments: [
            (268_435_581, "1000007d", "CERTIFICATE_VERIFY_FAILED", ClientHandshakeFailure.certificateNotTrusted),
            (268_435_703, "100000f7", "WRONG_VERSION_NUMBER", .peerDoesNotSpeakTLS),
            (268_435_696, "100000f0", "UNSUPPORTED_PROTOCOL", .noSharedProtocolVersion),
            (268_436_526, "1000042e", "TLSV1_ALERT_PROTOCOL_VERSION", .noSharedProtocolVersion),
        ] as [(UInt32, String, String, ClientHandshakeFailure)])
    func current(number: UInt32, hex: String, reason: String, expected: ClientHandshakeFailure) {
        let text = Self.description(number: number, hex: hex, reason: reason)
        #expect(ClientHandshakeFailure.classify(boringSSLDescription: text) == expected)
    }

    // MARK: Each signal alone

    @Test("The name is enough when the packed number is not there")
    func nameAlone() {
        let text = Self.description(number: nil, hex: "1000007d", reason: "CERTIFICATE_VERIFY_FAILED")
        #expect(ClientHandshakeFailure.classify(boringSSLDescription: text) == .certificateNotTrusted)
    }

    @Test("The number is enough when the name is not there")
    func numberAlone() {
        #expect(
            ClientHandshakeFailure.classify(boringSSLDescription: "Error: 268435703 something else entirely")
                == .peerDoesNotSpeakTLS)
    }

    // MARK: Renumbering

    @Test("A renumbered reason is still read by its name")
    func renumbered() {
        // Reason 999 is nothing this package knows; the name is the one it does.
        let text = Self.description(number: 268_436_455, hex: "100003e7", reason: "CERTIFICATE_VERIFY_FAILED")
        #expect(ClientHandshakeFailure.classify(boringSSLDescription: text) == .certificateNotTrusted)
    }

    @Test("A number that now means another reason is not believed over a name that says otherwise")
    func numberAndNameDisagree() {
        // 268435581 is CERTIFICATE_VERIFY_FAILED's number; the name says it is a version error.
        let text = Self.description(number: 268_435_581, hex: "1000007d", reason: "WRONG_VERSION_NUMBER")
        #expect(ClientHandshakeFailure.classify(boringSSLDescription: text) == nil)
    }

    @Test("A well-formed reason this package does not know is not classified, whatever the number says")
    func unknownName() {
        let text = Self.description(number: 268_435_581, hex: "1000007d", reason: "SOME_REASON_ADDED_LATER")
        #expect(ClientHandshakeFailure.classify(boringSSLDescription: text) == nil)
    }

    // MARK: Text that only looks like one

    @Test(
        "Text that mentions a reason but is not a BoringSSL error's description is not classified",
        arguments: [
            "",
            "Error: ",
            "CERTIFICATE_VERIFY_FAILED",
            "Error: 1 something CERTIFICATE_VERIFY_FAILED",
            "the handshake failed with WRONG_VERSION_NUMBER",
            "error:1000007d:SSL routines:OPENSSL_internal:NOT_CERTIFICATE_VERIFY_FAILED at a.cc:1",
            "error:1000007d:SSL routines:OPENSSL_internal:certificate_verify_failed at a.cc:1",
            "error:1000007d:SSL routines:OPENSSL_internal:CERTIFICATE_VERIFY_FAILED_AGAIN at a.cc:1",
            // The reason is in the file name, not where the reason goes.
            "error:1000007d:SSL routines:OPENSSL_internal:UNRELATED at /build/WRONG_VERSION_NUMBER.cc:1",
        ])
    func lookalikes(text: String) {
        #expect(ClientHandshakeFailure.classify(boringSSLDescription: text) == nil)
    }

    @Test("The same reason name from another library is not an SSL error")
    func otherLibrary() {
        let text = Self.description(
            number: nil, hex: "0b000074", reason: "CERTIFICATE_VERIFY_FAILED", library: "X509 certificate routines")
        #expect(ClientHandshakeFailure.classify(boringSSLDescription: text) == nil)
    }

    @Test("A number in another library is not an SSL reason, even with a reason's value")
    func numberFromAnotherLibrary() {
        // Library 11 (0x0b), reason 125.
        #expect(ClientHandshakeFailure.classify(boringSSLDescription: "Error: 184549501 not a name") == nil)
    }

    @Test("The reason is read from the first part that looks like one, however long the rest")
    func longTail() {
        let tail = String(repeating: ":CERTIFICATE_VERIFY_FAILED", count: 500)
        let text = "error:1000007d:SSL routines:OPENSSL_internal:WRONG_VERSION_NUMBER at a.cc:1" + tail
        #expect(ClientHandshakeFailure.classify(boringSSLDescription: text) == .peerDoesNotSpeakTLS)
    }
}
