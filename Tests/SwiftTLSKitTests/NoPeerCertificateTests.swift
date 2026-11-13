import NIOCore
import NIOEmbedded
import NIOSSL
import NIOTLS
import SwiftTLSKit
import Testing

/// A handshake that "completes" with no certificate from the server. No real handshake does that
/// with certificate verification on, so the pin handler is put in that state directly: an
/// embedded channel, the real TLS handler that has never handshaken, and the event a finished
/// handshake sends.
@Suite("A pinned client and a server that presents no certificate")
struct NoPeerCertificateTests {
    private static let anyPin = String(repeating: "00", count: 32)

    private func channelAfterHandshake() throws -> EmbeddedChannel {
        let context = try ClientTLSContext(trust: .pinned([try .certificate(sha256: Self.anyPin)]))
        let channel = EmbeddedChannel()
        try channel.pipeline.syncOperations.addHandlers(try context.makeHandlers(serverHostname: "localhost"))
        channel.pipeline.fireUserInboundEventTriggered(TLSUserEvent.handshakeCompleted(negotiatedProtocol: nil))
        return channel
    }

    @Test("It is refused as having no certificate, not as a mismatch with an empty one")
    func refused() throws {
        let channel = try channelAfterHandshake()

        #expect(throws: ClientTrustError.noPeerCertificate) { try channel.throwIfErrorCaught() }
    }

    @Test("The connection is closed, and a write after it fails")
    func closed() throws {
        let channel = try channelAfterHandshake()
        _ = try? channel.throwIfErrorCaught()

        #expect(channel.isActive == false)
    }

    @Test("The message says what happened")
    func message() {
        #expect(
            ClientTrustError.noPeerCertificate.description
                == "The server presented no certificate, so there is nothing to compare with the pins. Nothing was sent to it.")
    }

    @Test("It classifies as other, carrying that message: it is not a pin mismatch")
    func classification() {
        #expect(
            ClientHandshakeFailure(ClientTrustError.noPeerCertificate)
                == .other(ClientTrustError.noPeerCertificate.description))
    }
}
