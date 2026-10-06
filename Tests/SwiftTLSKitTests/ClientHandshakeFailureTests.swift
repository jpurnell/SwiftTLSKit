import NIOSSL
import Testing
import SwiftTLSKit

/// Each class of failure, produced by a real handshake over loopback and then classified.
///
/// The errors are whatever NIOSSL and BoringSSL actually raise, not ones made up to fit the
/// classifier: the point of publishing it is that a change in what they raise fails here
/// rather than in every consumer that had copied the matching.
@Suite("Classifying a failed client handshake", .timeLimit(.minutes(1)))
struct ClientHandshakeFailureTests {
    let authority: TestAuthority
    let fixture: Fixture

    init() throws {
        authority = try TestAuthority(commonName: "SwiftTLSKit Test Authority")
        fixture = try Fixture()
    }

    private func serve(
        _ leaf: TestLeaf, options: ServerTLSOptions = ServerTLSOptions()
    ) async throws -> LoopbackServer {
        let loaded = try fixture.install(leaf).load(now: TestInstant.now)
        return try await LoopbackServer.start(serving: try ServerTLSContext(identity: loaded, options: options))
    }

    private func failure(
        connectingTo server: LoopbackServer, trust: ClientTrust, minimumVersion: MinimumTLSVersion = .tls12,
        as hostname: String = "localhost"
    ) async throws -> ClientHandshakeFailure? {
        let context = try ClientTLSContext(trust: trust, minimumVersion: minimumVersion)
        return await handshakeFailure {
            try await LoopbackClient.connect(port: server.port, context: context, serverHostname: hostname)
        }
    }

    // MARK: - Not trusted

    @Test("A chain signed by an authority the client was not given is not trusted")
    func unknownAuthority() async throws {
        let server = try await serve(try authority.issueLeaf())
        let stranger = try TestAuthority(commonName: "Some Other Authority")

        #expect(
            try await failure(connectingTo: server, trust: .onlyRoots([.pem(try stranger.certificatePEM)]))
                == .certificateNotTrusted)
        try await server.stop()
    }

    @Test("A private authority is not trusted by the system's roots")
    func privateAuthorityUnderSystemRoots() async throws {
        let server = try await serve(try authority.issueLeaf())

        #expect(try await failure(connectingTo: server, trust: .systemRoots) == .certificateNotTrusted)
        try await server.stop()
    }

    @Test("An expired certificate from a trusted authority is not trusted")
    func expiredLeaf() async throws {
        // Served from a bare NIOSSL context: this package's own server refuses to load it.
        let expired = try authority.issueLeaf(notValidAfter: TestInstant.shortLivedEnd)
        let configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: try NIOSSLCertificate.fromPEMBytes(Array(try expired.chainPEM.utf8)).map { .certificate($0) },
            privateKey: .privateKey(try NIOSSLPrivateKey(bytes: Array(expired.keyPEM.utf8), format: .pem)))
        let context = try NIOSSLContext(configuration: configuration)
        let server = try await LoopbackServer.start { pipeline in
            try pipeline.addHandler(NIOSSLServerHandler(context: context))
        }

        #expect(
            try await failure(connectingTo: server, trust: .onlyRoots([.pem(try authority.certificatePEM)]))
                == .certificateNotTrusted)
        try await server.stop()
    }

    // MARK: - Hostname

    @Test("A trusted certificate for another name is a hostname mismatch when only supplied roots are trusted")
    func wrongNameUnderOnlyRoots() async throws {
        let server = try await serve(try authority.issueLeaf(dnsNames: ["localhost"]))
        let trust = ClientTrust.onlyRoots([.pem(try authority.certificatePEM)])

        #expect(try await failure(connectingTo: server, trust: trust, as: "elsewhere.example") == .hostnameMismatch)
        #expect(ClientHandshakeFailure.wrongHostname(under: trust) == .hostnameMismatch)
        try await server.stop()
    }

    @Test("An address the certificate does not name is a hostname mismatch")
    func wrongAddressUnderOnlyRoots() async throws {
        let server = try await serve(try authority.issueLeaf(dnsNames: ["localhost"]))

        #expect(
            try await failure(
                connectingTo: server, trust: .onlyRoots([.pem(try authority.certificatePEM)]), as: "127.0.0.1")
                == .hostnameMismatch)
        try await server.stop()
    }

    /// The Apple behaviour the type documents. The expectation is written out per platform
    /// here rather than taken from the library, and the library's own account of it —
    /// `wrongHostname(under:)` — is then held to the same value and to what really happened.
    @Test("With the system's roots consulted, a wrong name is reported as the platform reports it")
    func wrongNameWhenSystemRootsAreConsulted() async throws {
        let leaf = try authority.issueLeaf(dnsNames: ["localhost"])
        let server = try await serve(leaf)
        let additional = ClientTrust.additionalRoots([.pem(try authority.certificatePEM)])
        let pinned = ClientTrust.pinned(
            [try .certificate(sha256: try leaf.certificateSHA256)], additionalRoots: [.pem(try authority.certificatePEM)])
        #if canImport(Darwin)
        let expected = ClientHandshakeFailure.certificateNotTrusted
        #else
        let expected = ClientHandshakeFailure.hostnameMismatch
        #endif

        for trust in [additional, pinned] {
            #expect(try await failure(connectingTo: server, trust: trust, as: "elsewhere.example") == expected)
            #expect(ClientHandshakeFailure.wrongHostname(under: trust) == expected)
            // The same trust with the right name connects: so it was the name.
            #expect(try await failure(connectingTo: server, trust: trust) == nil)
        }
        #expect(ClientHandshakeFailure.wrongHostname(under: .systemRoots) == expected)
        try await server.stop()
    }

    @Test("Which trusts consult the system's roots")
    func consultsSystemRoots() throws {
        let root = CertificateSource.pem(try authority.certificatePEM)
        let pin = try CertificatePin.publicKey(sha256: String(repeating: "ab", count: 32))

        #expect(ClientTrust.systemRoots.consultsSystemRoots == true)
        #expect(ClientTrust.additionalRoots([root]).consultsSystemRoots == true)
        #expect(ClientTrust.pinned([pin]).consultsSystemRoots == true)
        #expect(ClientTrust.pinned([pin], additionalRoots: [root]).consultsSystemRoots == true)
        #expect(ClientTrust.onlyRoots([root]).consultsSystemRoots == false)
    }

    // MARK: - Pins

    @Test("A valid certificate that matches no pin is a pin mismatch carrying what was served")
    func pinMismatch() async throws {
        let served = try authority.issueLeaf()
        let expectedLeaf = try authority.issueLeaf()
        let server = try await serve(served)
        let trust = ClientTrust.pinned(
            [try .certificate(sha256: try expectedLeaf.certificateSHA256)],
            additionalRoots: [.pem(try authority.certificatePEM)])

        #expect(
            try await failure(connectingTo: server, trust: trust)
                == .pinMismatch(
                    certificateSHA256: try served.certificateSHA256, publicKeySHA256: served.publicKeySHA256))
        try await server.stop()
    }

    // MARK: - A peer that is not a TLS server

    @Test(
        "A peer that answers in the clear does not speak TLS",
        arguments: [
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "SSH-2.0-OpenSSH_9.9\r\n",
            "220 mail.example ESMTP\r\n",
        ])
    func plaintextPeer(reply: String) async throws {
        let server = try await LoopbackServer.startPlaintext(replying: reply)

        let failure = try await failure(connectingTo: server, trust: .onlyRoots([.pem(try authority.certificatePEM)]))

        #expect(failure == .peerDoesNotSpeakTLS)
        try await server.stop()
    }

    /// Nothing came back, so there is nothing to say the peer is not a TLS server — one that
    /// crashed mid-handshake looks the same. This is deliberately not `peerDoesNotSpeakTLS`.
    @Test("A peer that closes without answering is not classified as anything in particular")
    func silentClose() async throws {
        let server = try await LoopbackServer.startPlaintext(replying: nil)

        let failure = try await failure(connectingTo: server, trust: .onlyRoots([.pem(try authority.certificatePEM)]))

        // The text is NIOSSL's, at the version this package resolves. It is pinned so that a
        // change in what NIOSSL raises here is noticed, and the classification looked at again.
        #expect(failure == .other("handshakeFailed(NIOSSL.BoringSSLError.sslError([Error:  EOF during handshake]))"))
        try await server.stop()
    }

    // MARK: - Protocol versions

    @Test("A TLS 1.3-only client and a server capped at TLS 1.2 share no protocol version")
    func noSharedVersion() async throws {
        let leaf = try authority.issueLeaf()
        var capped = TLSConfiguration.makeServerConfiguration(
            certificateChain: try NIOSSLCertificate.fromPEMBytes(Array(try leaf.chainPEM.utf8)).map { .certificate($0) },
            privateKey: .privateKey(try NIOSSLPrivateKey(bytes: Array(leaf.keyPEM.utf8), format: .pem)))
        capped.maximumTLSVersion = .tlsv12
        let context = try NIOSSLContext(configuration: capped)
        let server = try await LoopbackServer.start { pipeline in
            try pipeline.addHandler(NIOSSLServerHandler(context: context))
        }

        #expect(
            try await failure(
                connectingTo: server, trust: .onlyRoots([.pem(try authority.certificatePEM)]), minimumVersion: .tls13)
                == .noSharedProtocolVersion)
        try await server.stop()
    }

    // MARK: - Everything else

    @Test("An error that is not a handshake failure is `other`, carrying its description")
    func unrelatedErrors() {
        #expect(ClientHandshakeFailure(LoopbackError.noPort) == .other("noPort"))
        // A refusal from this package that is not a pin mismatch is not reclassified.
        #expect(ClientHandshakeFailure(ClientTrustError.noPins) == .other("A pinned trust was given no pins."))
        // Text that merely mentions a BoringSSL reason is not a BoringSSL error.
        #expect(
            ClientHandshakeFailure(Mention(text: "CERTIFICATE_VERIFY_FAILED"))
                == .other("Mention(text: \"CERTIFICATE_VERIFY_FAILED\")"))
        #expect(ClientHandshakeFailure(Mention(text: "WRONG_VERSION_NUMBER")) == .other("Mention(text: \"WRONG_VERSION_NUMBER\")"))
    }

    /// An error whose description contains a BoringSSL reason code, and which is not one.
    private struct Mention: Error {
        let text: String
    }

    // MARK: - Messages

    @Test("Each class reads as a sentence")
    func descriptions() {
        #expect(
            ClientHandshakeFailure.certificateNotTrusted.description
                == "The server's certificate is not trusted: its chain does not lead to a trusted root, or is "
                + "expired or otherwise invalid.")
        #expect(
            ClientHandshakeFailure.hostnameMismatch.description
                == "The server's certificate is trusted, but was not issued for the host that was dialled.")
        #expect(
            ClientHandshakeFailure.pinMismatch(certificateSHA256: "aa", publicKeySHA256: "bb").description
                == "The server's certificate matches none of the pins. It presented a certificate with SHA-256 aa "
                + "and a public key with SHA-256 bb. Nothing was sent to it.")
        #expect(
            ClientHandshakeFailure.peerDoesNotSpeakTLS.description
                == "The peer answered with something that is not TLS. It is probably a plaintext listener.")
        #expect(
            ClientHandshakeFailure.noSharedProtocolVersion.description
                == "The client and the server support no TLS version in common.")
        #expect(ClientHandshakeFailure.other("uncleanShutdown").description == "The TLS handshake failed: uncleanShutdown")
    }
}
