import NIOCore
import NIOPosix
import Testing
import SwiftTLSKit
import SwiftTLSKitTestSupport

@Suite("Pinned trust", .timeLimit(.minutes(1)))
struct PinningTests {
    let authority: TestAuthority

    init() throws {
        authority = try TestAuthority(commonName: "SwiftTLSKit Test Authority", generator: SeededGenerator(seed: TestSeed.authority))
    }

    /// From memory: nothing in this suite is about files, so no key is written to one.
    private func context(serving leaf: TestLeaf) throws -> ServerTLSContext {
        try leaf.serverContext(now: TestInstant.now)
    }

    private func pinned(_ pins: [CertificatePin], trustingAuthority: Bool = true) throws -> ClientTLSContext {
        try ClientTLSContext(
            trust: .pinned(pins, additionalRoots: trustingAuthority ? [.pem(authority.certificatePEM)] : []))
    }

    // MARK: - Matching and not matching

    @Test("A pinned certificate that is the one served connects, and data flows")
    func certificatePinMatches() async throws {
        let leaf = try authority.issueLeaf()
        let server = try await LoopbackServer.start(serving: try context(serving: leaf))
        let pin = try CertificatePin.certificate(sha256: leaf.certificateSHA256)

        let client = try await LoopbackClient.connect(
            port: server.port, context: try pinned([pin]), serverHostname: "localhost")

        #expect(client.report.peerCertificateSHA256 == leaf.certificateSHA256)
        #expect(try await client.roundTrip("pinned") == "pinned")
        try await client.close()
        try await server.stop()
    }

    @Test("A pinned public key that is the one served connects")
    func publicKeyPinMatches() async throws {
        let leaf = try authority.issueLeaf()
        let server = try await LoopbackServer.start(serving: try context(serving: leaf))
        let pin = try CertificatePin.publicKey(sha256: leaf.publicKeySHA256)

        let client = try await LoopbackClient.connect(
            port: server.port, context: try pinned([pin]), serverHostname: "localhost")

        #expect(try await client.roundTrip("pinned") == "pinned")
        try await client.close()
        try await server.stop()
    }

    @Test("A different certificate from the same trusted authority is refused, and the error says what was served")
    func certificatePinMismatch() async throws {
        let served = try authority.issueLeaf()
        let expected = try authority.issueLeaf()
        let server = try await LoopbackServer.start(serving: try context(serving: served))
        let client = try pinned([try CertificatePin.certificate(sha256: expected.certificateSHA256)])

        let refusal = await handshakeFailure {
            try await LoopbackClient.connect(port: server.port, context: client, serverHostname: "localhost")
        }
        #expect(
            refusal == .pinMismatch(
                certificateSHA256: served.certificateSHA256, publicKeySHA256: served.publicKeySHA256))
        try await server.stop()
    }

    @Test("A different public key from the same trusted authority is refused")
    func publicKeyPinMismatch() async throws {
        let served = try authority.issueLeaf()
        let expected = try authority.issueLeaf()
        let server = try await LoopbackServer.start(serving: try context(serving: served))
        let client = try pinned([try CertificatePin.publicKey(sha256: expected.publicKeySHA256)])

        let refusal = await handshakeFailure {
            try await LoopbackClient.connect(port: server.port, context: client, serverHostname: "localhost")
        }
        #expect(
            refusal == .pinMismatch(
                certificateSHA256: served.certificateSHA256, publicKeySHA256: served.publicKeySHA256))
        try await server.stop()
    }

    @Test("A certificate digest is not accepted as a public-key pin, nor the reverse")
    func pinKindsAreNotInterchangeable() async throws {
        let leaf = try authority.issueLeaf()
        let server = try await LoopbackServer.start(serving: try context(serving: leaf))
        let crossed = try pinned([
            try CertificatePin.publicKey(sha256: leaf.certificateSHA256),
            try CertificatePin.certificate(sha256: leaf.publicKeySHA256),
        ])

        let refusal = await handshakeFailure {
            try await LoopbackClient.connect(port: server.port, context: crossed, serverHostname: "localhost")
        }
        #expect(
            refusal == .pinMismatch(
                certificateSHA256: leaf.certificateSHA256, publicKeySHA256: leaf.publicKeySHA256))
        try await server.stop()
    }

    @Test("Any one of several pins is enough, which is how a key is rotated")
    func anyPinMatches() async throws {
        let current = try authority.issueLeaf()
        let next = try authority.issueLeaf()
        let server = try await LoopbackServer.start(serving: try context(serving: next))
        let pins = [
            try CertificatePin.publicKey(sha256: current.publicKeySHA256),
            try CertificatePin.publicKey(sha256: next.publicKeySHA256),
        ]

        let client = try await LoopbackClient.connect(
            port: server.port, context: try pinned(pins), serverHostname: "localhost")

        #expect(client.report.peerCertificateSHA256 == next.certificateSHA256)
        try await client.close()
        try await server.stop()
    }

    @Test("A public-key pin survives a renewal that keeps the key; a certificate pin does not")
    func renewalWithSameKey() async throws {
        let original = try authority.issueLeaf()
        let renewed = try authority.issueLeaf(reusingKeyOf: original)
        let server = try await LoopbackServer.start(serving: try context(serving: renewed))

        let byKey = try await LoopbackClient.connect(
            port: server.port,
            context: try pinned([try CertificatePin.publicKey(sha256: original.publicKeySHA256)]),
            serverHostname: "localhost")
        #expect(byKey.report.peerCertificateSHA256 == renewed.certificateSHA256)
        try await byKey.close()

        let byCertificate = try pinned([try CertificatePin.certificate(sha256: original.certificateSHA256)])
        let refusal = await handshakeFailure {
            try await LoopbackClient.connect(port: server.port, context: byCertificate, serverHostname: "localhost")
        }
        #expect(
            refusal == .pinMismatch(
                certificateSHA256: renewed.certificateSHA256, publicKeySHA256: original.publicKeySHA256))
        try await server.stop()
    }

    // MARK: - A pin narrows trust; it never widens it

    @Test("A matching pin does not excuse an untrusted chain")
    func pinDoesNotReplaceChainValidation() async throws {
        let leaf = try authority.issueLeaf()
        let server = try await LoopbackServer.start(serving: try context(serving: leaf))
        let client = try pinned(
            [try CertificatePin.certificate(sha256: leaf.certificateSHA256)], trustingAuthority: false)

        let failure = await handshakeFailure {
            try await LoopbackClient.connect(port: server.port, context: client, serverHostname: "localhost")
        }

        #expect(failure == .certificateNotTrusted)
        try await server.stop()
    }

    @Test("A matching pin does not excuse the wrong hostname")
    func pinDoesNotReplaceHostnameVerification() async throws {
        let leaf = try authority.issueLeaf(dnsNames: ["localhost"])
        let server = try await LoopbackServer.start(serving: try context(serving: leaf))
        let client = try pinned([try CertificatePin.certificate(sha256: leaf.certificateSHA256)])

        let failure = await handshakeFailure {
            try await LoopbackClient.connect(port: server.port, context: client, serverHostname: "elsewhere.example")
        }
        #expect(failure == .wrongHostnameWithSystemRoots)

        // The same client, server and pin, with the right name: so it was the name.
        let named = try await LoopbackClient.connect(port: server.port, context: client, serverHostname: "localhost")
        #expect(named.report.peerCertificateSHA256 == leaf.certificateSHA256)
        try await named.close()
        try await server.stop()
    }

    // MARK: - Nothing is sent to a server that fails its pin

    @Test("Bytes written before the handshake reach a server that matches its pin, and never one that does not")
    func earlyWritesAreHeldUntilThePinIsChecked() async throws {
        let served = try authority.issueLeaf()
        let other = try authority.issueLeaf()
        let (server, receivedBytes) = try await LoopbackServer.startCounting(serving: try context(serving: served))
        var received = receivedBytes.makeAsyncIterator()

        let matching = try pinned([try CertificatePin.certificate(sha256: served.certificateSHA256)])
        let delivered = try await LoopbackClient.connect(port: server.port) { pipeline in
            try matching.addHandlers(to: pipeline, serverHostname: "localhost")
            try pipeline.addHandler(EarlyWriter("credentials"))
        }
        try await delivered.close()
        #expect(await received.next() == 11)

        let mismatching = try pinned([try CertificatePin.certificate(sha256: other.certificateSHA256)])
        let refusal = await handshakeFailure {
            try await LoopbackClient.connect(port: server.port) { pipeline in
                try mismatching.addHandlers(to: pipeline, serverHostname: "localhost")
                try pipeline.addHandler(EarlyWriter("credentials"))
            }
        }
        #expect(
            refusal == .pinMismatch(
                certificateSHA256: served.certificateSHA256, publicKeySHA256: served.publicKeySHA256))
        #expect(await received.next() == 0)
        try await server.stop()
    }

    @Test("Writes queued before the handshake are bounded, and the one past the bound fails")
    func earlyWritesAreBounded() async throws {
        let leaf = try authority.issueLeaf()
        let server = try await LoopbackServer.startSilent()
        let client = try pinned([try CertificatePin.certificate(sha256: leaf.certificateSHA256)])
        let channel = try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try client.addHandlers(to: channel.pipeline.syncOperations, serverHostname: "localhost")
                }
            }
            .connect(host: "127.0.0.1", port: server.port)
            .get()

        // A guard against a hung suite, not a measurement: if nothing bounds the queue, the
        // write below would wait on a handshake that never comes, and this closes the channel
        // so that it fails instead.
        let guardrail = channel.eventLoop.scheduleTask(in: .seconds(20)) { channel.close(promise: nil) }

        for _ in 0..<1_024 {
            channel.write(ByteBuffer(string: "x"), promise: nil)
        }
        await #expect(throws: ClientTrustError.tooManyWritesBeforeHandshake(limit: 1_024)) {
            try await channel.write(ByteBuffer(string: "x")).get()
        }
        guardrail.cancel()
        try await channel.close()
        try await server.stop()
    }

    // MARK: - Writing a pin down

    @Test("A digest is accepted as hex, as openssl's colon-separated hex, and as base64, and all three are one pin")
    func pinSpellings() throws {
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        let colons = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"
        let base64 = "ABEiM0RVZneImaq7zN3u/wARIjNEVWZ3iJmqu8zd7v8="

        let pin = try CertificatePin.publicKey(sha256: hex)
        #expect(pin.sha256 == hex)
        #expect(pin.subject == .publicKey)
        #expect(try CertificatePin.publicKey(sha256: colons) == pin)
        #expect(try CertificatePin.publicKey(sha256: base64) == pin)
        #expect(try CertificatePin.certificate(sha256: hex).subject == .certificate)
        #expect(try CertificatePin.certificate(sha256: hex) != pin)
        #expect(pin.description == "public key SHA-256 \(hex)")
        #expect(try CertificatePin.certificate(sha256: hex).description == "certificate SHA-256 \(hex)")
    }

    @Test(
        "Text that is not a SHA-256 digest is refused, quoting it",
        arguments: [
            "", "abcd", "zz112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
            "ABEiM0RVZneImaq7zN3u/wARIjNEVWZ3iJmqu8zd7g==",
        ])
    func invalidPin(text: String) {
        #expect(throws: ClientTrustError.invalidPin(text)) { try CertificatePin.certificate(sha256: text) }
        #expect(throws: ClientTrustError.invalidPin(text)) { try CertificatePin.publicKey(sha256: text) }
    }

    @Test("A pinned trust with no pins is refused rather than read as 'no pinning'")
    func noPins() {
        #expect(throws: ClientTrustError.noPins) { try ClientTLSContext(trust: .pinned([])) }
    }

    // MARK: - Where a pin can and cannot be enforced

    @Test("A pinned trust makes two handlers: TLS, then the pin check")
    func pinnedHandlers() throws {
        let leaf = try authority.issueLeaf()
        let client = try pinned([try CertificatePin.certificate(sha256: leaf.certificateSHA256)])
        #expect(try client.makeHandlers(serverHostname: "localhost").count == 2)
        #expect(client.rootFingerprints == [authority.certificateSHA256])
    }

    @Test("A pinned trust refuses to be flattened into a bare TLSConfiguration, which could not enforce it")
    func pinnedConfigurationRefused() throws {
        let leaf = try authority.issueLeaf()
        let trust = ClientTrust.pinned([try CertificatePin.certificate(sha256: leaf.certificateSHA256)])
        #expect(throws: ClientTrustError.pinsNeedHandlers) { try trust.makeTLSConfiguration() }
    }

    @Test("Pin messages say what was served and what to do")
    func messages() {
        #expect(
            ClientTrustError.invalidPin("abcd").description
                == "\"abcd\" is not a SHA-256 digest. Give 64 hexadecimal digits (colons allowed) or 44 characters of base64.")
        #expect(ClientTrustError.noPins.description == "A pinned trust was given no pins.")
        #expect(
            ClientTrustError.pinsNeedHandlers.description
                == "A pinned trust cannot be expressed as a TLSConfiguration: the pin is checked by a handler after "
                + "the handshake. Use ClientTLSContext.addHandlers(to:serverHostname:).")
        #expect(
            ClientTrustError.pinMismatch(certificateSHA256: "aa", publicKeySHA256: "bb").description
                == "The server's certificate matches none of the pins. It presented a certificate with SHA-256 aa "
                + "and a public key with SHA-256 bb. Nothing was sent to it.")
        #expect(
            ClientTrustError.tooManyWritesBeforeHandshake(limit: 1_024).description
                == "More than 1024 writes were queued before the TLS handshake finished.")
    }
}
