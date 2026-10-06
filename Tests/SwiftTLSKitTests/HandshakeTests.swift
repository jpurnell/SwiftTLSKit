import NIOSSL
import Testing
import SwiftTLSKit

/// Real handshakes over loopback, between this package's server context and its client trust.
@Suite("Handshakes over loopback", .timeLimit(.minutes(1)))
struct HandshakeTests {
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

    private func trustingAuthority() throws -> ClientTLSContext {
        try ClientTLSContext(trust: .onlyRoots([.pem(try authority.certificatePEM)]))
    }

    // MARK: - Trust

    @Test("A client that trusts the issuing authority is served the leaf, and data flows")
    func trustedAuthority() async throws {
        let leaf = try authority.issueLeaf()
        let server = try await serve(leaf)

        let client = try await LoopbackClient.connect(
            port: server.port, context: try trustingAuthority(), serverHostname: "localhost")

        #expect(client.report.peerCertificateSHA256 == (try leaf.certificateSHA256))
        #expect(client.report.tlsVersion == .tlsv13)
        #expect(client.report.applicationProtocol == nil)
        #expect(try await client.roundTrip("over TLS") == "over TLS")
        try await client.close()
        try await server.stop()
    }

    @Test("Additional roots from a PEM file are trusted alongside the system's")
    func additionalRootsFromFile() async throws {
        let leaf = try authority.issueLeaf()
        let server = try await serve(leaf)
        let rootPath = try fixture.write(try authority.certificatePEM, to: "root.pem", mode: 0o644)

        let client = try await LoopbackClient.connect(
            port: server.port,
            context: try ClientTLSContext(trust: .additionalRoots([.pemFile(rootPath)])),
            serverHostname: "localhost")

        #expect(client.report.peerCertificateSHA256 == (try leaf.certificateSHA256))
        try await client.close()
        try await server.stop()
    }

    @Test("A client that trusts only the system's roots refuses a private authority")
    func systemRootsRefusePrivateAuthority() async throws {
        let server = try await serve(try authority.issueLeaf())
        let context = try ClientTLSContext(trust: .systemRoots)

        let failure = await handshakeFailure {
            try await LoopbackClient.connect(port: server.port, context: context, serverHostname: "localhost")
        }

        #expect(failure == .certificateNotTrusted)
        try await server.stop()
    }

    @Test("A client that trusts a different authority refuses the server")
    func otherAuthorityRefused() async throws {
        let server = try await serve(try authority.issueLeaf())
        let stranger = try TestAuthority(commonName: "Some Other Authority")
        let context = try ClientTLSContext(trust: .onlyRoots([.pem(try stranger.certificatePEM)]))

        let failure = await handshakeFailure {
            try await LoopbackClient.connect(port: server.port, context: context, serverHostname: "localhost")
        }

        #expect(failure == .certificateNotTrusted)
        try await server.stop()
    }

    // MARK: - Hostname

    @Test("A trusted certificate that names a different host is refused")
    func hostnameMismatch() async throws {
        let server = try await serve(try authority.issueLeaf(dnsNames: ["localhost"]))
        let context = try trustingAuthority()

        let failure = await handshakeFailure {
            try await LoopbackClient.connect(port: server.port, context: context, serverHostname: "elsewhere.example")
        }

        #expect(failure == .hostnameMismatch)
        try await server.stop()
    }

    @Test("The hostname is checked when the system's roots are consulted too")
    func hostnameMismatchWithAdditionalRoots() async throws {
        let leaf = try authority.issueLeaf(dnsNames: ["localhost"])
        let server = try await serve(leaf)
        let context = try ClientTLSContext(trust: .additionalRoots([.pem(try authority.certificatePEM)]))

        let failure = await handshakeFailure {
            try await LoopbackClient.connect(port: server.port, context: context, serverHostname: "elsewhere.example")
        }
        #expect(failure == .wrongHostnameWithSystemRoots)

        // The same client and server with the right name: so it was the name.
        let named = try await LoopbackClient.connect(port: server.port, context: context, serverHostname: "localhost")
        #expect(named.report.peerCertificateSHA256 == (try leaf.certificateSHA256))
        try await named.close()
        try await server.stop()
    }

    @Test("An IP address is verified against the certificate's IP names")
    func ipAddressHostname() async throws {
        let named = try authority.issueLeaf(dnsNames: ["localhost"], ipv4Addresses: [[127, 0, 0, 1]])
        let server = try await serve(named)

        let client = try await LoopbackClient.connect(
            port: server.port, context: try trustingAuthority(), serverHostname: "127.0.0.1")

        #expect(client.report.peerCertificateSHA256 == (try named.certificateSHA256))
        try await client.close()
        try await server.stop()
    }

    @Test("An IP address the certificate does not name is refused")
    func ipAddressNotNamed() async throws {
        let server = try await serve(try authority.issueLeaf(dnsNames: ["localhost"]))
        let context = try trustingAuthority()

        let failure = await handshakeFailure {
            try await LoopbackClient.connect(port: server.port, context: context, serverHostname: "127.0.0.1")
        }

        #expect(failure == .hostnameMismatch)
        try await server.stop()
    }

    // MARK: - Protocol versions

    @Test("A client that speaks nothing newer than TLS 1.1 is refused; the same client at 1.2 is not")
    func tls11Refused() async throws {
        let leaf = try authority.issueLeaf()
        let server = try await serve(leaf)
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.trustRoots = .certificates(try NIOSSLCertificate.fromPEMBytes(Array(try authority.certificatePEM.utf8)))
        configuration.minimumTLSVersion = .tlsv1

        configuration.maximumTLSVersion = .tlsv11
        let oldClient = configuration
        let failure = await handshakeFailure {
            try await LoopbackClient.connect(port: server.port, configuration: oldClient, serverHostname: "localhost")
        }
        #expect(failure == .noSharedProtocolVersion)

        configuration.maximumTLSVersion = .tlsv12
        let client = try await LoopbackClient.connect(
            port: server.port, configuration: configuration, serverHostname: "localhost")
        #expect(client.report.tlsVersion == .tlsv12)
        try await client.close()
        try await server.stop()
    }

    @Test("A server set to TLS 1.3 only refuses a 1.2 client and serves a 1.3 one")
    func tls13Only() async throws {
        let leaf = try authority.issueLeaf()
        let server = try await serve(leaf, options: ServerTLSOptions(minimumVersion: .tls13))
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.trustRoots = .certificates(try NIOSSLCertificate.fromPEMBytes(Array(try authority.certificatePEM.utf8)))
        configuration.maximumTLSVersion = .tlsv12
        let cappedClient = configuration

        let failure = await handshakeFailure {
            try await LoopbackClient.connect(port: server.port, configuration: cappedClient, serverHostname: "localhost")
        }
        #expect(failure == .noSharedProtocolVersion)

        let client = try await LoopbackClient.connect(
            port: server.port, context: try trustingAuthority(), serverHostname: "localhost")
        #expect(client.report.tlsVersion == .tlsv13)
        try await client.close()
        try await server.stop()
    }

    @Test("A client set to TLS 1.3 only is refused by a server capped at 1.2")
    func clientMinimumVersion() async throws {
        let leaf = try authority.issueLeaf()
        let loaded = try fixture.install(leaf).load(now: TestInstant.now)
        var capped = TLSConfiguration.makeServerConfiguration(
            certificateChain: try NIOSSLCertificate.fromPEMBytes(Array(try leaf.chainPEM.utf8)).map { .certificate($0) },
            privateKey: .privateKey(try NIOSSLPrivateKey(bytes: Array(leaf.keyPEM.utf8), format: .pem)))
        capped.maximumTLSVersion = .tlsv12
        let cappedContext = try NIOSSLContext(configuration: capped)
        let server = try await LoopbackServer.start { pipeline in
            try pipeline.addHandler(NIOSSLServerHandler(context: cappedContext))
        }
        #expect(loaded.leaf.publicKeySHA256 == leaf.publicKeySHA256)

        let strict = try ClientTLSContext(
            trust: .onlyRoots([.pem(try authority.certificatePEM)]), minimumVersion: .tls13)
        let failure = await handshakeFailure {
            try await LoopbackClient.connect(port: server.port, context: strict, serverHostname: "localhost")
        }
        #expect(failure == .noSharedProtocolVersion)

        let client = try await LoopbackClient.connect(
            port: server.port, context: try trustingAuthority(), serverHostname: "localhost")
        #expect(client.report.tlsVersion == .tlsv12)
        try await client.close()
        try await server.stop()
    }

    // MARK: - ALPN

    @Test("The application protocol both sides list is the one negotiated")
    func applicationProtocolNegotiated() async throws {
        let server = try await serve(
            try authority.issueLeaf(), options: ServerTLSOptions(applicationProtocols: ["h2", "http/1.1"]))
        let context = try ClientTLSContext(
            trust: .onlyRoots([.pem(try authority.certificatePEM)]), applicationProtocols: ["http/1.1"])

        let client = try await LoopbackClient.connect(port: server.port, context: context, serverHostname: "localhost")

        #expect(client.report.applicationProtocol == "http/1.1")
        try await client.close()
        try await server.stop()
    }

    // MARK: - The pipeline helper

    @Test("The TLS handler goes to the front of the pipeline, ahead of what is already there")
    func handlerGoesFirst() async throws {
        let leaf = try authority.issueLeaf()
        let loaded = try fixture.install(leaf).load(now: TestInstant.now)
        let context = try ServerTLSContext(identity: loaded)
        // The application handler is added *before* TLS here. If the helper appended, the
        // echo would see ciphertext and no handshake could complete.
        let server = try await LoopbackServer.start { pipeline in
            try pipeline.addHandler(EchoHandler())
            try context.addHandler(to: pipeline)
        }

        let client = try await LoopbackClient.connect(
            port: server.port, context: try trustingAuthority(), serverHostname: "localhost")

        #expect(try await client.roundTrip("ordered") == "ordered")
        try await client.close()
        try await server.stop()
    }
}
