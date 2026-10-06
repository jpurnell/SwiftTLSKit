import NIOSSL
import Testing
import SwiftTLSKit

@Suite("Context configuration")
struct ContextConfigurationTests {
    let authority: TestAuthority
    let fixture: Fixture

    init() throws {
        authority = try TestAuthority(commonName: "SwiftTLSKit Test Authority")
        fixture = try Fixture()
    }

    // MARK: - Server

    @Test("Server options default to TLS 1.2 and no application protocols")
    func serverDefaults() {
        let options = ServerTLSOptions()
        #expect(options.minimumVersion == .tls12)
        #expect(options.applicationProtocols == [])
    }

    @Test("A server context carries the leaf it serves and the options it was given")
    func serverContextReports() throws {
        let leaf = try authority.issueLeaf()
        let loaded = try fixture.install(leaf).load(now: TestInstant.now)
        let options = ServerTLSOptions(minimumVersion: .tls13, applicationProtocols: ["h2"])

        let context = try ServerTLSContext(identity: loaded, options: options)

        #expect(context.leaf == loaded.leaf)
        #expect(context.options == options)
    }

    // MARK: - Client configuration

    @Test("Every trust verifies the chain and the hostname, at TLS 1.2 or newer")
    func verificationIsAlwaysFull() throws {
        let root = CertificateSource.pem(try authority.certificatePEM)
        for trust in [ClientTrust.systemRoots, .additionalRoots([root]), .onlyRoots([root])] {
            let configuration = try trust.makeTLSConfiguration()
            #expect(configuration.certificateVerification == .fullVerification)
            #expect(configuration.minimumTLSVersion == .tlsv12)
            #expect(configuration.applicationProtocols == [])
        }
    }

    @Test("System roots leave the trust store at the platform default")
    func systemRootsConfiguration() throws {
        let configuration = try ClientTrust.systemRoots.makeTLSConfiguration()
        #expect(configuration.trustRoots == .default)
        #expect(configuration.additionalTrustRoots == [])
    }

    @Test("Additional roots keep the platform default and add the supplied certificates")
    func additionalRootsConfiguration() throws {
        let pem = try authority.certificatePEM
        let configuration = try ClientTrust.additionalRoots([.pem(pem)]).makeTLSConfiguration()
        #expect(configuration.trustRoots == .default)
        #expect(configuration.additionalTrustRoots == [.certificates(try NIOSSLCertificate.fromPEMBytes(Array(pem.utf8)))])
    }

    @Test("Only-roots replaces the trust store with the supplied certificates")
    func onlyRootsConfiguration() throws {
        let pem = try authority.certificatePEM
        let configuration = try ClientTrust.onlyRoots([.pem(pem)]).makeTLSConfiguration()
        #expect(configuration.trustRoots == .certificates(try NIOSSLCertificate.fromPEMBytes(Array(pem.utf8))))
        #expect(configuration.additionalTrustRoots == [])
    }

    @Test("The minimum version and application protocols asked for are the ones configured")
    func clientOptionsCarried() throws {
        let configuration = try ClientTrust.systemRoots.makeTLSConfiguration(
            minimumVersion: .tls13, applicationProtocols: ["h2"])
        #expect(configuration.minimumTLSVersion == .tlsv13)
        #expect(configuration.applicationProtocols == ["h2"])
    }

    // MARK: - Client trust that cannot be made

    @Test("An empty list of roots is refused rather than read as 'trust nothing' or 'trust the system'")
    func emptyRoots() {
        #expect(throws: ClientTrustError.noCertificates) { try ClientTLSContext(trust: .additionalRoots([])) }
        #expect(throws: ClientTrustError.noCertificates) { try ClientTLSContext(trust: .onlyRoots([])) }
        #expect(throws: ClientTrustError.noCertificates) { try ClientTrust.onlyRoots([]).makeTLSConfiguration() }
    }

    @Test("A root that cannot be read is refused, naming the source")
    func unreadableRoots() throws {
        let missing = CertificateSource.pemFile(fixture.path("absent.pem"))
        #expect(throws: ClientTrustError.unreadable(missing)) { try ClientTLSContext(trust: .onlyRoots([missing])) }

        let garbage = CertificateSource.pem("not a certificate")
        #expect(throws: ClientTrustError.unreadable(garbage)) { try ClientTLSContext(trust: .onlyRoots([garbage])) }

        let notDER = CertificateSource.der([0x30, 0x00])
        #expect(throws: ClientTrustError.unreadable(notDER)) { try ClientTLSContext(trust: .additionalRoots([notDER])) }

        let good = CertificateSource.pem(try authority.certificatePEM)
        #expect(throws: ClientTrustError.unreadable(missing)) {
            try ClientTLSContext(trust: .onlyRoots([good, missing]))
        }
    }

    @Test("A client context reports the SHA-256 of each root it was given")
    func rootFingerprints() throws {
        let leaf = try authority.issueLeaf()
        let asRoot = try ClientTLSContext(trust: .onlyRoots([.pem(try leaf.certificatePEM)]))
        #expect(asRoot.rootFingerprints == [try leaf.certificateSHA256])
        #expect(try ClientTLSContext(trust: .systemRoots).rootFingerprints == [])
    }

    // MARK: - Server hostname

    @Test("An empty server hostname is refused; there is no way to skip naming the server")
    func emptyHostname() throws {
        let context = try ClientTLSContext(trust: .systemRoots)
        #expect(throws: ClientTrustError.emptyServerHostname) { try context.makeHandlers(serverHostname: "") }
    }

    @Test("A hostname that cannot go in SNI is refused")
    func invalidHostname() throws {
        let context = try ClientTLSContext(trust: .systemRoots)
        #expect(throws: ClientTrustError.invalidServerHostname("bad\u{0}name")) {
            try context.makeHandlers(serverHostname: "bad\u{0}name")
        }
    }

    @Test("One TLS handler is made for a name, and one for an address")
    func handlerCount() throws {
        let context = try ClientTLSContext(trust: .systemRoots)
        #expect(try context.makeHandlers(serverHostname: "roseclub.org").count == 1)
        #expect(try context.makeHandlers(serverHostname: "127.0.0.1").count == 1)
        #expect(try context.makeHandlers(serverHostname: "::1").count == 1)
    }

    @Test("Client trust messages name the source and never suggest turning verification off")
    func messages() {
        #expect(ClientTrustError.noCertificates.description == "No certificates were supplied to trust.")
        #expect(
            ClientTrustError.unreadable(.pemFile("/c/root.pem")).description
                == "No certificate could be read from the PEM file at /c/root.pem.")
        #expect(
            ClientTrustError.unreadable(.derFile("/c/root.der")).description
                == "No certificate could be read from the DER file at /c/root.der.")
        #expect(
            ClientTrustError.unreadable(.pem("x")).description
                == "The supplied PEM text holds no readable certificate.")
        #expect(
            ClientTrustError.unreadable(.der([1])).description
                == "The supplied DER bytes are not a certificate.")
        #expect(
            ClientTrustError.emptyServerHostname.description
                == "No server hostname was given. The server's name is required: it is what its certificate is checked against.")
        #expect(
            ClientTrustError.invalidServerHostname("bad name").description
                == "\"bad name\" cannot be used as a TLS server name.")
        #expect(
            ClientTrustError.contextRejected(reason: "no ciphers").description
                == "The TLS library refused this client configuration: no ciphers.")
    }
}
