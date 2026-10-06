import Testing
import SwiftTLSKit

@Suite("Resolving a certificate and key pair of options")
struct ServerIdentityResolveTests {

    @Test("Neither path is no identity")
    func neither() throws {
        #expect(try ServerIdentity.resolve(certificateChainPath: nil, privateKeyPath: nil) == nil)
    }

    @Test("Both paths are an identity naming both")
    func both() throws {
        let resolved = try ServerIdentity.resolve(
            certificateChainPath: "/certs/fullchain.pem", privateKeyPath: "/certs/privkey.pem")
        #expect(
            resolved == ServerIdentity(
                certificateChainPath: "/certs/fullchain.pem", privateKeyPath: "/certs/privkey.pem"))
    }

    @Test("A certificate without a key is an error that says which half is present, and where")
    func certificateOnly() {
        #expect(throws: IncompleteServerIdentity(present: .certificateChain, path: "/certs/fullchain.pem")) {
            try ServerIdentity.resolve(certificateChainPath: "/certs/fullchain.pem", privateKeyPath: nil)
        }
    }

    @Test("A key without a certificate is an error that says which half is present, and where")
    func keyOnly() {
        #expect(throws: IncompleteServerIdentity(present: .privateKey, path: "/certs/privkey.pem")) {
            try ServerIdentity.resolve(certificateChainPath: nil, privateKeyPath: "/certs/privkey.pem")
        }
    }

    @Test("The missing half is the other one")
    func missing() {
        #expect(IncompleteServerIdentity(present: .certificateChain, path: "/c").missing == .privateKey)
        #expect(IncompleteServerIdentity(present: .privateKey, path: "/k").missing == .certificateChain)
    }

    /// The whole sentence, because what it must not say matters as much as what it says: a
    /// consumer that refuses plaintext cannot show its operator "or neither to serve plaintext".
    @Test("The message names the half and the path, and makes no promise about plaintext")
    func messages() {
        #expect(
            IncompleteServerIdentity(present: .certificateChain, path: "/certs/fullchain.pem").description
                == "A TLS certificate chain was given (/certs/fullchain.pem) without a private key. "
                + "A server identity needs both; one without the other is refused.")
        #expect(
            IncompleteServerIdentity(present: .privateKey, path: "/certs/privkey.pem").description
                == "A TLS private key was given (/certs/privkey.pem) without a certificate chain. "
                + "A server identity needs both; one without the other is refused.")
    }

    @Test("The message can name the consumer's own settings")
    func messagesNamingSettings() {
        #expect(
            IncompleteServerIdentity(present: .certificateChain, path: "/certs/fullchain.pem")
                .description(certificateChainSetting: "--tls-cert", privateKeySetting: "--tls-key")
                == "--tls-cert was given (/certs/fullchain.pem) without --tls-key. "
                + "A server identity needs both; one without the other is refused.")
        #expect(
            IncompleteServerIdentity(present: .privateKey, path: "/certs/privkey.pem")
                .description(certificateChainSetting: "--tls-cert", privateKeySetting: "--tls-key")
                == "--tls-key was given (/certs/privkey.pem) without --tls-cert. "
                + "A server identity needs both; one without the other is refused.")
    }

    @Test("No message mentions plaintext", arguments: [IncompleteServerIdentity.Half.certificateChain, .privateKey])
    func noPlaintextPromise(present: IncompleteServerIdentity.Half) {
        let error = IncompleteServerIdentity(present: present, path: "/p")
        #expect(error.description.lowercased().contains("plaintext") == false)
        #expect(
            error.description(certificateChainSetting: "cert", privateKeySetting: "key").lowercased()
                .contains("plaintext") == false)
    }
}
