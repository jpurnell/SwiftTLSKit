import Testing
import SwiftTLSKit

@Suite("Resolving a certificate and key pair of options")
struct ServerIdentityResolveTests {

    @Test("Neither path means no TLS")
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

    @Test("A certificate without a key is an error, not plaintext")
    func certificateOnly() {
        #expect(throws: ServerIdentityError.incompletePair(present: .certificateChain, path: "/certs/fullchain.pem")) {
            try ServerIdentity.resolve(certificateChainPath: "/certs/fullchain.pem", privateKeyPath: nil)
        }
    }

    @Test("A key without a certificate is an error, not plaintext")
    func keyOnly() {
        #expect(throws: ServerIdentityError.incompletePair(present: .privateKey, path: "/certs/privkey.pem")) {
            try ServerIdentity.resolve(certificateChainPath: nil, privateKeyPath: "/certs/privkey.pem")
        }
    }

    @Test("The half-pair messages say which half is missing and that plaintext is not the result")
    func messages() {
        #expect(
            ServerIdentityError.incompletePair(present: .certificateChain, path: "/certs/fullchain.pem").description
                == "A TLS certificate chain was given (/certs/fullchain.pem) without a private key. "
                + "Supply both to serve TLS, or neither to serve plaintext; one without the other is refused.")
        #expect(
            ServerIdentityError.incompletePair(present: .privateKey, path: "/certs/privkey.pem").description
                == "A TLS private key was given (/certs/privkey.pem) without a certificate chain. "
                + "Supply both to serve TLS, or neither to serve plaintext; one without the other is refused.")
    }
}
