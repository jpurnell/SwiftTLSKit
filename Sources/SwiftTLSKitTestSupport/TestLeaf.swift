import Crypto
import Foundation
import SwiftTLSKit

/// A server certificate and its private key, made when a test runs by a ``TestAuthority``.
///
/// The key exists in the test process. It reaches disk only if the test writes
/// ``privateKeyPEM`` there itself, which a test of file handling has to and no other test
/// needs to: ``serverContext(options:now:)`` builds a context from memory.
public struct TestLeaf: Sendable {
    /// The leaf certificate alone, PEM-encoded.
    public let certificatePEM: String

    /// The leaf certificate followed by the authority's: the order and content of certbot's
    /// `fullchain.pem`.
    public let chainPEM: String

    /// SHA-256 of the leaf certificate in DER, as lowercase hex: what
    /// `openssl x509 -noout -fingerprint -sha256` prints, without the colons.
    ///
    /// Computed by swift-certificates and swift-crypto, not by SwiftTLSKit, so that a test can
    /// compare it with what SwiftTLSKit reports.
    public let certificateSHA256: String

    let key: P256.Signing.PrivateKey

    /// The leaf's private key as unencrypted PEM: the content of certbot's `privkey.pem`.
    ///
    /// A test key, for a certificate nothing trusts. It is here for tests that exercise file
    /// handling — permissions, missing files, a mismatched pair — and so have to write one.
    public var privateKeyPEM: String {
        key.pemRepresentation
    }

    /// SHA-256 of the leaf's SubjectPublicKeyInfo in DER, as lowercase hex.
    ///
    /// The value a ``SwiftTLSKit/CertificatePin/publicKey(sha256:)`` pin takes. Computed by
    /// swift-crypto, not by SwiftTLSKit.
    public var publicKeySHA256: String {
        LowercaseHex.encode(SHA256.hash(data: key.publicKey.derRepresentation))
    }

    /// A server context that serves this leaf, built without writing anything to disk.
    ///
    /// The chain and key go through every check SwiftTLSKit makes of an identity's contents:
    /// the key must be the leaf's and the leaf must be valid at `now`. The checks it makes of
    /// files — that the key is a regular file only its owner can read — have nothing to apply
    /// to. Errors name `<in-memory certificate chain>` and `<in-memory private key>` where a
    /// path would be.
    ///
    /// - Parameters:
    ///   - options: The minimum TLS version and ALPN protocols.
    ///   - now: The current time, against which the leaf's validity is judged. Usually
    ///     ``TestInstant/now``.
    /// - Returns: The context.
    /// - Throws: ``SwiftTLSKit/ServerIdentityError`` if the leaf is not valid at `now`.
    public func serverContext(
        options: ServerTLSOptions = ServerTLSOptions(),
        now: Date
    ) throws(ServerIdentityError) -> ServerTLSContext {
        try ServerTLSContext(identity: try loadedIdentity(now: now), options: options)
    }

    /// This leaf as SwiftTLSKit sees it once loaded: its names, validity and fingerprints.
    ///
    /// - Parameter now: The current time, against which the leaf's validity is judged.
    /// - Returns: The summary SwiftTLSKit reports for this leaf.
    /// - Throws: ``SwiftTLSKit/ServerIdentityError`` if the leaf is not valid at `now`.
    public func summary(now: Date) throws(ServerIdentityError) -> CertificateSummary {
        try loadedIdentity(now: now).leaf
    }

    func loadedIdentity(now: Date) throws(ServerIdentityError) -> LoadedServerIdentity {
        try LoadedServerIdentity.inMemory(certificateChainPEM: chainPEM, privateKeyPEM: privateKeyPEM, now: now)
    }
}
