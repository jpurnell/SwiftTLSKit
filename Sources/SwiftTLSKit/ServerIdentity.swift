import Foundation
import NIOSSL

/// The two files a server presents as itself: a certificate chain and the private key for it.
///
/// A value naming paths, nothing more. Making one reads nothing; ``load(now:)`` is where the
/// files are opened and judged.
///
/// ## From two optional settings
///
/// A server's TLS settings usually arrive as two optional strings — `--tls-cert` and
/// `--tls-key`. ``resolve(certificateChainPath:privateKeyPath:)`` turns the pair into one of
/// three answers, and the one that matters is the third:
///
/// ```swift
/// import SwiftTLSKit
///
/// do {
///     _ = try ServerIdentity.resolve(certificateChainPath: "/certs/fullchain.pem", privateKeyPath: nil)
/// } catch {
///     print(error)
/// }
/// // Prints "A TLS certificate chain was given (/certs/fullchain.pem) without a private key. Supply both to serve TLS, or neither to serve plaintext; one without the other is refused."
/// ```
public struct ServerIdentity: Sendable, Hashable {
    /// The path of the PEM certificate chain: the leaf first, then its intermediates.
    public let certificateChainPath: String

    /// The path of the PEM private key belonging to the leaf.
    public let privateKeyPath: String

    /// Names the two files. Reads neither.
    ///
    /// - Parameters:
    ///   - certificateChainPath: The PEM certificate chain, leaf first.
    ///   - privateKeyPath: The unencrypted PEM private key for the leaf.
    public init(certificateChainPath: String, privateKeyPath: String) {
        self.certificateChainPath = certificateChainPath
        self.privateKeyPath = privateKeyPath
    }

    /// Turns two optional paths into an identity, no identity, or an error.
    ///
    /// - Parameters:
    ///   - certificateChainPath: The certificate chain path, if one was configured.
    ///   - privateKeyPath: The private key path, if one was configured.
    /// - Returns: `nil` when neither was configured — the server is to run without TLS — and
    ///   the identity when both were.
    /// - Throws: ``ServerIdentityError/incompletePair(present:path:)`` when exactly one was
    ///   configured. Half a pair is never treated as "no TLS".
    public static func resolve(
        certificateChainPath: String?,
        privateKeyPath: String?
    ) throws(ServerIdentityError) -> ServerIdentity? {
        switch (certificateChainPath, privateKeyPath) {
        case (nil, nil):
            return nil
        case (let chain?, let key?):
            return ServerIdentity(certificateChainPath: chain, privateKeyPath: key)
        case (let chain?, nil):
            throw .incompletePair(present: .certificateChain, path: chain)
        case (nil, let key?):
            throw .incompletePair(present: .privateKey, path: key)
        }
    }

    /// Reads both files and refuses an identity that should not be served.
    ///
    /// Everything is checked before anything is returned, so a ``LoadedServerIdentity`` is one
    /// a TLS context can be built from: both files are regular files, the key is reachable only
    /// by its owner, the chain holds at least one certificate, the key is the leaf's, and the
    /// leaf is valid at `now`.
    ///
    /// - Parameter now: The current time. The library never reads the clock; the caller says
    ///   what time it is, which is also what lets a test ask about any instant it likes.
    /// - Returns: The parsed chain and key, with a summary of the leaf.
    /// - Throws: ``ServerIdentityError`` naming the file and the reason.
    public func load(now: Date) throws(ServerIdentityError) -> LoadedServerIdentity {
        let chainBytes = try PEMFile.read(path: certificateChainPath, mustBeOwnerOnly: false)
        let keyBytes = try PEMFile.read(path: privateKeyPath, mustBeOwnerOnly: true)

        let chain = try parseChain(chainBytes)
        guard let leafCertificate = chain.first else {
            throw .emptyCertificateChain(path: certificateChainPath)
        }
        let key = try parseKey(keyBytes)
        let leaf = try summarise(leafCertificate)
        try requireMatch(chain: chain, key: key)

        guard now >= leaf.notValidBefore else {
            throw .notYetValid(path: certificateChainPath, notValidBefore: leaf.notValidBefore)
        }
        guard now <= leaf.notValidAfter else {
            throw .expired(path: certificateChainPath, notValidAfter: leaf.notValidAfter)
        }
        return LoadedServerIdentity(identity: self, certificateChain: chain, privateKey: key, leaf: leaf)
    }

    private static let certificateMarker = Array("-----BEGIN CERTIFICATE-----".utf8)

    private func parseChain(_ bytes: [UInt8]) throws(ServerIdentityError) -> [NIOSSLCertificate] {
        // Asked first, because NIOSSL reports "no certificate here" and "a damaged certificate"
        // as the same error, and they call for different fixes.
        guard bytes.firstRange(of: Self.certificateMarker) != nil else {
            throw .emptyCertificateChain(path: certificateChainPath)
        }
        do {
            return try NIOSSLCertificate.fromPEMBytes(bytes)
        } catch {
            throw .invalidCertificateChain(path: certificateChainPath)
        }
    }

    private func parseKey(_ bytes: [UInt8]) throws(ServerIdentityError) -> NIOSSLPrivateKey {
        do {
            return try NIOSSLPrivateKey(bytes: bytes, format: .pem)
        } catch {
            // The underlying error is discarded on purpose: nothing derived from the key file
            // goes into a message.
            throw .invalidPrivateKey(path: privateKeyPath)
        }
    }

    private func summarise(_ leaf: NIOSSLCertificate) throws(ServerIdentityError) -> CertificateSummary {
        do {
            return try CertificateSummary(leaf)
        } catch {
            throw .invalidCertificateChain(path: certificateChainPath)
        }
    }

    /// Builds a throwaway TLS context, which is the library's own test of whether this key
    /// signs for this leaf.
    private func requireMatch(chain: [NIOSSLCertificate], key: NIOSSLPrivateKey) throws(ServerIdentityError) {
        let configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: chain.map { .certificate($0) },
            privateKey: .privateKey(key))
        do {
            _ = try NIOSSLContext(configuration: configuration)
        } catch NIOSSLError.failedToLoadPrivateKey {
            // Both files parsed above, so the key failing to load *into a context that already
            // holds the leaf* is the mismatch: BoringSSL compares the two public keys there.
            throw .privateKeyDoesNotMatchCertificate(
                certificateChainPath: certificateChainPath, privateKeyPath: privateKeyPath)
        } catch {
            throw .contextRejected(reason: String(describing: error))
        }
    }
}

/// A server identity that has been read from disk and found fit to serve.
///
/// Made only by ``ServerIdentity/load(now:)``. Holding one means every check passed at the
/// moment it was loaded; it says nothing about the files since.
public struct LoadedServerIdentity: Sendable {
    /// The paths this was loaded from.
    public let identity: ServerIdentity

    /// The parsed certificate chain, leaf first.
    public let certificateChain: [NIOSSLCertificate]

    /// The parsed private key. Not public: nothing outside the package needs the key itself,
    /// and a value that cannot be reached cannot be logged.
    let privateKey: NIOSSLPrivateKey

    /// What the leaf certificate says: its names, its validity, its fingerprints.
    public let leaf: CertificateSummary
}
