import Foundation
import NIOConcurrencyHelpers
import SwiftTLSKit

/// A server identity held in memory that a test can renew, for exercising a reload without
/// touching the filesystem.
///
/// It stands where the two PEM files stand for a real server. ``replace(with:)`` is the
/// renewal — both halves at once, so there is no window with a new chain and an old key — and
/// the ``SwiftTLSKit/ReloadableServerTLS`` made by ``reloadableServerTLS(options:now:)`` reads
/// whatever is current each time it reloads.
///
/// ```swift
/// import SwiftTLSKit
/// import SwiftTLSKitTestSupport
///
/// let authority = try TestAuthority(commonName: "Test Authority", generator: SeededGenerator(seed: 1))
/// let identity = InMemoryServerIdentity(try authority.issueLeaf())
/// let tls = try identity.reloadableServerTLS(now: { TestInstant.now })
///
/// identity.replace(with: try authority.issueLeaf())
/// print(tls.reloadIfChanged().suggestedLogLevel)
/// // Prints "notice"
/// ```
///
/// What it cannot exercise is anything about files: permissions, a missing file, or a reload
/// that lands between the two writes of a renewal. Those need real files, and
/// ``TestLeaf/chainPEM`` and ``TestLeaf/privateKeyPEM`` are there to write them.
public final class InMemoryServerIdentity: Sendable {
    private let current: NIOLockedValueBox<TestLeaf>

    /// Holds `leaf` as the identity to serve.
    ///
    /// - Parameter leaf: The certificate and key to start with.
    public init(_ leaf: TestLeaf) {
        current = NIOLockedValueBox(leaf)
    }

    /// The leaf a load would find now.
    public var leaf: TestLeaf {
        current.withLockedValue { $0 }
    }

    /// Replaces the certificate and key, as a renewal does. Nothing is served differently
    /// until a reloader is asked to reload.
    ///
    /// - Parameter leaf: The renewed certificate and key.
    public func replace(with leaf: TestLeaf) {
        current.withLockedValue { $0 = leaf }
    }

    /// A reloadable server TLS that loads from this identity instead of from disk.
    ///
    /// Its ``SwiftTLSKit/ReloadableServerTLS/identity`` names `<in-memory certificate chain>`
    /// and `<in-memory private key>`, and so do its errors.
    ///
    /// - Parameters:
    ///   - options: The minimum TLS version and ALPN protocols.
    ///   - now: Called at each load to ask what time it is.
    /// - Returns: The reloader, having loaded the current leaf.
    /// - Throws: ``SwiftTLSKit/ServerIdentityError`` if the current leaf is not valid at the
    ///   time `now` gives.
    public func reloadableServerTLS(
        options: ServerTLSOptions = ServerTLSOptions(),
        now: @escaping @Sendable () -> Date
    ) throws(ServerIdentityError) -> ReloadableServerTLS {
        try ReloadableServerTLS(identity: .inMemory, options: options, now: now) { [current] instant throws(ServerIdentityError) in
            try current.withLockedValue { $0 }.loadedIdentity(now: instant)
        }
    }
}
