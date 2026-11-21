import Foundation
import Testing
import SwiftTLSKit
import SwiftTLSKitTestSupport

/// What a client does on a Linux box that has no system CA store.
///
/// These tests only mean something where the platform trust store is absent, which is not the
/// machine a developer runs the suite on. `scripts/linux-test.sh --no-ca-store` hides the store
/// from one process (a private mount namespace; no root) and sets
/// `SWIFTTLSKIT_NO_CA_STORE=1`. Anywhere else the suite is skipped, not passed.
///
/// The expected behaviour is read from swift-nio-ssl's `platformDefaultConfiguration`, which on
/// Linux searches fixed paths and passes whatever it found, possibly nothing, to
/// `SSL_CTX_load_verify_locations`; with neither a file nor a directory that call fails. It is
/// not taken from this package's own output.
@Suite(
    "A client on a box with no system CA store",
    .enabled(if: ProcessInfo.processInfo.environment["SWIFTTLSKIT_NO_CA_STORE"] == "1"),
    .timeLimit(.minutes(1))
)
struct BareBoxTrustTests {
    let authority: TestAuthority

    init() throws {
        authority = try TestAuthority(commonName: "SwiftTLSKit Test Authority", generator: SeededGenerator(seed: TestSeed.authority))
    }

    /// Whether `body` threw the library-rejected error, whatever reason text the library gave.
    private func rejectedByLibrary(_ body: () throws -> Void) -> Bool {
        do {
            try body()
            return false
        } catch ClientTrustError.contextRejected {
            return true
        } catch {
            return false
        }
    }

    @Test("Trusting the system's roots is refused when the box has none, where the configuration is written")
    func systemRootsRefused() {
        #expect(rejectedByLibrary { _ = try ClientTLSContext(trust: .systemRoots) })
    }

    @Test("Adding roots to the system's is refused too, because it keeps the platform default")
    func additionalRootsRefused() throws {
        let root = CertificateSource.pem(authority.certificatePEM)
        #expect(rejectedByLibrary { _ = try ClientTLSContext(trust: .additionalRoots([root])) })
    }

    @Test("Trusting only the supplied roots needs no system store, and works")
    func onlyRootsStillWork() throws {
        let root = CertificateSource.pem(authority.certificatePEM)
        let context = try ClientTLSContext(trust: .onlyRoots([root]))
        #expect(context.rootFingerprints.count == 1)
    }
}
