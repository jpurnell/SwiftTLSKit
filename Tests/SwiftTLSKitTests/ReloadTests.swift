import Foundation
import NIOConcurrencyHelpers
import Testing
import SwiftTLSKit
import SwiftTLSKitTestSupport

@Suite("Reloading a server identity without restarting", .timeLimit(.minutes(1)))
struct ReloadTests {
    let authority: TestAuthority
    let fixture: Fixture

    init() throws {
        authority = try TestAuthority(commonName: "SwiftTLSKit Test Authority", generator: SeededGenerator(seed: TestSeed.authority))
        fixture = try Fixture()
    }

    private func trustingAuthority() throws -> ClientTLSContext {
        try ClientTLSContext(trust: .onlyRoots([.pem(authority.certificatePEM)]))
    }

    /// What the library reports for `leaf`, loaded from a directory of its own so that asking
    /// does not disturb the files a test is reloading.
    private func summary(of leaf: TestLeaf, at instant: Date = TestInstant.now) throws -> CertificateSummary {
        let scratch = try Fixture()
        return try scratch.install(leaf).load(now: instant).leaf
    }

    private func served(by server: LoopbackServer) async throws -> String {
        let client = try await LoopbackClient.connect(
            port: server.port, context: try trustingAuthority(), serverHostname: "localhost")
        try await client.close()
        return client.report.peerCertificateSHA256
    }

    // MARK: - A good reload

    @Test("After a reload, a new connection is served the new certificate and a live one is left alone")
    func reloadServesNewConnections() async throws {
        let first = try authority.issueLeaf()
        let second = try authority.issueLeaf()
        let tls = try ReloadableServerTLS(identity: try fixture.install(first), now: { TestInstant.now })
        let server = try await LoopbackServer.start { pipeline in try tls.addHandler(to: pipeline) }

        let live = try await LoopbackClient.connect(
            port: server.port, context: try trustingAuthority(), serverHostname: "localhost")
        #expect(live.report.peerCertificateSHA256 == first.certificateSHA256)
        #expect(try await live.roundTrip("before") == "before")

        _ = try fixture.install(second)
        let outcome = tls.reload()

        #expect(outcome == .reloaded(serving: try summary(of: second), replacing: try summary(of: first)))
        #expect(tls.current.leaf == (try summary(of: second)))
        #expect(try await served(by: server) == second.certificateSHA256)
        // The connection opened before the reload is still up, still on the certificate it
        // negotiated, and still carrying data.
        #expect(try await live.roundTrip("after") == "after")
        #expect(live.channel.isActive == true)
        try await live.close()
        try await server.stop()
    }

    // MARK: - A bad reload

    @Test("A reload that finds a key not matching the certificate keeps serving the old one, and says why")
    func mismatchedReloadKeepsOld() async throws {
        let first = try authority.issueLeaf()
        let second = try authority.issueLeaf()
        let identity = try fixture.install(first)
        let tls = try ReloadableServerTLS(identity: identity, now: { TestInstant.now })
        let server = try await LoopbackServer.start { pipeline in try tls.addHandler(to: pipeline) }
        let before = tls.current.sslContext

        // The state a renewal passes through: the new chain is in place, the key is not yet.
        try fixture.write(second.chainPEM, to: "fullchain.pem", mode: 0o644)
        let outcome = tls.reload()

        #expect(
            outcome == .failed(
                .privateKeyDoesNotMatchCertificate(
                    certificateChainPath: identity.certificateChainPath, privateKeyPath: identity.privateKeyPath),
                stillServing: try summary(of: first)))
        #expect(tls.current.sslContext === before)
        #expect(try await served(by: server) == first.certificateSHA256)

        // ...and once the key arrives, the same reload succeeds.
        try fixture.write(second.privateKeyPEM, to: "privkey.pem", mode: 0o600)
        #expect(tls.reload() == .reloaded(serving: try summary(of: second), replacing: try summary(of: first)))
        #expect(try await served(by: server) == second.certificateSHA256)
        try await server.stop()
    }

    @Test("A reload that finds the key world-readable keeps serving the old identity")
    func openKeyReloadKeepsOld() throws {
        let first = try authority.issueLeaf()
        let identity = try fixture.install(first)
        let tls = try ReloadableServerTLS(identity: identity, now: { TestInstant.now })

        _ = try fixture.install(try authority.issueLeaf(), keyMode: 0o644)

        #expect(
            tls.reload() == .failed(
                .privateKeyPermissionsTooOpen(path: identity.privateKeyPath, mode: 0o644),
                stillServing: try summary(of: first)))
        #expect(tls.current.leaf == (try summary(of: first)))
    }

    @Test("A reload that finds the files gone keeps serving the old identity")
    func missingFilesReloadKeepsOld() throws {
        let first = try authority.issueLeaf()
        let identity = try fixture.install(first)
        let tls = try ReloadableServerTLS(identity: identity, now: { TestInstant.now })

        try FileManager.default.removeItem(atPath: identity.certificateChainPath)

        #expect(
            tls.reload() == .failed(
                .unreadable(path: identity.certificateChainPath, reason: "No such file or directory"),
                stillServing: try summary(of: first)))
        #expect(tls.current.leaf == (try summary(of: first)))
    }

    @Test("Each reload asks what time it is, and refuses a certificate that has expired by then")
    func reloadUsesTheSuppliedClock() throws {
        let shortLived = try authority.issueLeaf(notValidAfter: TestInstant.shortLivedEnd)
        let identity = try fixture.install(shortLived)
        let clock = NIOLockedValueBox(TestInstant.duringShortLived)
        let tls = try ReloadableServerTLS(identity: identity, now: { clock.withLockedValue { $0 } })

        let serving = try summary(of: shortLived, at: TestInstant.duringShortLived)

        #expect(tls.reload() == .reloaded(serving: serving, replacing: serving))

        clock.withLockedValue { $0 = TestInstant.now }
        #expect(
            tls.reload() == .failed(
                .expired(path: identity.certificateChainPath, notValidAfter: TestInstant.shortLivedEnd),
                stillServing: serving))
    }

    @Test("An identity that cannot be loaded at start is an error, not a server without TLS")
    func initialLoadFailureThrows() throws {
        let identity = ServerIdentity(
            certificateChainPath: fixture.path("absent.pem"), privateKeyPath: fixture.path("absent.key"))

        #expect(throws: ServerIdentityError.unreadable(path: fixture.path("absent.pem"), reason: "No such file or directory")) {
            try ReloadableServerTLS(identity: identity, now: { TestInstant.now })
        }
    }

    // MARK: - Reloading only when something changed

    @Test("reloadIfChanged leaves the context alone when the files are the same, and swaps it when they are not")
    func reloadIfChanged() throws {
        let first = try authority.issueLeaf()
        let second = try authority.issueLeaf()
        let tls = try ReloadableServerTLS(identity: try fixture.install(first), now: { TestInstant.now })
        let original = tls.current.sslContext

        #expect(tls.reloadIfChanged() == .unchanged(serving: try summary(of: first)))
        #expect(tls.current.sslContext === original)

        _ = try fixture.install(second)
        #expect(tls.reloadIfChanged() == .reloaded(serving: try summary(of: second), replacing: try summary(of: first)))
        #expect(tls.current.sslContext !== original)
        #expect(tls.current.leaf == (try summary(of: second)))
    }

    /// The chain is byte for byte the one being served; only the key file differs. `load`
    /// refuses a key that is not the leaf's, so a key file that changes under an unchanged
    /// chain and still loads holds the same key written differently — here, with one more
    /// line ending. "Unchanged" has to mean the files are the ones being served, so this is a
    /// change, and the context is rebuilt from the file as it now is.
    @Test("reloadIfChanged sees a key file that changed under a chain that did not")
    func reloadIfChangedSeesAKeyOnlyChange() throws {
        let first = try authority.issueLeaf()
        let tls = try ReloadableServerTLS(identity: try fixture.install(first), now: { TestInstant.now })
        let original = tls.current.sslContext
        #expect(tls.reloadIfChanged() == .unchanged(serving: try summary(of: first)))

        try fixture.write(first.privateKeyPEM + "\n", to: "privkey.pem", mode: 0o600)

        #expect(tls.reloadIfChanged() == .reloaded(serving: try summary(of: first), replacing: try summary(of: first)))
        #expect(tls.current.sslContext !== original)
        // And having taken it, the same files are unchanged again.
        let afterKeyChange = tls.current.sslContext
        #expect(tls.reloadIfChanged() == .unchanged(serving: try summary(of: first)))
        #expect(tls.current.sslContext === afterKeyChange)
    }

    @Test("reload always rebuilds, even from the same files")
    func reloadAlwaysRebuilds() throws {
        let first = try authority.issueLeaf()
        let tls = try ReloadableServerTLS(identity: try fixture.install(first), now: { TestInstant.now })
        let original = tls.current.sslContext

        #expect(tls.reload() == .reloaded(serving: try summary(of: first), replacing: try summary(of: first)))
        #expect(tls.current.sslContext !== original)
    }

    @Test("reloadIfChanged reports files that have gone bad even though nothing is swapped")
    func reloadIfChangedReportsFailure() throws {
        let first = try authority.issueLeaf()
        let identity = try fixture.install(first)
        let tls = try ReloadableServerTLS(identity: identity, now: { TestInstant.now })

        try FileManager.default.setAttributes([.posixPermissions: 0o640], ofItemAtPath: identity.privateKeyPath)

        #expect(
            tls.reloadIfChanged() == .failed(
                .privateKeyPermissionsTooOpen(path: identity.privateKeyPath, mode: 0o640),
                stillServing: try summary(of: first)))
    }

    // MARK: - Triggers

    @Test("Each trigger checks once, in order, and the loop ends when the triggers do")
    func reloadOnEachTrigger() async throws {
        let first = try authority.issueLeaf()
        let second = try authority.issueLeaf()
        let tls = try ReloadableServerTLS(identity: try fixture.install(first), now: { TestInstant.now })
        _ = try fixture.install(second)

        let (triggers, continuation) = AsyncStream.makeStream(of: Void.self)
        continuation.yield()
        continuation.yield()
        continuation.finish()
        let outcomes = NIOLockedValueBox<[ReloadOutcome]>([])
        await tls.reloadOnEach(triggers) { outcome in
            outcomes.withLockedValue { $0.append(outcome) }
        }

        #expect(
            outcomes.withLockedValue { $0 } == [
                .reloaded(serving: try summary(of: second), replacing: try summary(of: first)),
                .unchanged(serving: try summary(of: second)),
            ])
    }

    /// The outcomes of `count` triggers under `mode`, starting from `first` being served with
    /// `second` already on disk.
    private func outcomes(
        of mode: ReloadMode, triggers count: Int, serving first: TestLeaf, onDisk second: TestLeaf
    ) async throws -> [ReloadOutcome] {
        let tls = try ReloadableServerTLS(identity: try fixture.install(first), now: { TestInstant.now })
        _ = try fixture.install(second)
        let (triggers, continuation) = AsyncStream.makeStream(of: Void.self)
        for _ in 0..<count { continuation.yield() }
        continuation.finish()
        let outcomes = NIOLockedValueBox<[ReloadOutcome]>([])
        await tls.reloadOnEach(triggers, mode: mode) { outcome in
            outcomes.withLockedValue { $0.append(outcome) }
        }
        return outcomes.withLockedValue { $0 }
    }

    @Test("In .always mode every trigger is a full reload, whether or not anything changed")
    func reloadOnEachAlways() async throws {
        let first = try authority.issueLeaf()
        let second = try authority.issueLeaf()

        #expect(
            try await outcomes(of: .always, triggers: 3, serving: first, onDisk: second) == [
                .reloaded(serving: try summary(of: second), replacing: try summary(of: first)),
                .reloaded(serving: try summary(of: second), replacing: try summary(of: second)),
                .reloaded(serving: try summary(of: second), replacing: try summary(of: second)),
            ])
    }

    @Test("In .ifChanged mode a trigger that finds the same files changes nothing")
    func reloadOnEachIfChanged() async throws {
        let first = try authority.issueLeaf()
        let second = try authority.issueLeaf()

        #expect(
            try await outcomes(of: .ifChanged, triggers: 3, serving: first, onDisk: second) == [
                .reloaded(serving: try summary(of: second), replacing: try summary(of: first)),
                .unchanged(serving: try summary(of: second)),
                .unchanged(serving: try summary(of: second)),
            ])
    }

    @Test("reload(_:) is the two triggers under one name")
    func reloadByMode() throws {
        let first = try authority.issueLeaf()
        let tls = try ReloadableServerTLS(identity: try fixture.install(first), now: { TestInstant.now })
        let original = tls.current.sslContext

        #expect(tls.reload(.ifChanged) == .unchanged(serving: try summary(of: first)))
        #expect(tls.current.sslContext === original)
        #expect(tls.reload(.always) == .reloaded(serving: try summary(of: first), replacing: try summary(of: first)))
        #expect(tls.current.sslContext !== original)
    }

    // MARK: - Log levels

    /// The levels a server that had to choose for itself chose (IconquerServer's
    /// `CertificateReload.level(for:)`), which is where the suggestion comes from.
    @Test("A reload is a notice, no change is info, and a failure is a warning — not an error")
    func suggestedLogLevels() throws {
        let first = try summary(of: try authority.issueLeaf())
        let second = try summary(of: try authority.issueLeaf())

        #expect(ReloadOutcome.reloaded(serving: second, replacing: first).suggestedLogLevel == .notice)
        #expect(ReloadOutcome.unchanged(serving: first).suggestedLogLevel == .info)
        #expect(
            ReloadOutcome.failed(.emptyCertificateChain(path: "/c/fullchain.pem"), stillServing: first)
                .suggestedLogLevel == .warning)
    }

    /// swift-log's `Logger.Level` is a `String` enum whose raw values are these words, so a
    /// consumer converts with `Logger.Level(rawValue:)` and this package needs no dependency.
    @Test("The level's raw values are swift-log's level names, in order of severity")
    func logLevelRawValues() {
        #expect(SuggestedLogLevel.allCases.map(\.rawValue) == ["info", "notice", "warning"])
        #expect(SuggestedLogLevel.info < .notice)
        #expect(SuggestedLogLevel.notice < .warning)
        #expect(SuggestedLogLevel.allCases.sorted() == [.info, .notice, .warning])
    }

    // MARK: - Messages

    @Test("An outcome reads as a log line")
    func descriptions() throws {
        let first = try summary(of: try authority.issueLeaf())
        let second = try summary(of: try authority.issueLeaf())

        #expect(
            ReloadOutcome.reloaded(serving: second, replacing: first).description
                == "TLS identity reloaded. Now serving \(second). Was serving \(first).")
        #expect(
            ReloadOutcome.unchanged(serving: first).description
                == "TLS identity unchanged. Still serving \(first).")
        #expect(
            ReloadOutcome.failed(.emptyCertificateChain(path: "/c/fullchain.pem"), stillServing: first).description
                == "TLS identity reload failed: /c/fullchain.pem holds no certificates. Still serving \(first).")
    }
}
