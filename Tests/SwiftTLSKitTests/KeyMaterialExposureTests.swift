import Crypto
import Foundation
import Testing
import SwiftTLSKit
import SwiftTLSKitTestSupport

/// Change detection keeps a digest of the private key file. These tests are the other half of
/// that decision: the digest, like the key, is reachable by nothing that prints.
@Suite("Nothing derived from the private key can be printed")
struct KeyMaterialExposureTests {
    let authority: TestAuthority
    let fixture: Fixture

    init() throws {
        authority = try TestAuthority(commonName: "SwiftTLSKit Test Authority", generator: SeededGenerator(seed: TestSeed.authority))
        fixture = try Fixture()
    }

    /// Every string and every run of bytes that reflection can reach from `root`, which is
    /// everything `print`, `dump`, string interpolation and a debugger's summary are made from.
    ///
    /// A worklist with a bound rather than recursion: the values include NIOSSL's context,
    /// whose depth is not this package's to promise.
    private static func reachable(from root: Any) -> (strings: [String], byteRuns: [[UInt8]]) {
        let visitLimit = 100_000
        var strings: [String] = []
        var byteRuns: [[UInt8]] = []
        var pending: [Any] = [root]
        var visited = 0
        while let value = pending.popLast(), visited < visitLimit {
            visited += 1
            if let string = value as? String { strings.append(string) }
            if let bytes = value as? [UInt8] { byteRuns.append(bytes) }
            if let data = value as? Data { byteRuns.append(Array(data)) }
            pending.append(contentsOf: Mirror(reflecting: value).children.map(\.value))
        }
        return (strings, byteRuns)
    }

    private static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { byte in
            let text = String(byte, radix: 16)
            return text.count == 1 ? "0" + text : text
        }.joined()
    }

    @Test("Neither the key file nor its SHA-256 is reachable from a loaded identity, a context or a reloader")
    func digestIsUnreachable() throws {
        let leaf = try authority.issueLeaf()
        let identity = try fixture.install(leaf)
        let loaded = try identity.load(now: TestInstant.now)
        let context = try ServerTLSContext(identity: loaded)
        let reloader = try ReloadableServerTLS(identity: identity, now: { TestInstant.now })

        // Computed here, by swift-crypto, from the bytes the fixture wrote.
        let keyFile = Array(leaf.privateKeyPEM.utf8)
        let digest = Array(SHA256.hash(data: keyFile))
        let forms = [Self.hex(digest), Self.hex(digest).uppercased(), Data(digest).base64EncodedString(), leaf.privateKeyPEM]

        let subjects: [(name: String, value: Any)] = [
            ("LoadedServerIdentity", loaded), ("ServerTLSContext", context),
            ("ReloadableServerTLS", reloader), ("ReloadableServerTLS.current", reloader.current),
            ("ReloadOutcome", reloader.reload()), ("ReloadOutcome, unchanged", reloader.reloadIfChanged()),
        ]
        for subject in subjects {
            var dumped = ""
            dump(subject.value, to: &dumped)
            let reached = Self.reachable(from: subject.value)
            let texts = reached.strings + [String(describing: subject.value), String(reflecting: subject.value), dumped]
            for form in forms {
                #expect(texts.contains { $0.contains(form) } == false, "\(subject.name) prints the key or its digest")
            }
            #expect(reached.byteRuns.contains(digest) == false, "\(subject.name) exposes the digest's bytes")
            #expect(reached.byteRuns.contains(keyFile) == false, "\(subject.name) exposes the key file's bytes")
        }
    }
}
