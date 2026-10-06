import Foundation
import SwiftTLSKit

/// A directory of PEM files that exists for one test and is removed when the test lets go.
final class Fixture {
    let directory: URL

    init() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("SwiftTLSKitTests-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    }

    deinit {
        try? FileManager.default.removeItem(at: directory)
    }

    func path(_ name: String) -> String {
        directory.appendingPathComponent(name).path
    }

    /// Writes `contents` to `name` with exactly `mode`, replacing what was there the way
    /// `install(1)` does: a new file renamed over the old one.
    @discardableResult
    func write(_ contents: String, to name: String, mode: Int) throws -> String {
        let destination = path(name)
        let staging = path(name + ".staging")
        try Data(contents.utf8).write(to: URL(fileURLWithPath: staging))
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: staging)
        _ = try FileManager.default.replaceItemAt(
            URL(fileURLWithPath: destination), withItemAt: URL(fileURLWithPath: staging))
        return destination
    }

    /// Writes a leaf's chain (0644) and key (0600) under the names certbot uses.
    func install(_ leaf: TestLeaf, keyMode: Int = 0o600) throws -> ServerIdentity {
        ServerIdentity(
            certificateChainPath: try write(try leaf.chainPEM, to: "fullchain.pem", mode: 0o644),
            privateKeyPath: try write(leaf.keyPEM, to: "privkey.pem", mode: keyMode))
    }
}
