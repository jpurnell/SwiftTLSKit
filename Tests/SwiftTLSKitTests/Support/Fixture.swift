import Foundation
import SwiftTLSKit
import SwiftTLSKitTestSupport

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

    /// Writes `contents` to `name` with exactly `mode`, replacing what was there in one step:
    /// a new file with the new mode, renamed over the old one. A reader sees the old file or
    /// the new one, never half of either, and the old file's mode does not survive.
    @discardableResult
    func write(_ contents: String, to name: String, mode: Int) throws -> String {
        let destination = path(name)
        let staging = path(name + ".staging")
        try Data(contents.utf8).write(to: URL(fileURLWithPath: staging))
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: staging)
        guard rename(staging, destination) == 0 else {
            throw CocoaError(.fileWriteUnknown)
        }
        return destination
    }

    /// Writes a leaf's chain (0644) and key (0600) under the names certbot uses.
    func install(_ leaf: TestLeaf, keyMode: Int = 0o600) throws -> ServerIdentity {
        ServerIdentity(
            certificateChainPath: try write(leaf.chainPEM, to: "fullchain.pem", mode: 0o644),
            privateKeyPath: try write(leaf.privateKeyPEM, to: "privkey.pem", mode: keyMode))
    }
}
