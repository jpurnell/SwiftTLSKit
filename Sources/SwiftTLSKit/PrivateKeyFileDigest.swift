import Crypto

/// SHA-256 of a private key file's bytes, kept so that a reload can tell whether the file
/// changed, and for nothing else.
///
/// It answers one question — is this the file that was loaded before — by comparison with
/// another of itself. It has no accessor, so nothing outside this file can read the digest; it
/// describes itself as redacted and reflects as empty, so `print`, string interpolation, `dump`
/// and a debugger's summary of anything holding one show nothing of it.
///
/// A digest of a private key is not the key, and SHA-256 of a real key cannot be reversed. It
/// is still derived from the key file, and the rule in this package is that nothing derived
/// from the key file leaves the process or reaches a log; a value that cannot be printed keeps
/// that rule without relying on every future caller to remember it.
struct PrivateKeyFileDigest: Sendable, Equatable {
    private let digest: [UInt8]

    /// Digests the bytes of a key file.
    ///
    /// - Parameter fileContents: Everything read from the file.
    init(ofFileContents fileContents: [UInt8]) {
        digest = Array(SHA256.hash(data: fileContents))
    }
}

extension PrivateKeyFileDigest: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    private static let redacted = "<redacted>"

    var description: String { Self.redacted }

    var debugDescription: String { Self.redacted }

    /// No children: reflection is how `dump` and a debugger reach stored properties.
    var customMirror: Mirror {
        Mirror(self, children: EmptyCollection<Mirror.Child>())
    }
}
