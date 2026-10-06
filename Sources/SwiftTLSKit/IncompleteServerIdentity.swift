/// Half a server identity: a certificate chain without a private key, or the reverse.
///
/// The only way ``ServerIdentity/resolve(certificateChainPath:privateKeyPath:)`` fails, and so
/// the only thing it throws. It says which half was configured and the path given for it,
/// which is everything there is to know, and it is the defect the package exists to remove:
/// the code it replaces built a TLS context only when both halves were present, so one without
/// the other was served without TLS and without a word.
///
/// ```swift
/// import SwiftTLSKit
///
/// let half = IncompleteServerIdentity(present: .privateKey, path: "/certs/privkey.pem")
/// print(half.description(certificateChainSetting: "--tls-cert", privateKeySetting: "--tls-key"))
/// // Prints "--tls-key was given (/certs/privkey.pem) without --tls-cert. A server identity needs both; one without the other is refused."
/// ```
///
/// ## What the message does not say
///
/// It does not say what happens when neither half is given. `resolve` returns `nil` for that,
/// and what a server does with no identity is the server's decision: one may serve plaintext
/// on loopback, another may refuse to start. A message promising plaintext would be false for
/// the second, so the message stops at what is true for both.
public struct IncompleteServerIdentity: Error, Sendable, Hashable {
    /// One of the two files a server identity is made of.
    public enum Half: Sendable, Hashable {
        /// The PEM certificate chain.
        case certificateChain
        /// The PEM private key.
        case privateKey
    }

    /// The half that was configured.
    public let present: Half

    /// The path given for the half that was configured.
    ///
    /// A path, never contents: nothing was read.
    public let path: String

    /// Describes half an identity.
    ///
    /// - Parameters:
    ///   - present: The half that was configured.
    ///   - path: The path given for it.
    public init(present: Half, path: String) {
        self.present = present
        self.path = path
    }

    /// The half that was not configured.
    public var missing: Half {
        switch present {
        case .certificateChain: return .privateKey
        case .privateKey: return .certificateChain
        }
    }

    /// The message, naming the two settings the way the consumer's own interface names them.
    ///
    /// A command-line server's operator typed `--tls-cert`, not "a TLS certificate chain";
    /// this is the sentence that tells them which flag to add.
    ///
    /// - Parameters:
    ///   - certificateChainSetting: What the consumer calls the certificate chain setting, such
    ///     as `"--tls-cert"`.
    ///   - privateKeySetting: What the consumer calls the private key setting, such as
    ///     `"--tls-key"`.
    /// - Returns: A sentence naming the setting that was given, its path, and the setting that
    ///   was not.
    public func description(certificateChainSetting: String, privateKeySetting: String) -> String {
        switch present {
        case .certificateChain:
            return Self.sentence(given: certificateChainSetting, path: path, without: privateKeySetting)
        case .privateKey:
            return Self.sentence(given: privateKeySetting, path: path, without: certificateChainSetting)
        }
    }

    private static func sentence(given: String, path: String, without: String) -> String {
        "\(given) was given (\(path)) without \(without). "
            + "A server identity needs both; one without the other is refused."
    }
}

extension IncompleteServerIdentity: CustomStringConvertible {
    /// A sentence for a start-up failure, naming the half that was given and its path.
    public var description: String {
        switch present {
        case .certificateChain:
            return Self.sentence(given: "A TLS certificate chain", path: path, without: "a private key")
        case .privateKey:
            return Self.sentence(given: "A TLS private key", path: path, without: "a certificate chain")
        }
    }
}
