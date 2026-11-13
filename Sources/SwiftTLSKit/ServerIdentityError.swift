import Foundation

/// Why a server identity was refused when it was loaded.
///
/// Thrown by ``ServerIdentity/load(now:)`` and everything built on it. Half a pair of settings
/// is not here: that is ``IncompleteServerIdentity``, which is all
/// ``ServerIdentity/resolve(certificateChainPath:privateKeyPath:)`` can throw.
///
/// Every case names the path concerned and the reason. None carries anything read from a file:
/// a refusal is written to logs and shown to operators, and a private key must not follow it
/// there.
public enum ServerIdentityError: Error, Sendable, Hashable {
    /// The file could not be opened or read.
    ///
    /// - Parameters:
    ///   - path: The file.
    ///   - reason: The operating system's description of the failure.
    case unreadable(path: String, reason: String)

    /// The path names something other than a regular file — a directory, a FIFO, a device.
    ///
    /// - Parameter path: The path.
    case notRegularFile(path: String)

    /// The file is larger than any certificate chain or private key.
    ///
    /// - Parameters:
    ///   - path: The file.
    ///   - limit: The largest size accepted, in bytes.
    case fileTooLarge(path: String, limit: Int)

    /// The private key can be read or written by its group or by others.
    ///
    /// - Parameters:
    ///   - path: The key file.
    ///   - mode: Its permission bits.
    case privateKeyPermissionsTooOpen(path: String, mode: UInt16)

    /// The private key belongs to a user who is neither the one running this process nor root.
    ///
    /// Its mode can be `0600` and it is still not private: its owner can read it, and replace it
    /// with a key and certificate of their own that the next reload then serves.
    ///
    /// - Parameters:
    ///   - path: The key file.
    ///   - ownerID: The numeric ID of the user who owns it.
    case privateKeyOwnedByAnotherUser(path: String, ownerID: UInt32)

    /// A directory above the private key can be written by its group or by others, so someone
    /// else could replace the key by renaming it or the directory.
    ///
    /// A directory with the sticky bit set, such as `/tmp`, does not count: there only a file's
    /// owner can rename or remove it.
    ///
    /// - Parameters:
    ///   - path: The key file.
    ///   - directory: The directory that can be written, which may be the key's own or any one
    ///     above it. A symbolic link in `path` is followed, so this is where the key really is.
    ///   - mode: The directory's permission bits.
    case privateKeyDirectoryWritable(path: String, directory: String, mode: UInt16)

    /// The private key has an access control list, which can grant access its mode does not
    /// show.
    ///
    /// Only macOS keeps access control lists apart from the mode bits, so only there is this
    /// raised. On Linux a POSIX ACL's mask is the group bits, which
    /// ``privateKeyPermissionsTooOpen(path:mode:)`` already refuses.
    ///
    /// - Parameter path: The key file.
    case privateKeyHasAccessControlList(path: String)

    /// The certificate chain file holds no certificate.
    ///
    /// - Parameter path: The chain file.
    case emptyCertificateChain(path: String)

    /// The certificate chain file holds a certificate that cannot be parsed.
    ///
    /// - Parameter path: The chain file.
    case invalidCertificateChain(path: String)

    /// The private key file does not hold an unencrypted PEM private key.
    ///
    /// - Parameter path: The key file.
    case invalidPrivateKey(path: String)

    /// The private key is not the one the leaf certificate was issued for.
    ///
    /// - Parameters:
    ///   - certificateChainPath: The chain file.
    ///   - privateKeyPath: The key file.
    case privateKeyDoesNotMatchCertificate(certificateChainPath: String, privateKeyPath: String)

    /// The leaf certificate's validity ended before the time supplied.
    ///
    /// - Parameters:
    ///   - path: The chain file.
    ///   - notValidAfter: The last instant at which the leaf was valid.
    case expired(path: String, notValidAfter: Date)

    /// The leaf certificate's validity begins after the time supplied.
    ///
    /// - Parameters:
    ///   - path: The chain file.
    ///   - notValidBefore: The first instant at which the leaf is valid.
    case notYetValid(path: String, notValidBefore: Date)

    /// The TLS library refused the identity for a reason not covered above.
    ///
    /// - Parameter reason: The library's description. It describes the failure, not the files.
    case contextRejected(reason: String)
}

extension ServerIdentityError: CustomStringConvertible {
    /// A sentence for a log line or a start-up failure, naming the path and what to do.
    public var description: String {
        switch self {
        case .unreadable(let path, let reason):
            return "Cannot read \(Self.printable(path)): \(reason)."
        case .notRegularFile(let path):
            return "\(Self.printable(path)) is not a regular file."
        case .fileTooLarge(let path, let limit):
            return "\(Self.printable(path)) is larger than \(limit) bytes, which no certificate chain or private key is."
        case .privateKeyPermissionsTooOpen(let path, let mode):
            return "The private key at \(Self.printable(path)) has mode \(Self.octal(mode)), "
                + "which lets group or others read or write it. Run: chmod 600 \(Self.shellQuoted(path))"
        case .privateKeyOwnedByAnotherUser(let path, let ownerID):
            return "The private key at \(Self.printable(path)) is owned by user \(ownerID), who is neither the user "
                + "running this process nor root, and so can read it and replace it."
        case .privateKeyDirectoryWritable(let path, let directory, let mode):
            return "The directory \(Self.printable(directory)), which holds or is above the private key at "
                + "\(Self.printable(path)), has mode \(Self.octal(mode)), which lets group or others add, rename or "
                + "remove files in it, and so replace the key. Run: chmod go-w \(Self.shellQuoted(directory))"
        case .privateKeyHasAccessControlList(let path):
            return "The private key at \(Self.printable(path)) has an access control list, which can grant access "
                + "its mode does not show. Run: chmod -N \(Self.shellQuoted(path))"
        case .emptyCertificateChain(let path):
            return "\(Self.printable(path)) holds no certificates."
        case .invalidCertificateChain(let path):
            return "\(Self.printable(path)) holds a certificate that cannot be read as PEM."
        case .invalidPrivateKey(let path):
            return "\(Self.printable(path)) does not hold a private key that can be read as unencrypted PEM."
        case .privateKeyDoesNotMatchCertificate(let certificateChainPath, let privateKeyPath):
            return "The private key at \(Self.printable(privateKeyPath)) does not match the leaf certificate in \(Self.printable(certificateChainPath))."
        case .expired(let path, let notValidAfter):
            return "The leaf certificate in \(Self.printable(path)) expired at \(notValidAfter.formatted(.iso8601))."
        case .notYetValid(let path, let notValidBefore):
            return "The leaf certificate in \(Self.printable(path)) is not valid until \(notValidBefore.formatted(.iso8601))."
        case .contextRejected(let reason):
            return "The TLS library refused this identity: \(reason)."
        }
    }

    /// `text` with every control character written out, so that a path cannot break or forge a
    /// line in the log a description goes to.
    private static func printable(_ text: String) -> String {
        var written = ""
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\n": written += "\\n"
            case "\r": written += "\\r"
            case "\t": written += "\\t"
            default:
                if isControl(scalar) {
                    written += "\\u{" + String(scalar.value, radix: 16, uppercase: true) + "}"
                } else {
                    written.unicodeScalars.append(scalar)
                }
            }
        }
        return written
    }

    /// A character that can end or rewrite a line: the C0 and C1 controls, DEL, and the Unicode
    /// line and paragraph separators.
    private static func isControl(_ scalar: Unicode.Scalar) -> Bool {
        scalar.value < 0x20 || (0x7f...0x9f).contains(scalar.value) || scalar.value == 0x2028 || scalar.value == 0x2029
    }

    /// `path` as one shell word, for a command an operator pastes.
    ///
    /// Left as it is when every character is one a shell reads literally, so an ordinary path
    /// reads as an ordinary path. Otherwise in single quotes, which are the only quoting that
    /// does not interpret anything; a single quote inside is written `'\''`. Without this a path
    /// such as `/etc/ssl/a; rm -rf ~` is a command in the hint. A path that begins with `-` is an
    /// option to `chmod` however it is quoted, so it follows `--`.
    private static func shellQuoted(_ path: String) -> String {
        // A control character cannot be written in a line, so it is written the way bash and zsh
        // read it back: `$'…'`, with the control characters as escapes.
        if path.unicodeScalars.contains(where: isControl) {
            let escaped = path.unicodeScalars.map { scalar -> String in
                switch scalar {
                case "\\": return "\\\\"
                case "'": return "\\'"
                case "\n": return "\\n"
                case "\r": return "\\r"
                case "\t": return "\\t"
                default:
                    guard isControl(scalar) else { return String(scalar) }
                    let hex = String(scalar.value, radix: 16, uppercase: true)
                    return scalar.value <= 0xff ? "\\x" + (hex.count < 2 ? "0" : "") + hex : "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
                }
            }.joined()
            return (path.hasPrefix("-") ? "-- " : "") + "$'" + escaped + "'"
        }
        let literal = path.unicodeScalars.allSatisfy { scalar in
            scalar.isASCII && (scalar.properties.isAlphabetic || ("0"..."9").contains(Character(scalar))
                || "_@%+=:,./-".unicodeScalars.contains(scalar))
        }
        let word = literal && !path.isEmpty ? path : "'" + path.replacing("'", with: "'\\''") + "'"
        return path.hasPrefix("-") ? "-- " + word : word
    }

    /// Permission bits as `chmod` writes them: four octal digits.
    private static func octal(_ mode: UInt16) -> String {
        let digits = String(mode, radix: 8)
        return String(repeating: "0", count: max(0, 4 - digits.count)) + digits
    }
}
