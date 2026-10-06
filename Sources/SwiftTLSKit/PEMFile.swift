import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// Reads the two files an identity is made of, refusing the ones that should not be read.
enum PEMFile {
    /// The largest file accepted. A full chain with several intermediates is a few kilobytes;
    /// a megabyte is far beyond any real one and small enough to read without thought.
    static let maximumBytes = 1_048_576

    /// Permission bits that give group or others any access at all.
    private static let groupAndOtherBits: mode_t = 0o077
    /// The permission bits of a mode, without the file-type bits.
    private static let permissionBits: mode_t = 0o7777

    /// The bytes of the file at `path`.
    ///
    /// The checks are made on the descriptor that is then read, not on the path, so the file
    /// examined is the file used: nothing can be swapped in between the two.
    ///
    /// - Parameters:
    ///   - path: The file.
    ///   - mustBeOwnerOnly: Whether to refuse a file its group or others can reach.
    /// - Returns: The file's bytes.
    /// - Throws: ``ServerIdentityError`` naming `path` and the reason.
    static func read(path: String, mustBeOwnerOnly: Bool) throws(ServerIdentityError) -> [UInt8] {
        // O_NONBLOCK so that opening a FIFO returns instead of waiting for a writer; it has no
        // effect on reading a regular file, which is the only kind accepted below.
        let descriptor = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw .unreadable(path: path, reason: describe(errno))
        }
        defer { close(descriptor) }

        var status = stat()
        guard fstat(descriptor, &status) == 0 else {
            throw .unreadable(path: path, reason: describe(errno))
        }
        guard (status.st_mode & S_IFMT) == S_IFREG else {
            throw .notRegularFile(path: path)
        }
        if mustBeOwnerOnly {
            guard status.st_mode & groupAndOtherBits == 0 else {
                throw .privateKeyPermissionsTooOpen(
                    path: path, mode: UInt16(truncatingIfNeeded: status.st_mode & permissionBits))
            }
        }
        guard status.st_size <= maximumBytes else {
            throw .fileTooLarge(path: path, limit: maximumBytes)
        }

        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        let contents: Data
        do {
            // One more than the limit, so a file that grew after `fstat` is still refused.
            contents = try handle.read(upToCount: maximumBytes + 1) ?? Data()
        } catch {
            throw .unreadable(path: path, reason: error.localizedDescription)
        }
        guard contents.count <= maximumBytes else {
            throw .fileTooLarge(path: path, limit: maximumBytes)
        }
        return Array(contents)
    }

    private static func describe(_ code: Int32) -> String {
        guard let message = strerror(code) else { return "error \(code)" }
        return String(cString: message)
    }
}
