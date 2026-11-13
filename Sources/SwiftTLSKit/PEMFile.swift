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

    /// Whether a file owned by `owner` is one the process running as `effectiveUserID` can keep
    /// to itself.
    ///
    /// The process's own user, or root. Anyone else who owns the file can read it and can replace
    /// it, whatever its mode says; and a process running as root does not take a key an
    /// unprivileged user owns, because that user could put their own there.
    static func ownerIsTrusted(owner: uid_t, effectiveUserID: uid_t) -> Bool {
        owner == effectiveUserID || owner == rootUserID
    }

    private static let rootUserID: uid_t = 0
    /// Write permission for group and others.
    private static let groupAndOtherWriteBits: mode_t = 0o022
    /// The sticky bit: in a directory that has it, only a file's owner can rename or remove it.
    private static let stickyBit: mode_t = 0o1000

    /// Refuses a key that somebody other than its owner could replace, by writing to a directory
    /// it is in or that is above it.
    ///
    /// `path` is resolved first, so a symbolic link is judged by where the key is. Every
    /// directory from the key's own up to `/` must be free of group and other write permission,
    /// unless it has the sticky bit, as `/tmp` does.
    ///
    /// The directories are examined by path, after the key was opened, so this is a statement
    /// about the layout at that moment and not a lock: somebody who could change a directory's
    /// mode in between could already replace the key.
    private static func requireUnwritableAncestors(of path: String) throws(ServerIdentityError) {
        guard let resolvedPointer = realpath(path, nil) else {
            throw .unreadable(path: path, reason: describe(errno))
        }
        let resolved = String(cString: resolvedPointer)
        free(resolvedPointer)

        var directory = parentDirectory(of: resolved)
        for _ in 0..<maximumDirectoryDepth {
            var status = stat()
            guard stat(directory, &status) == 0 else {
                throw .unreadable(path: directory, reason: describe(errno))
            }
            if status.st_mode & groupAndOtherWriteBits != 0, status.st_mode & stickyBit == 0 {
                throw .privateKeyDirectoryWritable(
                    path: path, directory: directory, mode: UInt16(truncatingIfNeeded: status.st_mode & permissionBits))
            }
            let parent = parentDirectory(of: directory)
            guard parent != directory else { return }
            directory = parent
        }
        // Reached only by a path with more components than any filesystem allows: refused, not
        // waved through, since the directories above the last one examined were not.
        throw .unreadable(path: path, reason: "the path has more than \(maximumDirectoryDepth) directories")
    }

    /// More components than `PATH_MAX` (4096 on Linux) can hold: the most directories a real
    /// path can have, so the walk to `/` ends in this many steps whatever it meets.
    private static let maximumDirectoryDepth = 4096

    /// `path` without its last component: `/` for anything directly under it, and `/` for `/`.
    private static func parentDirectory(of path: String) -> String {
        guard let slash = path.lastIndex(of: "/"), slash != path.startIndex else { return "/" }
        return String(path[..<slash])
    }

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
    static func read(
        path: String, mustBeOwnerOnly: Bool, effectiveUserID: uid_t = geteuid()
    ) throws(ServerIdentityError) -> [UInt8] {
        // `open` takes a C string, which ends at the first NUL: `key.pem` + NUL + anything would
        // open `key.pem`, and every error and log line would name a path that was not read.
        guard !path.utf8.contains(0) else {
            throw .unreadable(path: path, reason: "the path contains a NUL byte")
        }
        // O_NONBLOCK so that opening a FIFO returns instead of waiting for a writer; it has no
        // effect on reading a regular file, which is the only kind accepted below. O_NOCTTY so
        // that opening a terminal device, which is refused as not a regular file a moment later,
        // cannot first make it this process's controlling terminal.
        let descriptor = open(path, O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC)
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
            guard ownerIsTrusted(owner: status.st_uid, effectiveUserID: effectiveUserID) else {
                throw .privateKeyOwnedByAnotherUser(path: path, ownerID: UInt32(status.st_uid))
            }
            #if os(macOS)
            // macOS keeps an access control list apart from the mode, so a key can be `0600` and
            // readable by everyone. `acl_get_fd_np` returns nothing for a file with none. (On
            // Linux a POSIX ACL's mask is the group bits, which the mode check above refused.)
            if let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) {
                acl_free(UnsafeMutableRawPointer(acl))
                throw .privateKeyHasAccessControlList(path: path)
            }
            #endif
            try requireUnwritableAncestors(of: path)
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
