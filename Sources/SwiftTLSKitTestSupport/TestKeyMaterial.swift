import Crypto
import NIOConcurrencyHelpers

/// Why a test certificate could not be made.
public enum TestCertificateError: Error, Sendable, Hashable {
    /// The generator did not produce a usable P-256 private key in the attempts allowed.
    ///
    /// A private key is a number from 1 to just under the order of the curve, and 32 bytes
    /// from a generator are outside that range about once in four thousand million draws. A
    /// generator that fails this many times in a row is not producing random bytes.
    ///
    /// - Parameter attempts: How many draws were made.
    case keyGenerationExhausted(attempts: Int)
}

extension TestCertificateError: CustomStringConvertible {
    /// A sentence for a test failure.
    public var description: String {
        switch self {
        case .keyGenerationExhausted(let attempts):
            return "The generator produced no usable P-256 private key in \(attempts) attempts. "
                + "It is probably not producing random bytes."
        }
    }
}

/// The caller's generator, shared by an authority and everything it issues.
///
/// All of the randomness in this module comes through here, from a generator the caller
/// supplied: nothing reaches for the system's. That is what lets a test choose between keys
/// that are the same on every run (a seeded generator) and keys nobody can predict (the
/// system's), and it is the caller's choice to make.
struct InjectedRandomness: Sendable {
    /// How many times a private key is drawn before giving up.
    static let maximumKeyAttempts = 16

    private static let keyByteCount = 32
    private static let bitsPerByte = 8

    private let generator: NIOLockedValueBox<any RandomNumberGenerator & Sendable>

    init(_ generator: some RandomNumberGenerator & Sendable) {
        self.generator = NIOLockedValueBox(generator)
    }

    /// `count` bytes: each value the generator returns contributes its eight bytes most
    /// significant first, and values are used in the order they are drawn.
    func bytes(count: Int) -> [UInt8] {
        generator.withLockedValue { generator in
            var bytes: [UInt8] = []
            bytes.reserveCapacity(count + MemoryLayout<UInt64>.size)
            while bytes.count < count {
                let word = generator.next()
                for shift in stride(from: UInt64.bitWidth - Self.bitsPerByte, through: 0, by: -Self.bitsPerByte) {
                    bytes.append(UInt8(truncatingIfNeeded: word >> UInt64(shift)))
                }
            }
            return Array(bytes.prefix(count))
        }
    }

    /// A P-256 private key whose scalar is the next 32 bytes drawn, read as a big-endian
    /// number. A draw that is not a valid scalar — zero, or not below the order of the curve —
    /// is discarded and the next 32 bytes are tried.
    func signingKey() throws(TestCertificateError) -> P256.Signing.PrivateKey {
        for _ in 0..<Self.maximumKeyAttempts {
            // The only way this initializer fails for 32 bytes is a scalar outside the valid
            // range, and the response to that is the next draw, so the error itself is not kept.
            let drawn = Result { try P256.Signing.PrivateKey(rawRepresentation: bytes(count: Self.keyByteCount)) }
            if case .success(let key) = drawn {
                return key
            }
        }
        throw .keyGenerationExhausted(attempts: Self.maximumKeyAttempts)
    }
}
