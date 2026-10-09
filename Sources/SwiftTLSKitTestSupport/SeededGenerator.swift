/// A seeded generator for a test's certificates: the same seed gives the same keys and
/// serial numbers on every run, on every machine.
///
/// It is SplitMix64 (Steele, Lea and Flood, "Fast Splittable Pseudorandom Number Generators",
/// 2014), which is small enough to check against published values — and this package's tests
/// do.
///
/// ```swift
/// import SwiftTLSKitTestSupport
///
/// var generator = SeededGenerator(seed: 1_234_567)
/// print(generator.next(), generator.next())
/// // Prints "6457827717110365317 3203168211198807973"
/// ```
///
/// Pass one to ``TestAuthority/init(commonName:notValidBefore:notValidAfter:generator:)``:
///
/// ```swift
/// import SwiftTLSKitTestSupport
///
/// let authority = try TestAuthority(commonName: "Test Authority", generator: SeededGenerator(seed: 1))
/// let again = try TestAuthority(commonName: "Test Authority", generator: SeededGenerator(seed: 1))
/// let leaf = try authority.issueLeaf(dnsNames: ["localhost"])
/// let same = try again.issueLeaf(dnsNames: ["localhost"])
/// print(leaf.publicKeySHA256 == same.publicKeySHA256)
/// // Prints "true"
/// ```
///
/// ## Not for secrets
///
/// **Nothing this produces is secret, and nothing it produces may protect anything.** Its
/// whole output is a function of the seed, the seed is written in a test file, and SplitMix64
/// was never designed to resist prediction: one output is enough to recover its state. A key
/// made from it is a published key.
///
/// That is acceptable in exactly one place, which is where this type lives: an authority made
/// by ``TestAuthority`` is trusted by nothing except a client that a test builds to trust it,
/// inside the test process. It is in the test-support product, and not in `SwiftTLSKit`, so
/// that code which ships cannot reach it without depending on a product whose name says what
/// it is for.
///
/// ## Seeds
///
/// Two authorities that must be different authorities need different seeds: the same seed is
/// the same key. Every seed is usable, zero included.
///
/// It is a value. A copy continues from the state the original had when it was copied, and
/// the two do not affect each other afterwards — so passing the same variable to two
/// authorities gives them the same key.
public struct SeededGenerator: RandomNumberGenerator, Sendable {
    /// The increment: 2⁶⁴ divided by the golden ratio, rounded to an odd number.
    private static let increment: UInt64 = 0x9E37_79B9_7F4A_7C15
    /// The first multiplier of the output mix (Stafford's variant 13 of the MurmurHash3
    /// finaliser).
    private static let firstMultiplier: UInt64 = 0xBF58_476D_1CE4_E5B9
    /// The second multiplier of the output mix.
    private static let secondMultiplier: UInt64 = 0x94D0_49BB_1331_11EB
    private static let firstShift: UInt64 = 30
    private static let secondShift: UInt64 = 27
    private static let finalShift: UInt64 = 31

    private var state: UInt64

    /// Makes a generator whose every output is determined by `seed`.
    ///
    /// - Parameter seed: Any value. The same seed gives the same sequence.
    public init(seed: UInt64) {
        state = seed
    }

    /// The next value of the sequence.
    ///
    /// - Returns: 64 bits that depend only on the seed and on how many values were drawn
    ///   before this one.
    public mutating func next() -> UInt64 {
        state &+= Self.increment
        var mixed = state
        mixed = (mixed ^ (mixed >> Self.firstShift)) &* Self.firstMultiplier
        mixed = (mixed ^ (mixed >> Self.secondShift)) &* Self.secondMultiplier
        return mixed ^ (mixed >> Self.finalShift)
    }
}
