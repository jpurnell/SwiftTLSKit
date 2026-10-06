/// SplitMix64 (Steele, Lea and Flood, 2014): a seeded generator, so that the keys and serial
/// numbers a test's certificates are made from are the same on every run.
///
/// It lives here, in the test target, rather than coming from SwiftDeterminism, because this
/// package takes no dependency on the owner's other packages and that includes its tests. It
/// is deliberately not part of `SwiftTLSKitTestSupport`: a consumer brings its own generator.
///
/// The keys this produces are reproducible from the seed below, which makes them public. That
/// is acceptable for exactly one reason: nothing trusts a test authority except a client that
/// a test constructs to trust it, inside the test process.
struct SeededGenerator: RandomNumberGenerator, Sendable {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var mixed = state
        mixed = (mixed ^ (mixed >> 30)) &* 0xBF58_476D_1CE4_E5B9
        mixed = (mixed ^ (mixed >> 27)) &* 0x94D0_49BB_1331_11EB
        return mixed ^ (mixed >> 31)
    }
}

/// The seeds the suites use. Two authorities that must be different authorities need
/// different seeds: the same seed is the same key.
enum TestSeed {
    /// The authority every suite issues its leaves from.
    static let authority: UInt64 = 0x5357_4946_544C_5301
    /// An authority no client in the suite is told to trust.
    static let stranger: UInt64 = 0x5357_4946_544C_5302
}
