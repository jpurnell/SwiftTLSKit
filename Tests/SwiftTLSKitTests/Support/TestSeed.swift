/// The seeds the suites use. Two authorities that must be different authorities need
/// different seeds: the same seed is the same key.
enum TestSeed {
    /// The authority every suite issues its leaves from.
    static let authority: UInt64 = 0x5357_4946_544C_5301
    /// An authority no client in the suite is told to trust.
    static let stranger: UInt64 = 0x5357_4946_544C_5302
}
