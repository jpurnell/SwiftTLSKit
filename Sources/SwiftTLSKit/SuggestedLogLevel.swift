/// How loudly something this package returns deserves to be logged.
///
/// A suggestion, and only that. The package has no logger and no logging dependency — see
/// <doc:DesignNotes> — so it cannot log anything itself; what it can do is say what it knows
/// about how much an outcome matters, so that every consumer does not work it out again.
///
/// The raw values are the names swift-log gives the same levels, so a consumer that uses
/// swift-log converts with `Logger.Level(rawValue: level.rawValue)`. With `os.Logger`, ``info``
/// is `.info`, ``notice`` is `.default`, and ``warning`` is `.error`, which is what
/// `Logger.warning(_:)` itself logs at.
///
/// ```swift
/// import SwiftTLSKit
///
/// print(SuggestedLogLevel.allCases.map(\.rawValue))
/// // Prints "["info", "notice", "warning"]"
/// ```
public enum SuggestedLogLevel: String, Sendable, Hashable, CaseIterable {
    /// Routine. Nothing happened that anyone needs to know about unless they are looking.
    case info
    /// Normal, and worth a line: something an operator did, or was waiting for, took effect.
    case notice
    /// Not an error, and may become one if it is still true later.
    case warning
}

extension SuggestedLogLevel: Comparable {
    /// Orders levels by severity, least first.
    ///
    /// - Parameters:
    ///   - lhs: A level.
    ///   - rhs: Another level.
    /// - Returns: Whether `lhs` is less severe than `rhs`.
    public static func < (lhs: SuggestedLogLevel, rhs: SuggestedLogLevel) -> Bool {
        lhs.severity < rhs.severity
    }

    private var severity: Int {
        switch self {
        case .info: return 0
        case .notice: return 1
        case .warning: return 2
        }
    }
}
