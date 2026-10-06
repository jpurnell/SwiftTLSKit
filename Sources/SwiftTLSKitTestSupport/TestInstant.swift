import Foundation

/// Fixed instants for tests, so that no test reads the clock.
///
/// Test certificates carry these as their validity, and SwiftTLSKit — which takes the current
/// time as a parameter — is handed one of them as "now".
///
/// ## Why long-lived certificates start before 1 July 2019
///
/// When the system's root store is consulted, an Apple platform verifies a server certificate
/// through Security.framework, and Apple's policy applies whoever signed it: a TLS server
/// certificate issued on or after 1 July 2019 must be valid for 825 days or fewer. A test
/// certificate that short would have to be dated from the day the suite runs, which means
/// reading the clock, and would make every run issue different certificates.
///
/// The rule is keyed on the certificate's own "not before" date. A certificate dated before
/// the rule is outside it, so it can be long-lived and fixed. ``longLivedStart`` is
/// 1 January 2019 for that reason, and it is the default start of everything
/// ``TestAuthority`` issues.
///
/// Two details, both measured with real handshakes on macOS 27.0.1 rather than read from a
/// document:
///
/// - The line is at 2019-06-30T23:00:00Z, an hour before 1 July in UTC, and it is the same
///   whatever the machine's time zone. A certificate meant to be outside the rule should be
///   dated well before it, not at its edge.
/// - The rule is applied only where the system's roots are consulted. A client that trusts
///   only supplied roots — ``TestAuthority/clientTrust`` — verifies with BoringSSL, which has
///   no such rule, so a test that uses that trust alone would pass with any dates and then
///   fail the first time someone trusts the same authority alongside the system's.
public enum TestInstant {
    /// 2019-01-01T00:00:00Z — the start of every long-lived test certificate.
    ///
    /// Before 1 July 2019 on purpose; see ``TestInstant``.
    public static let longLivedStart = Date(timeIntervalSince1970: 1_546_300_800)

    /// 2090-01-01T00:00:00Z — the end of every long-lived test certificate.
    ///
    /// A real handshake is verified by the TLS library against the machine's own clock, which
    /// no parameter reaches, so this has to be later than any day the suite will run on.
    public static let longLivedEnd = Date(timeIntervalSince1970: 3_786_912_000)

    /// 2021-01-01T00:00:00Z — the end of a short-lived certificate: one that has expired by
    /// ``now`` and had not by ``duringShortLived``.
    public static let shortLivedEnd = Date(timeIntervalSince1970: 1_609_459_200)

    /// 2020-07-01T00:00:00Z — inside the short-lived certificate's validity.
    public static let duringShortLived = Date(timeIntervalSince1970: 1_593_561_600)

    /// 2018-01-01T00:00:00Z — before any test certificate is valid.
    public static let beforeAnything = Date(timeIntervalSince1970: 1_514_764_800)

    /// 2026-10-06T00:00:00Z — a "now" inside every long-lived test certificate's validity, to
    /// hand to SwiftTLSKit when a test has no reason to choose another.
    public static let now = Date(timeIntervalSince1970: 1_791_244_800)
}
