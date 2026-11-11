# Design Proposal: SwiftTLSKit 1.0.0 readiness

**Status:** Approved 2026-11-11 (decisions below). **Date:** 2026-11-11. **Baseline:** 0.2.1 (`0a836ef`).

## Decisions (2026-11-11)

1. **Enums stay exhaustive.** A new case is a major version; future capabilities arrive as new types.
2. **Release path: smaller commits, each a feature/fix on its own branch, working toward `1.0.0-beta.1`** (not 0.3.0 → rc). Adopters pin `.upToNextMinor(from: "0.2.1")`; SwiftPM never selects a prerelease for that range, so betas are opt-in and cannot reach them by accident. Any breaking change before beta.1 is still announced to the adopters.
3. **Linux scope includes arm64** (swift:6.2 and latest, x86_64 and arm64). Outcome: the hosted arm64 runner started on this private repo; no emulation needed. (Billing for it while private is unverified.)
4. **`description` text is not API** (documented in `StabilityPolicy.md`).
5. **GitHub:** confirmed — `jpurnell/SwiftTLSKit`, private, default branch `main`, Actions enabled (`allowed_actions: all`).
6. **`ClientHandshakeFailure` string parse: investigated.** NIOSSL has no typed path: `BoringSSLInternalError` keeps the packed code and the reason in private storage and exposes only `description` (`"Error: <decimal code> <ERR_error_string_n text>"`). It is not constructible outside NIOSSL, so it cannot even be matched by value. Plan: keep the numeric read (the documented format), **add the reason name** from the same description (`CERTIFICATE_VERIFY_FAILED`, `WRONG_VERSION_NUMBER`, `UNSUPPORTED_PROTOCOL`, `TLSV1_ALERT_PROTOCOL_VERSION`) as a second signal, because BoringSSL regenerates numbers but the name and number come from one table; an unrecognised format still degrades to `.other`, never to a wrong case. Both forms are pinned by the existing real-handshake tests, which CI now runs on Linux as well.

## Work log

Each step is its own branch and PR (gate 0/0 before commit): (1) CI + Linux, (2) SAN DER parser, (3) handshake classifier, (4) IPv6 text, (5) security review findings, (6) API audit + `StabilityPolicy.md`, (7) doc reconciliation → tag `1.0.0-beta.1`.

## 1. Objective

Take SwiftTLSKit from 0.2.1 to a 1.0.0 whose public API can be frozen, on a footing that has
been run on every platform it claims. Five workstreams:

| # | Workstream | Outcome |
|---|---|---|
| A | CI + Linux | `.github/workflows/ci.yml` builds and tests on macOS and Linux; Linux is declared in the README only after it is green |
| B | Remove the underscored NIOSSL SAN dependency | `CertificateSummary` no longer calls `_subjectAlternativeNames()` |
| C | API audit and freeze | Every public symbol justified; enum extensibility policy decided and written down |
| D | Security review | Key-file permissions, loopback/exposure classification, pinning, reload — reviewed adversarially, findings fixed or recorded |
| E | Doc reconciliation | master plan, CHANGELOG (incl. link references), README, DesignNotes agree with the code |

**Master Plan reference:** Roadmap "Future" (Linux; CI) and Known limits (Linux; underscored API).
Both were deferred at 0.2.0 with stated bars ("if the repository gains a second contributor");
six adopters on 0.2.1 is the case that moves the bar, and the plan should say so (Doc
Housekeeping: show where the plan was wrong).

## 2. Motivation

- **Linux is claimed in code, not in evidence.** `IPAddressLiteral`, `PEMFile` and
  `ClientHandshakeFailure` carry `Glibc`/`Musl` branches; `wrongHostname(under:)` has a non-Apple
  branch "nothing here has run". SwiftHTTPService's Linux CI compiles this package as a
  dependency but never runs its tests.
- **No CI.** The only gate is the local git hook and `quality-gate`. A 1.0 with six adopters
  should not depend on one machine.
- **`_subjectAlternativeNames()`** is public-but-underscored in NIOSSL (2.37.5 resolved). A NIOSSL
  minor can remove it; the failure lands as a compile error in every adopter's build, not here.
- **Exhaustive enums can't grow after 1.0** without breaking every adopter's `switch`.
  `ServerIdentityError`, `ClientTrustError`, `ClientHandshakeFailure`, `ReloadOutcome`,
  `ClientTrust`, `CertificateSource` are the ones most likely to need a case.
- **The security rules have never had an independent review.**

## 3. Proposed Architecture

**New files**
- `.github/workflows/ci.yml`
- `Sources/SwiftTLSKit/DERSubjectAlternativeNames.swift` (internal; B)
- `Tests/SwiftTLSKitTests/SubjectAlternativeNameTests.swift` (B)
- `Tests/SwiftTLSKitTests/Security/*` (D; one file per reviewed area)
- `project/plans/proposals/…` → `upcoming/` moves per the guidelines
- `project/decisions/` entries for the two ADR-worthy decisions in §11

**Modified files**
- `CertificateSummary.swift` (B: swap the source of names; public shape unchanged)
- Whatever C and D produce (each finding gets a test first)
- `Package.swift` only if C narrows a dependency range
- `README.md`, `CHANGELOG.md`, `project/master_plan.md`, `DesignNotes.md` (E)

**Release shape.** Breaking changes ride in **0.3.0**, then `1.0.0-rc.1`, then `1.0.0` with no
code change beyond docs. Correction (2026-11-11): an earlier draft said adopters declare `from: "0.2.1"` and would auto-receive a breaking 0.3.0. They declare `.upToNextMinor(from: "0.2.1")` (checked in all six), so a 0.3.0 reaches nobody without a manifest edit, and a prerelease tag is never selected by that range. Workstreams B and A are non-breaking; any C/D change that breaks must be agreed with
the adopters (or be 0.3.0 with their pins moved to `.upToNextMinor` first).

### A. CI and Linux

One workflow, modelled on `SwiftHTTPService/.github/workflows/ci.yml` but simpler: every
dependency of this package is public, so **no deploy key is needed** (SwiftHTTPService needs one
only because *it* depends on this private repo).

```yaml
jobs:
  linux:   # container: swift:6.2   (the tools-version floor)
  linux-latest:  # container: swift:6   (newest stable; catches forward breaks)
  macos:   # newest Xcode on the image; swift build --build-tests && swift test
  ios-tvos-visionos:  # xcodebuild -destination generic/platform=… build   (already a documented claim)
```

`quality-gate` is not installed on runners (owner's tool); CI builds and tests, the hook keeps
running the gate. Linux failures are expected on the first run; the work is fixing them with
tests, not skipping them. Anticipated suspects, to check not assume:
`FileHandle.read(upToCount:)`/`localizedDescription` text on corelibs-foundation, `Date.formatted`
in `description`, `strerror`-derived `unreadable(reason:)` text, the non-Apple
`wrongHostname(under:)` branch, and test assumptions that were measured on Security.framework
(the 2019 certificate-date rule is **Apple-only**; BoringSSL has no such rule, so the suite must
not assert it on Linux).

Musl/static-SDK: build-only job, optional (Open Question 3).

### B. Replace `_subjectAlternativeNames()`

`NIOSSLCertificate` offers `toDERBytes()` (stable, public). Read the SAN extension (OID
2.5.29.17) from the DER ourselves with a small bounded walker; no new dependency, and the
"`SwiftTLSKit` must not import X509 or SwiftASN1" rule holds.

```swift
/// internal
enum DERSubjectAlternativeNames {
    /// DNS names and IP addresses, in certificate order; empty if there is no SAN extension
    /// or the encoding is not what X.509 allows. Never throws, never traps.
    static func names(inCertificateDER der: [UInt8]) -> [String]
}
```

`CertificateSummary`'s public surface does not change (`subjectAlternativeNames: [String]`).
Parsing rules: definite lengths only (DER), every length checked against remaining bytes before
use, nesting depth bounded, total work linear in input, `iPAddress` of 4 or 16 bytes only, other
GeneralName kinds skipped. A malformed certificate yields `[]`, never an error: the input was
already accepted by BoringSSL, and the output is for a log line.

### C. API audit and freeze

Mechanical pass, then decisions. Public surface today: 19 top-level public types (10 enums, 7
structs, 1 class, plus `isLoopback` free function and an extension on `ClientTrust`).

Audit checklist, each answered in a table in the proposal's successor `api_audit.md`:

1. **Does it need to be public?** (`IncompleteServerIdentity.Half`, `description(certificateChainSetting:…)` are candidates to justify.)
2. **Does it leak a NIO/NIOSSL type?** `ServerTLSContext.sslContext: NIOSSLContext`,
   `LoadedServerIdentity.certificateChain: [NIOSSLCertificate]`, `NIOSSLServerHandler` returns,
   `ChannelHandler` returns. Freezing these ties 1.x to NIO 2 / NIOSSL 2. Decide: accept and
   document (recommended: it is the package's reason to exist), or wrap.
3. **Enum extensibility** (see Policy below).
4. **Value stability of text.** `CertificateSummary.description`, `ServerIdentityError.description`,
   `ClientTrustError.description` are quoted in docs (`ServingTLS.md` shows an exact message).
   Either they are API (frozen) or they are documented as not. Recommend: not API, except
   exact `chmod 600 PATH` guidance which is covered by tests anyway.
5. **IPv6 formatting.** `CertificateSummary` currently renders IPv6 as uncompressed groups
   (`0:0:0:0:0:0:0:1`). That is not RFC 5952 text and will be what adopters log and compare.
   Fix before freeze (compressed, lowercase) — a visible change, hence 0.3.0.
6. **Sendable/`Hashable` conformances** are API: only promise what we will keep.
7. **Platform floors** (macOS 14, iOS/tvOS 17, visionOS 1) are API; 1.0 keeps them.

**Enum policy (decision needed, Open Question 1).** A SwiftPM source dependency gets no
`@unknown default` protection, so adding a case is source-breaking for exhaustive switches.
Three tiers:

- *Closed by nature* — stay exhaustive, frozen: `MinimumTLSVersion`, `ReloadMode`,
  `SuggestedLogLevel`, `CertificatePin.Subject`, `IncompleteServerIdentity.Half`, `BindExposure`.
- *Foreseeably open* — `ServerIdentityError`, `ClientTrustError`, `ClientHandshakeFailure`,
  `ReloadOutcome`, `ClientTrust`, `CertificateSource`. Recommended: **keep as enums, and make the
  policy explicit**: new cases are a *major* version; the Known limits that would need cases
  (mutual TLS, encrypted keys) are introduced in 1.x as **new types/initialisers**, not new cases
  on these. Pre-freeze, add any case already known to be needed.
- Rejected: converting errors to `struct { kind }` — costs the typed-throws ergonomics the
  package was built around, for a risk the policy above removes.

### D. Security review

Method: three independent adversarial reviewers (fresh context, given the code and the
package rules, *not* given this proposal's conclusions), each producing findings with a failing
test before any fix. Scope and first questions:

| Area | Questions |
|---|---|
| Key-file permissions (`PEMFile.read`) | Only mode is checked, not owner (documented limit): does 1.0 accept that? Symlinks (check is on the opened descriptor — confirm the target's mode is what is tested). Parent-directory writability. `O_NONBLOCK` + FIFO/device handling. Size limit race. ACLs / extended attributes on macOS. Linux `st_mode` type width differences. |
| Loopback / exposure (`isLoopback`, `BindExposure.classify`) | `127.0.0.0/8` vs `127.0.0.1`; `::1`; IPv4-mapped `::ffff:127.0.0.1`; `localhost` and trailing-dot / case variants; zone IDs (`fe80::1%lo0`); `0.0.0.0`, `::`, empty string, whitespace; leading-zero octets (already refused); hostnames that *resolve* to loopback (we classify text only — must be stated). Fail-closed: any ambiguity → exposed. |
| Pinning (`CertificatePin`, `PinVerificationHandler`) | Pin check happens after the handshake: can application bytes reach the next handler before the pin is verified? Which certificate is hashed (leaf only? any in chain?). Pin parsing (case, length, whitespace, `:` separators). Pinned trust must still verify the chain+hostname or must it not (documented). Comparison need not be constant-time (public values) — say so. |
| Reload | Cert and key replaced non-atomically: do we ever pair a new cert with an old key and serve it? Failure path keeps the old context (confirm). `reloadIfChanged` change detection (mtime resolution, inode swap). |
| No-leak rule | Nothing from a key file in an error/description (existing `KeyMaterialExposureTests` — extend to every error path found above). |

Outputs: findings with severity, fix commit + test per finding, and a `security_review.md`
summary. Findings that cannot be fixed without breaking the API are decided in C before freeze.

### E. Doc reconciliation

Per the global Doc Housekeeping list: master plan type table / status / roadmap (strike-through,
keep the reasoning, record that CI and Linux shipped despite "not without a second
contributor"), CHANGELOG including link references, README platform claim, DesignNotes (the
"underscored API" section is replaced, not deleted: it records why the DER walker exists),
**Last Updated** note, and the unaudited "Tested on macOS arm64" and Known limits lines.
Adopter migration items in the plan (still unchecked) updated against the six packages now on 0.2.1.

## 4. API Surface

Nothing new is added to the public surface by A, B, D or E. Possible public changes come only
from C, and each would be listed in `api_audit.md` before being made:

```swift
// B: unchanged
public struct CertificateSummary: Sendable, Hashable {
    public let subjectAlternativeNames: [String]   // IPv6 text becomes RFC 5952 (C.5)
    …
}

// internal, new (B)
enum DERSubjectAlternativeNames {
    static func names(inCertificateDER der: [UInt8]) -> [String]
}
```

## 5. MCP Schema

N/A. SwiftTLSKit is a configuration library with no tool surface; there is nothing to expose to
an AI client and the project's own rules forbid adding a runtime surface here.

## 6. Constraints & Compliance

- **No `withUnsafe*`:** the DER walker uses `[UInt8]` indexing and `ArraySlice` only.
- **No X509/SwiftASN1 in the library target:** preserved — that is the reason B is hand-written.
- **No force unwraps / `try!`, guards for validation, bounds checked before every index:** applies to the walker.
- **Nothing reads the clock; no randomness of its own:** unchanged. CI adds neither.
- **No key material in errors, descriptions or logs:** D extends the test over every path.
- **No new dependency on the owner's other packages:** unchanged.
- **Quality gate 0/0 without overrides** before each commit.
- **Concurrency:** no new shared state.

## 7. Source & API Compatibility

- A, B, E: none. D: tightening only where it fixes a defect (a case that was accepted and
  should have been refused is behavioural, and noted in CHANGELOG as such).
- C.5 (IPv6 text) is observable: 0.3.0, called out in CHANGELOG with the migration.
- Any enum case added pre-freeze is source-breaking: 0.3.0, coordinated with adopters, who are
  on `.upToNextMinor(from: "0.2.1")`, so each must edit its requirement to receive it.
- Adoption is incremental: CI/Linux need no consumer change at all.

## 8. Backend Abstraction

N/A (not compute-intensive). The one platform split is the existing Darwin/Glibc/Musl `canImport`
branches, which A exercises.

## 9. Dependencies

**Internal:** `CertificateSummary`, `ServerIdentity`, `PinVerificationHandler` (callers of the
summary).
**External:** none added. Possible *narrowing* of `swift-nio-ssl` upper bound if C decides to
freeze against NIOSSL 2 (it already resolves ≥ 2.37.4). `swift-certificates` stays
test-support-only and becomes the **independent reference** for B's tests.

## 10. Test Strategy

**Categories.** Golden path; edge; invalid/hostile input; differential; platform parity.

- **B — differential test.** Generate certificates with `SwiftTLSKitTestSupport` (seeded) with
  many SAN shapes; parse the same DER with swift-certificates' `SubjectAlternativeNames` (a
  parser that is neither ours nor NIOSSL's) and assert equal output.
  **Validation trace:** a leaf with SANs DNS `example.test`, DNS `*.example.test`, IP `127.0.0.1`,
  IP `::1` must produce `["example.test", "*.example.test", "127.0.0.1", "::1"]` (RFC 5952 for
  the last; the *current* code would give `0:0:0:0:0:0:0:1`, which is the red test for C.5).
  Reference truth for the textual forms: RFC 5952 §4; for the encoding: RFC 5280 §4.2.1.6 and
  X.690 (DER).
- **B — hostile input.** Truncated DER at every byte offset of a real certificate; lengths
  claiming more than remains; indefinite-length form; deeply nested sequences; an extension with
  a 3-byte `iPAddress`; non-UTF-8 `dNSName`. Property: never traps, never reads out of bounds,
  returns `[]` or a prefix-consistent list.
- **A — platform parity.** The whole existing suite is the test; Apple-only expectations are
  guarded by what they actually measure, not by `#if` that skips a check.
- **D — one failing test per finding** before its fix, in `Tests/…/Security/`.
- **C — API stability test.** A test (or CI step using `swift package diagnose-api-breaking-changes 0.2.1`)
  that fails on an unintended public-surface change after the audit.

## 11. Architecture Decision Review

- [x] `project/decisions/` is empty; decisions live in `DesignNotes.md` and `master_plan.md`.
- Supersedes: DesignNotes "Subject names come from an underscored NIOSSL API" (replaced).
- New ADR 1 — *api/dependency*: **read SANs from the DER ourselves rather than add
  swift-certificates to the library target.**
- New ADR 2 — *api*: **error/failure enums stay exhaustive; new cases are a major version;
  future capabilities arrive as new types.**
- New ADR 3 — *testing/CI*: **CI builds and tests; the quality gate stays a local hook.**

## 12. Adversarial Review

**Strongest case for a different approach.** Add swift-certificates to the *library* target and
delete the hand parser: it is the maintained, fuzzed, Apple-owned implementation, and "don't
hand-write a security-adjacent parser" is the same argument this package used for SHA-256.
Against that: it reverses a recorded package rule, pulls swift-certificates and swift-asn1 into
every adopter's *build* (today they only resolve), and the parser here is bounded, only feeds a
log line, and is differential-tested against the maintained one. **Alternative:** drop
`subjectAlternativeNames` from the summary. Rejected because adopters log it at start-up.

**Where this design is most likely wrong.**
(1) That the Linux run reveals only small fixes. If BoringSSL's error text or hostname behaviour
differs materially, `ClientHandshakeFailure` (which parses NIOSSL's description for the packed
error code) may need redesign, and that is a public-API change inside the freeze window.
(2) That adopters can absorb a breaking change at all: they must each edit their manifest, six packages.
(3) That text of `description` is not API — adopters may already match on it.

**What an experienced critic would say.** "You are freezing a surface that still depends on
parsing another library's error strings." We are proceeding because A is sequenced *first*: the
Linux evidence and a decision on the error-string dependency (Open Question 4) land before any
freeze, and 1.0.0-rc.1 gives adopters a window.

## 13. Alternatives Considered

1. **Tag 1.0.0 now, fix everything in 1.x.** Fast, and the underscored API and enum policy are
   *exactly* the things that become expensive after 1.0. Rejected.
2. **Keep `_subjectAlternativeNames()` and pin NIOSSL to `..<2.38`.** Cheap; but a pin to a minor
   range forces six adopters' resolution, and the symbol is only "unstable" by NIOSSL's own
   word. Acceptable fallback if B's differential test shows a surprise.
3. **`@frozen`/library evolution.** Would give `@unknown default`, but needs resilient builds
   across SwiftPM consumers; not how this ecosystem consumes packages. Rejected.
4. **Self-hosted Linux runner (Chromedome is macOS).** Not available; GitHub's containers do it.

## 14. Future Directions

- Mutual TLS on the server side; encrypted private keys — could arrive in 1.x as new types.
- A peer-certificate fingerprint after a client handshake (already in the plan's Future).
- Replacing the BoringSSL error-code string parse with a typed NIOSSL error path, if NIOSSL
  exposes one.
- A Musl / Static Linux SDK job; an Android build.

## 15. Open Questions

1. **Enum policy (C).** Is "exhaustive, new cases = major version, future features as new
   types" acceptable to you and the adopters? (Recommended.)
2. **Release path.** `0.3.0` → `1.0.0-rc.1` → `1.0.0` (recommended), or straight to 1.0.0 once
   D and C are clean?
3. **Linux scope.** swift:6.2 and swift:6 containers only (recommended), or also an arm64 Linux
   and a Musl build-only job?
4. **`ClientHandshakeFailure`'s packed-error-code parse.** Fix before 1.0 if a typed path exists
   in NIOSSL, otherwise freeze with a CI test that pins the format? Needs a short investigation
   during A.
5. **Is `description` text API?** (Recommended: no, documented.)
6. **GitHub.** Is the repo on GitHub with Actions enabled (SwiftHTTPService reaches it as
   `git@github.com:jpurnell/SwiftTLSKit.git`)? Confirm before A begins.

## 16. Documentation Strategy

**Documentation Type:** Narrative Article Required (one, short).

- Combines 3+ APIs? No. Needs 50+ lines? Yes (the stability policy). Theory? No → article required.
- **Article:** `StabilityPolicy.md` in the `.docc` catalog: what 1.x promises (source
  compatibility, enum policy, NIO/NIOSSL coupling, text-not-API), what it does not, and the
  Platform table including Linux.
- DesignNotes updated (B replaces the underscored-API section); security findings summarised in
  `project/plans/…/security_review.md`, not in public docs unless they change a documented rule.

## Proposed order of work (TDD, one PR per step, gate 0/0 each)

1. **A** — CI workflow; first red run on Linux; fix with tests. (Gate: both Linux containers + macOS green.)
2. **B** — red differential and hostile-input tests, DER walker, remove the underscored call.
3. **D** — three reviewers in parallel (read-only, `Explore`/fresh agents); triage; fix per finding.
4. **C** — audit table, decisions from Open Questions, API-breakage check against 0.2.1; 0.3.0.
5. **E** — reconcile docs; `StabilityPolicy.md`; `1.0.0-rc.1`; adopters build against it; `1.0.0`.

## Review checklist

- [ ] Module placement follows existing structure (library target gains one internal file)
- [ ] No forbidden patterns (`withUnsafe*`, force unwraps, X509 in library)
- [ ] Source compatibility assessed; breaking items named (C.5, any pre-freeze enum case)
- [ ] Adoption path documented (`.upToNextMinor` pins; prereleases are opt-in)
- [ ] Alternatives with pros/cons
- [ ] Reference truth identified (swift-certificates, RFC 5280, RFC 5952, X.690)
- [ ] Adversarial review complete
- [ ] Open questions resolved
