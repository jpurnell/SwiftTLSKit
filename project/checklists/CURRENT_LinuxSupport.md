# Implementation Checklist for SwiftTLSKit — LinuxSupport

**Purpose:** Local Linux verification harness, Musl-safe IPv6 parsing, system-roots bare-box test.
**Design:** `project/plans/proposals/LinuxSupport.md` (read it before changing anything here)
**Target release:** 1.0.1 (patch; no public API change)

---

## Current Phase: Steps 1 and 4 done; next Step 2 (Musl RED, needs static SDK) then Step 3

### In Progress
- [ ] Owner approves the proposal (trims applied 2026-11-21: Step 5 optional, Step 7 dropped, simpler IPv6 fix)
- [x] Step 0: runner is **starscream.local** (Ubuntu 26.04.1, x86_64, Swift 6.4.2 via swiftly, uid 1000, passwordless ssh). No container needed; supersedes proposal section 6
- [x] Step 1 baseline 2026-11-21: `scripts/linux-test.sh` -> 193 tests in 18 suites passed, non-root, Swift 6.4.2, 0 warnings, 1m13s cold. (The docs' "135 tests" is stale; reconcile in Step 6.)
- [x] Step 1 remainder: Swift 6.2.4 floor run green, 193 tests, 0 warnings. Root run not done (starscream login is uid 1000 only; the non-root case is the one that matters)
- [x] Step 4: bare-box tests (`BareBoxTrustTests`) written and verified with `scripts/linux-test.sh --no-ca-store` (bubblewrap, no sudo). Findings: NIOSSL ignores `SSL_CERT_FILE`; with neither CA file nor directory, `.systemRoots` and `.additionalRoots` throw `ClientTrustError.contextRejected(reason: "unknownError([])")` at construction; `.onlyRoots` works. Negative control (env var set, store visible) fails the two refusal tests. Typed error already exists, so Q4 needs no API addition; only the empty reason text is unhelpful (candidate: a clearer reason string, not an API change)

### Blocked
- [ ] Step 2 (Musl build) — *needs the static Linux SDK installed on starscream (also lets Musl tests actually run there); owner to approve*

---

## 0. Design Proposal
- [x] Objective documented
- [x] Architecture proposed (one NIOSSL path; no NIOTransportServices)
- [x] API surface: no change
- [x] Constraints compliance reviewed (no `withUnsafe*`, no clock, no own RNG, no key in errors)
- [x] Dependencies: none added
- [x] Test strategy outlined
- [ ] Open questions resolved: Q2 runner, Q3 target box arch / static vs dynamic, Q5, Q6, Q7
- [ ] **Proposal approved by owner**

## 1. Testing (RED)
- [x] Step 1: `scripts/linux-test.sh` written; 6.4.2 non-root green (no failing test to write). Root and 6.2 runs outstanding
- [ ] Step 2: Musl build RED — `swift build --swift-sdk {aarch64,x86_64}-swift-linux-musl` fails on `__in6_u` (confirm, do not assume)
- [ ] Step 3 tests: IPv6 vectors written from RFC 5952 forms, not from function output: `::1`, `2001:db8::1`, `::ffff:192.0.2.1`, malformed, embedded NUL
- [x] Step 4 (see above; the original prediction that probes would report `certificateNotTrusted` was wrong)
- [ ] Variant c (empty bundle file via a real temp file, not /dev/null) still to try
- [ ] Deterministic seeds only (`TestSeed.swift`); no clock reads
- [ ] `/evaluate-tests` >= 75 on all dimensions

## 2. Implementation (GREEN)
- [ ] `IPAddressLiteral.ipv6Bytes`: `[UInt8]` x16 + `inet_pton(AF_INET6, literal, &bytes)`; delete `in6_addr` use and the `#if`
- [ ] Musl build now green; Glibc and macOS suites green
- [ ] Commit at each green state

## 3. Refactoring
- [ ] Remove dead branch; keep `isWhole` NUL guard
- [ ] Safety audit: searched for `!`, `as!`, `try!`, `fatalError`, `while true`, `withUnsafe*`
- [ ] Hygiene audit (`zzz In Process/` n/a if absent)

## 4. Documentation
- [ ] `ServingTLS.md` / `ConnectingAsAClient.md`: Platforms and deployment (key mode/owner on Linux, certbot deploy hook, `ca-certificates`)
- [ ] `docs/` decision record for the runner choice in `project/decisions/`
- [ ] Doc housekeeping: README platform line, `StabilityPolicy.md`, CHANGELOG 1.0.1 + link refs, `master_plan.md` (strike through, keep earlier reasoning; note "Linux needed no source change" did not hold for Musl if confirmed), Last Updated
- [ ] Session summary in `project/summaries/`

## 5. Quality Gates
- [ ] `quality-gate` 0 errors / 0 warnings, no suppressions
- [ ] All tests pass on macOS and Linux (harness)
- [ ] Final gate pass before declaring done

## Optional / deferred
- [ ] Step 5: consumer-style scratch package (low value)
- [ ] Step 7: second environment (only if the runner is flaky)
- [ ] SwiftPenTest Linux: separate proposal (argument-parser, `.copy("PenTestCore.docc")` resource bundle, `import os` guards)

---

**Last Updated:** 2026-11-21 — Steps 1 and 4 done on starscream; gate 51/51; macOS 198 tests, Linux 193 + 3 bare-box
