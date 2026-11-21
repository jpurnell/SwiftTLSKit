# Implementation Checklist for SwiftTLSKit — LinuxSupport

**Purpose:** Local Linux verification harness, Musl-safe IPv6 parsing, system-roots bare-box test.
**Design:** `project/plans/proposals/LinuxSupport.md` (read it before changing anything here)
**Target release:** 1.0.1 (patch; no public API change)

---

## Current Phase: Step 6 done; gate, PR and tag remain

### In Progress
- [ ] Owner approves the proposal (trims applied 2026-11-21: Step 5 optional, Step 7 dropped, simpler IPv6 fix)
- [x] Step 0: runner is **starscream.local** (Ubuntu 26.04.1, x86_64, Swift 6.4.2 via swiftly, uid 1000, passwordless ssh). No container needed; supersedes proposal section 6
- [x] Step 1 baseline 2026-11-21: `scripts/linux-test.sh` -> 193 tests in 18 suites passed, non-root, Swift 6.4.2, 0 warnings, 1m13s cold. (The docs' "135 tests" is stale; reconcile in Step 6.)
- [x] Step 1 remainder: Swift 6.2.4 floor run green, 193 tests, 0 warnings. Root run not done (starscream login is uid 1000 only; the non-root case is the one that matters)
- [x] Step 4: bare-box tests (`BareBoxTrustTests`) written and verified with `scripts/linux-test.sh --no-ca-store` (bubblewrap, no sudo). Findings: NIOSSL ignores `SSL_CERT_FILE`; with neither CA file nor directory, `.systemRoots` and `.additionalRoots` throw `ClientTrustError.contextRejected(reason: "unknownError([])")` at construction; `.onlyRoots` works. Negative control (env var set, store visible) fails the two refusal tests. Typed error already exists, so Q4 needs no API addition; only the empty reason text is unhelpful (candidate: a clearer reason string, not an API change)

### Blocked
- none

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
- [x] Step 2: Musl build RED confirmed 2026-11-21 on starscream with the 6.4.2 static SDK (SHA-256 of the bundle `3786b179936d9cc9e266dd506bd1654176358d7b25288e243359f4d17cc4dc5a`, downloaded over HTTPS; swift.org publishes a checksum for 6.4.3 only): `IPAddressLiteral.swift:40: value of type 'in6_addr' has no member '__in6_u'`. Only that file failed. Musl is build-only: the static SDK has no `Testing` module, so the suite cannot link
- [x] Step 3 tests: IPv6 vectors by hand from RFC 4291/5952 (`::`, `2001:db8::1`, `1:2:3:4:5:6:7:8`, `::ffff:192.0.2.1`, eight malformed forms); NUL case already present
- [x] Step 4 (see above; the original prediction that probes would report `certificateNotTrusted` was wrong)
- [ ] (optional) Variant c (empty bundle file via a real temp file, not /dev/null) still to try
- [ ] Deterministic seeds only (`TestSeed.swift`); no clock reads
- [ ] `/evaluate-tests` >= 75 on all dimensions

## 2. Implementation (GREEN)
- [x] `IPAddressLiteral.ipv6Bytes`: `[UInt8]` x16 + `inet_pton(AF_INET6, literal, &bytes)`; `in6_addr` use and the `#if` deleted
- [x] Green: macOS 203 tests; Linux Glibc 201 (Swift 6.4.2 and 6.2.4 on 193 before the vectors; 6.4.2 rerun after); Musl x86_64 and aarch64 build clean, 0 warnings
- [ ] Musl build now green; Glibc and macOS suites green
- [ ] Commit at each green state

## 3. Refactoring
- [ ] Remove dead branch; keep `isWhole` NUL guard
- [ ] Safety audit: searched for `!`, `as!`, `try!`, `fatalError`, `while true`, `withUnsafe*`
- [ ] Hygiene audit (`zzz In Process/` n/a if absent)

## 4. Documentation
- [x] `ServingTLS.md` / `ConnectingAsAClient.md`: Platforms and deployment (key mode/owner on Linux, certbot deploy hook, `ca-certificates`)
- [x] (the runner choice is recorded in the proposal section 6 and the session summary; no separate decision file) `docs/` decision record for the runner choice in `project/decisions/`
- [x] Doc housekeeping: README platform line, `StabilityPolicy.md`, CHANGELOG 1.0.1 + link refs, `master_plan.md` (strike through, keep earlier reasoning; note "Linux needed no source change" did not hold for Musl if confirmed), Last Updated
- [x] Session summary in `project/summaries/`

## 5. Quality Gates
- [ ] `quality-gate` 0 errors / 0 warnings, no suppressions
- [ ] All tests pass on macOS and Linux (harness)
- [ ] Final gate pass before declaring done

## Findings
- [x] **Zone suffix:** decided 2026-11-21 to fix in 1.0.1. Not an address on any platform; `makeHandlers` refuses it (`invalidServerHostname`). Glibc's NIOSSL had been sending it as SNI. macOS behaviour change recorded in CHANGELOG.

## Optional / deferred
- [ ] Step 5: consumer-style scratch package (low value)
- [ ] Step 7: second environment (only if the runner is flaky)
- [ ] SwiftPenTest Linux: separate proposal (argument-parser, `.copy("PenTestCore.docc")` resource bundle, `import os` guards)

---

**Last Updated:** 2026-11-21 — Steps 1-4 done; Musl IPv6 fix green on macOS, Glibc and Musl (x86_64, aarch64 build-only)
