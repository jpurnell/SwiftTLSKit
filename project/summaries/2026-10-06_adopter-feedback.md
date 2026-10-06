# Session Summary: Adopter feedback (intended 0.2.0)

| Date | Phase | Status |
| :--- | :--- | :--- |
| 2026-10-06 | Phase 3: what the first adopters found | DONE ON BRANCH — not merged, not tagged |

Branch `feat/adopter-feedback`, from `main` at `0.1.0`. A pull request is open; nothing was
merged or tagged, and no other repository was modified. The adopters' code was read with
`git show <branch>:<path>` only.

## 1. Core Objective

IconquerServer (`feat/tls`, PR #4) and IconquerClient (`feat/wss`, PR #2) adopted 0.1.0 and
reported nine problems. Fix them.

## 2. Design Decisions

Full reasoning: "What the first adopters changed" in
`Sources/SwiftTLSKit/SwiftTLSKit.docc/DesignNotes.md`.

- **Decision:** `resolve` throws a new `IncompleteServerIdentity`, and
  `ServerIdentityError.incompletePair` / `.Component` are removed. **Rationale:** an error
  type should be as wide as what throws it, in both directions. **Alternative rejected:**
  keep the case for source compatibility — it would be a case nothing throws. **Cost:** a
  source break, which is why the intended version is 0.2.0.
- **Decision:** the half-pair message ends at "one without the other is refused", and takes
  the consumer's setting names. **Rationale:** "or neither to serve plaintext" is false for a
  consumer that refuses plaintext.
- **Decision:** change detection covers the key file *and* `reloadOnEach` takes a `ReloadMode`
  with no default. **Rationale:** they answer different questions — what "unchanged" means,
  and what a trigger means. **Finding:** the reported defect ("a renewal keeping the chain but
  changing the key is missed") does not hold: a key that is not the leaf's is refused, so a
  new key implies a new chain. The real defect was that `.unchanged` was reported for a
  rewritten key file. Recorded as such in the commit, CHANGELOG, article and master plan.
- **Decision:** the key-file digest is a type with no accessor, a redacted description and an
  empty mirror. **Rationale:** "never log or expose it" enforced by construction, and tested
  by walking everything reflection reaches.
- **Decision:** `isLoopback(host:)` is a free function, and stricter than 0.1.0's private one.
  **Rationale:** the table test found `0127.0.0.1` (octal to `getaddrinfo`), `[localhost]`,
  `[127.0.0.1]` and `::1%lo0` all counted as loopback.
- **Decision:** `ClientHandshakeFailure` reads BoringSSL's packed error code, numerically,
  from an error that is structurally a BoringSSL one. **Alternative rejected:** searching
  `String(describing:)` for `CERTIFICATE_VERIFY_FAILED`, which is what both adopters did.
  **Limit:** NIOSSL keeps the code private, so it is parsed from the front of its description.
- **Decision:** a peer that closes silently is `.other`, not `.peerDoesNotSpeakTLS`.
- **Decision:** the in-memory identity entry points in `SwiftTLSKit` are `package`.
  **Rationale:** a server's context still comes only from files, with the permission check.
- **Decision:** `SwiftTLSKitTestSupport` takes an injected generator and ships none.
  **Rationale:** the gate's determinism rule for `Sources/`; "do not write another seeded
  generator" for the rest.

## 3. Work Completed

### Design Proposal
- [ ] No design proposal document was written. The nine items arrived as a specification
  from the adopters; the decisions above were made during implementation and are recorded in
  Design Notes. **Not reviewed by the owner before implementation.**

### Tests

131 tests in 11 suites (was 85 in 7).

**Seen red by assertion before the implementation existed or was correct:**

| Change | How it was red |
|---|---|
| Stricter loopback, via `BindExposure` | six new cases failed against the existing classifier |
| `isLoopback(host:)` table | function first published with the old logic; five cases failed |
| `IncompleteServerIdentity` messages, `missing` | type first written with the old wording and a wrong `missing`; ten failures |
| Key-only change under `reloadIfChanged` | failed against 0.1.0's chain-only comparison |
| Key digest not reachable | digest first stored as a plain `[UInt8]`; three failures; then the redacting type |
| `ReloadMode` in `reloadOnEach` and `reload(_:)` | overload first written calling `reloadIfChanged`; three failures |
| `suggestedLogLevel`, raw values, ordering | stub returning `.info`, cases out of order, `<` false; six failures |
| `ClientHandshakeFailure` — every class, and the migrated handshake and pinning tests | stub returning `.other(text)` for everything; about thirty failures, which also showed the real error text for each class |

**Not seen red by assertion:**

| Change | Why | How it was checked |
|---|---|---|
| swift-crypto range | a manifest requirement has no assertion | resolved to 4.5.2 and the suite run; library built against exactly 3.0.0 in a scratch copy |
| tvOS / visionOS | likewise | `xcodebuild -destination generic/platform=…` for iOS, tvOS, visionOS, both schemes; `vtool` shows minos 17.0 / 17.0 / 1.0 |
| `SwiftTLSKitTestSupport` (14 of its 17 tests) | the product was ported from the suite's own support code *before* its tests were written, so they passed at once | four mutations, each caught: reversed byte order (4 failures), unmasked serial (1), default start inside the 825-day rule (3), `replace` a no-op (6) |
| The suite's SplitMix64 | written with its reference test | outputs are the published values for seed 1234567, also recomputed in Python |
| "No message mentions plaintext" for `description(certificateChainSetting:…)` | red only through the staged wording | — |
| `consultsSystemRoots`, `wrongHostname(under:)` | red against stubs returning `false` / `.other("")` | — |
| The main product does not link swift-certificates | not a unit test | a scratch consumer of `SwiftTLSKit` alone: 0 symbols from module `X509`; a consumer of the test-support product: 11066 |

**One test that failed when it was expected to pass, and was right:** the 825-day test first
asserted that a leaf dated one second before 2019-07-01T00:00:00Z is accepted. It is refused.
Bisecting with real handshakes put Apple's line at 2019-06-30T23:00:00Z (macOS 27.0.1, a
UTC−4 machine, so not local midnight). The test now uses 2 July 2019 for the refused leaf and
the default dates for the accepted one, and does not pin Apple's constant.

**Deterministic seeds:** the suite's authorities come from `SeededGenerator` (SplitMix64) with
`TestSeed.authority` and `TestSeed.stranger`. This is new: 0.1.0's tests used the system's
randomness implicitly. The gate refuses `SystemRandomNumberGenerator` in test code once it is
named, which the injected generator made necessary.

**Stability:** `swift test` run three times after each of the handshake-classifier and
test-support changes, and again at the end; all green each time.

### Documentation
- [x] DocC on every public symbol in both targets
- [x] Articles updated: Serving TLS, Reloading Without Restarting (Triggers, the SIGHUP
  snippet, "What changed means"), Connecting as a Client ("When the handshake fails", the
  Apple hostname table), Design Notes ("What the first adopters changed")
- [x] README: HTTPS and SSH, `.upToNextMinor`, two products, and usage for every item
- [x] CHANGELOG `[Unreleased]`, stating the intended version in prose, with migration notes
  naming what each adopter can delete
- [x] master plan, capability map, CLAUDE.md

## 4. Mandatory Quality Gate (Zero Tolerance)

`quality-gate --check all --strict` by the pre-commit hook on every commit, and with
`--release-boundary` by the pre-push hook. No suppression comments, no excluded checkers, no
`--no-verify`, no `QG_SKIP`.

| Check | Status |
| :--- | :--- |
| **build** | ✅ 0 warnings |
| **test** | ✅ 131 passing |
| **doc-coverage** | ✅ 100% |
| **all 46 checkers** | ✅ 0 errors, 0 warnings |

### Findings fixed along the way
- **logging**: `try?` around `P256.Signing.PrivateKey(rawRepresentation:)` in the test-support
  key loop. Rewritten as `Result { … }` with the reason the error is not kept.
- **test-quality (`unseeded-random`)**: `SystemRandomNumberGenerator()` at every
  `TestAuthority` in the suite — 12 warnings. Fixed by seeding, which has the consequence
  below.
- **status**: the plan needed `- [x] SwiftTLSKitTestSupport` for the new target.

## 5. Project State Updates

- [x] `project/master_plan.md`: reconciled; Phase 3 added; "nothing has adopted it" corrected
- [x] `project/capability_map.md`: Test support section
- [x] No checklist was created

## 6. Next Session Handover (Context Recovery)

### Immediate Starting Point

Review and merge the pull request, then `git tag -a 0.2.0` (the existing tag is `0.1.0`, with
no `v`) and rename the CHANGELOG's `[Unreleased]` section to `[0.2.0]` in the same step —
the pre-push hook refuses a CHANGELOG version with no tag, which is why the section is still
"Unreleased" on the branch. Add the `[0.2.0]` link reference at the bottom of the CHANGELOG.

The same checker refuses a README whose install snippet names a version with no tag. So the
README on this branch still says `.upToNextMinor(from: "0.1.0")` while describing the new
API. **Change that to `"0.2.0"` in the tagging step too** — it is the one line in the README
that is knowingly behind.

### Pending Tasks

- [ ] Merge, tag 0.2.0, update the CHANGELOG heading and link references and the README's
  install snippet.
- [ ] Move IconquerServer and IconquerClient to 0.2.0; the CHANGELOG lists what each deletes.
  Both declare `from: "0.1.0"`, which admits 0.2.0 and its source break at the next
  `swift package update`; change to `.upToNextMinor(from: "0.2.0")` when moving.
- [ ] The adopters' gates will refuse `SystemRandomNumberGenerator()` in their tests as this
  one did. They can use SwiftDeterminism's generator; this package could not.
- [ ] Linux build and test (unchanged).

### Blockers

None.

### Context Loss Warning

- **This suite's test keys are reproducible from `TestSeed`.** That is deliberate and safe
  only because nothing outside a test trusts a test authority. Do not reuse `TestAuthority`
  with a fixed seed for anything a real client is configured to trust.
- **Two rules collided.** "No dependency on the owner's other packages" (this project) and
  "do not write another seeded generator, use SwiftDeterminism" (the guidelines). The first
  won: there is a SplitMix64 in `Tests/SwiftTLSKitTests/Support/SeededGenerator.swift`, in the
  test target only, pinned to the reference outputs. The owner may prefer the other answer.
- **Apple's 825-day line is 2019-06-30T23:00:00Z**, not midnight UTC on 1 July. Measured, not
  documented by Apple that this session could find.
- `ClientHandshakeFailure` depends on NIOSSL printing BoringSSL's packed code first in an
  error's description. If a swift-nio-ssl update turns the classifier tests red, that is the
  first place to look, and the test "A peer that closes without answering…" pins NIOSSL's
  wording on purpose so that such a change is noticed.
- A consumer of `SwiftTLSKit` alone still *fetches* swift-certificates. It does not build it.
