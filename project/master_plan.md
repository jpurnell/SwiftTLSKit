# SwiftTLSKit Master Plan

**Purpose:** Source of truth for project vision, architecture, and goals.

---

## Project Overview

### Mission
Hold the TLS configuration that was duplicated across the owner's SwiftNIO servers and
clients — which files are a server identity, what makes them unfit to serve, how a running
server takes a renewed certificate, and what a client is prepared to trust — so that it is
written, tested and corrected in one place.

### Target Users
- The owner's NIO servers and clients. Seven packages in the owner's workspace depend on 0.2.1
  (checked 2026-11-13, each `.upToNextMinor(from: "0.2.1")`): FleetWatch, FleetWatch-infoplist,
  ijs-dashboard-server, SwiftHTTPService, SwiftPushHub, SwiftDiagnosticsHub, SwiftPenTest.
- Named in the original plan and **not checked on 2026-11-13** (not in the workspace):
  SwiftMCPServer, VaultMCP's web view, IconquerServer, IconquerTournament, IconquerClient,
  SwiftMCPClient. IconquerServer and IconquerClient adopted 0.1.0 on 2026-10-06.

### Key Differentiators
- **A half-configured identity is an error, never plaintext.** The copies this replaces built
  a TLS context only `if let certPath, let keyPath`, so passing one of the two served
  plaintext without a word.
- **Refusals are typed and name the path, never the contents.**
- **No way to switch verification off.** The client API has no "trust anything" case.
- **Configuration only.** No sockets, no event loops, no listener framework.

---

## Architecture

### Technology Stack
- **Language:** Swift 6.2+ (tools-version 6.2, matching every sibling package)
- **Build System:** Swift Package Manager
- **Testing:** Swift Testing framework
- **Concurrency:** Swift 6 strict concurrency throughout; no `@unchecked Sendable`, no
  `nonisolated(unsafe)`
- **Platforms:** macOS 14+, iOS 17+, tvOS 17+, visionOS 1+. Tested on macOS arm64; both
  products built for generic iOS, tvOS and visionOS devices with `xcodebuild`. Built and tested
  on Linux (x86_64 and arm64; Swift 6.2 and latest) by CI since 2026-11-11.
- **Products:** `SwiftTLSKit` (the library) and `SwiftTLSKitTestSupport` (for consumers' test
  targets).
- **Dependencies of `SwiftTLSKit`:** swift-nio 2.102.0+ (`NIOCore`, `NIOConcurrencyHelpers`,
  `NIOTLS`), swift-nio-ssl 2.37.4+ (`NIOSSL`), swift-crypto 3.0.0..<5.0.0 (`Crypto`, for
  SHA-256).
- **Dependencies of `SwiftTLSKitTestSupport` only:** swift-certificates, swift-asn1. They were
  test-only until the test-support product; the library target still must not import them.
  This package's own tests add `NIOPosix` and `NIOEmbedded`.
- **Public interface and NIO:** the NIO types left in it are `ChannelPipeline.SynchronousOperations`,
  `any ChannelHandler`, and NIOSSL's `TLSConfiguration` in `ClientTrust.makeTLSConfiguration`.
  A move to NIO 3 or NIOSSL 3 would be package 2.0 (`StabilityPolicy.md`).
- **Repository:** public since 2026-11-13, so that CI runs on GitHub's hosted runners.
- **No dependency on any other package of the owner's, and no logging dependency.** The first
  is why the test-support product ships its own seeded generator (`SeededGenerator`) rather
  than using SwiftDeterminism. (Until 2026-10-09 this read "the suite carries its own": the
  generator was a file in the test target, and each adopter had copied it.)

### Module Structure

```
Sources/SwiftTLSKit/
├── ServerIdentity.swift            the two paths; resolve(…), load(now:), in-memory validation (package)
├── IncompleteServerIdentity.swift  the one thing resolve throws
├── ServerIdentityError.swift       every refusal load makes, typed, with its message
├── PEMFile.swift                   open / fstat / read, with the key's mode, owner, ACL (macOS)
│                                   and ancestor-directory checks (internal)
├── DERSubjectAlternativeNames.swift  reads DNS names and addresses from a certificate's DER (internal)
├── PrivateKeyFileDigest.swift      what the key file held, comparable and unprintable (internal)
├── CertificateSummary.swift        names, validity, SHA-256 fingerprints
├── ServerTLSContext.swift          MinimumTLSVersion, ServerTLSOptions, ServerTLSContext
├── ReloadableServerTLS.swift       the current context, ReloadMode, reload, ReloadOutcome
├── SuggestedLogLevel.swift         info / notice / warning, with no logging dependency
├── ClientTrust.swift               CertificateSource, ClientTrust, resolution of roots
├── ClientTrustError.swift          every client-side refusal
├── ClientTLSContext.swift          the client context and its handlers
├── ClientHandshakeFailure.swift    classifies an error from a failed client handshake
├── CertificatePin.swift            a SHA-256 pin on a certificate or public key
├── PinVerificationHandler.swift    checks the pin after the handshake (internal)
├── BindExposure.swift              TLS / loopback plaintext / exposed plaintext
├── Loopback.swift                  isLoopback(host:), the one definition
├── IPAddressLiteral.swift          IPv4 / IPv6 literal parsing (internal)
└── SwiftTLSKit.docc/               landing page and five articles (Serving, Reloading, Client,
                                    DesignNotes, StabilityPolicy)

Sources/SwiftTLSKitTestSupport/
├── TestAuthority.swift             an authority, and the leaves it issues
├── TestLeaf.swift                  a leaf, its PEM and digests, serverContext(options:now:)
├── TestInstant.swift               the fixed dates, and why they are those dates
├── TestKeyMaterial.swift           the injected generator; TestCertificateError
├── SeededGenerator.swift           SplitMix64 for a test to seed; not for secrets
└── InMemoryServerIdentity.swift    a renewable identity and a reloader, with no files
```

### Key Types

| Type | Purpose |
|------|---------|
| `ServerIdentity` | Names a PEM certificate chain and private key; `resolve` turns two optionals into nil, an identity, or a thrown `IncompleteServerIdentity` |
| `IncompleteServerIdentity` | Half a pair: which half was given, its path, and a message that can name the consumer's own settings |
| `LoadedServerIdentity` | An identity read from disk and found fit to serve; the only input a server context accepts |
| `ServerIdentityError` | Typed refusals from loading: unreadable, not a regular file, too large, key permissions, key owned by another user, key in a writable directory, key with an ACL (macOS), empty or damaged chain, damaged key, key mismatch, expired, not yet valid |
| `CertificateSummary` | Leaf subject alternative names (DNS and addresses; IPv6 as RFC 5952), validity, certificate and public-key SHA-256 |
| `ServerTLSOptions`, `MinimumTLSVersion` | TLS 1.2 minimum (or 1.3 only), ALPN list |
| `ServerTLSContext` | The server context and `makeHandler()` / `addHandler(to:)`. The `NIOSSLContext` is `package`-level |
| `ReloadableServerTLS`, `ReloadMode`, `ReloadOutcome` | Owns the current context; `reload()`, `reloadIfChanged()` (chain and key file), `reloadOnEach(_:mode:report:)` |
| `SuggestedLogLevel` | What `ReloadOutcome.suggestedLogLevel` returns: info, notice, warning |
| `ClientTrust`, `CertificateSource` | System roots, additional roots, only roots, or pinned — never "trust anything" |
| `CertificatePin` | SHA-256 of a certificate or of its SubjectPublicKeyInfo |
| `ClientTLSContext` | The client context; `addHandlers(to:serverHostname:)` with SNI and hostname verification |
| `ClientTrustError` | Typed client refusals, including `pinMismatch` and `noPeerCertificate` |
| `ClientHandshakeFailure` | Classifies a failed client handshake: not trusted, hostname mismatch, pin mismatch, peer does not speak TLS, no shared version, other |
| `BindExposure` | Classifies a bind host and TLS flag as TLS, loopback plaintext, or exposed plaintext |
| `isLoopback(host:)` | The one definition of loopback, for a bind host or a dial host |
| `TestAuthority`, `TestLeaf`, `TestInstant` (test support) | Certificates generated when tests run, from an injected generator, dated before Apple's 825-day rule |
| `InMemoryServerIdentity` (test support) | A server context and a renewable reloader built from memory |
| `SeededGenerator` (test support) | SplitMix64 from a seed, for `TestAuthority`'s `generator:`; predictable by design, never for a secret |

### Data Flow

```
Server
  --tls-cert? --tls-key?
        │  ServerIdentity.resolve            nil ─▶ no identity ─▶ BindExposure.classify ─▶ the server decides
        ▼                                    throws IncompleteServerIdentity for one of two
  ServerIdentity
        │  load(now:)                        throws ServerIdentityError
        ▼
  LoadedServerIdentity ─▶ ServerTLSContext ─▶ ReloadableServerTLS.current
                                                   │ addHandler(to:)   per connection
                                                   ▼
                                             a TLS handler (any ChannelHandler)
  reload() / reloadIfChanged() ─▶ load + build ─▶ swap, or keep the old one and return the error
  reloadOnEach(triggers, mode:)  ─▶ one of the two per trigger; outcome.suggestedLogLevel

Client
  isLoopback(host:) ─▶ may this host be dialled in plaintext?   (the client decides)
  ClientTrust ─▶ ClientTLSContext ─▶ addHandlers(to:serverHostname:)
                                        ├─ NIOSSLClientHandler   (chain + hostname, always)
                                        └─ PinVerificationHandler (pinned trust only)
  an error before the handshake completes ─▶ ClientHandshakeFailure(error)

Tests (a consumer's, and this package's)
  generator ─▶ TestAuthority ─▶ TestLeaf ─▶ serverContext(now:)            in memory
                    │               └────▶ InMemoryServerIdentity ─▶ reloadableServerTLS(now:)
                    └─▶ clientContext()
```

---

## Core Architectural Decisions

1. **Configuration, not a listener framework.** The package produces values and NIO handlers;
   the consumer keeps its own bootstrap.
2. **A server context can only be built from a loaded identity**, so no path from two strings
   to a TLS listener skips validation.
3. **Time is a parameter.** Nothing in the library reads the clock; validity checks take the
   current time from the caller.
4. **Errors are typed and carry paths, never file contents.** The key's parse error is
   discarded rather than wrapped.
5. **No logging in the library.** It returns describable values; the consumer logs them.
6. **The reloader is a class with a lock, not an actor**, because a channel initializer is
   synchronous.
7. **No file watcher.** Triggers are explicit; see the Reloading article for why.
8. **A pin is an additional check after the handshake**, because NIOSSL's verification
   callback replaces chain validation rather than adding to it. (NIOSSL also has an
   additional-verification callback that runs before the handshake completes, which would close
   the window; it is `_`-prefixed, the same fragility decision 20 avoids. The window leaks
   nothing: the handler holds every write and releases no read until the pin has matched.)
9. **Test certificates are generated when the tests run.** No private key file is checked in.
10. **An error type is exactly as wide as what throws it.** `resolve` throws
    `IncompleteServerIdentity`; `ServerIdentityError` holds only what loading can refuse.
    (0.1.0 had one type for both. Adopters showed why that was wrong.)
11. **A message says only what is true for every consumer.** The half-pair message does not
    say what happens with neither half, because that is the consumer's decision.
12. **"Unchanged" means both files.** Change detection covers the key file, by a digest that
    can be compared and cannot be printed.
13. **A trigger's meaning is stated at the call site.** `reloadOnEach` takes a `ReloadMode`
    with no default.
14. **In-memory identities are for tests.** The entry points are `package`, reached through
    `SwiftTLSKitTestSupport`; a server's key is on disk and the permission check is the point.
15. **The package has no randomness of its own.** Test support takes the caller's generator.
    It ships one a caller may construct, `SeededGenerator`, and constructs none itself.
16. **BoringSSL's errors are read from an error that is structurally one** — not by searching
    an error's text for a reason name. *Amended 2026-11-13:* first by the packed code alone;
    now by the code **and** the reason name, because NIOSSL has no typed path (investigated:
    `BoringSSLInternalError` keeps both private, and cannot be constructed outside NIOSSL) and
    BoringSSL renumbers reasons. The name is read by position (the fifth `:` field, its first
    word, compared whole), not searched for. Where the two disagree the answer is `other`.
17. **A private key is refused if somebody else can replace it, not only if somebody else can
    read it.** Owner, writable ancestor directory, and (macOS) ACL, each typed. Chosen over a
    documented limit because a key at `0600` that another user can swap serves their identity
    at the next reload. It can refuse a server that used to start; the message says how to fix it.
18. **Enumerations are closed.** A new case is a major version; a new capability (client
    certificates, encrypted keys) arrives as a new type. The last cases were added before
    1.0. The text of a `description` is not API.
19. **The public interface names as little of NIO as it can.** NIOSSL's context and parsed
    certificates are `package`-level; handlers are `any ChannelHandler`. `makeHandlers` is
    `package`, since a pinned trust has two handlers and a caller who added one lost the pin.
20. **Certificate names are read from the DER, here, not from NIOSSL's underscored API and not
    with swift-certificates in the library target.** A bounded reader with no recursion; its
    tests compare it with swift-certificates. A name that cannot be printed safely is left out.
21. **CI builds and tests; the quality gate stays a local hook.** `quality-gate` is the owner's
    tool and is not installed on runners.

The reasoning for each, and where the code forced a deviation from the first design, is in
`Sources/SwiftTLSKit/SwiftTLSKit.docc/DesignNotes.md`.

---

## Current Status

### What's Working
- [x] SwiftTLSKit
- [x] SwiftTLSKitTestSupport
- [x] Vendored guidelines, hooks, gate configuration
- [x] `BindExposure`
- [x] `ServerIdentity.resolve` and `load(now:)`, with every refusal typed and tested
- [x] `ServerTLSContext` and the one-line pipeline helper
- [x] `ReloadableServerTLS`: reload, reload-if-changed, trigger loop
- [x] `ClientTrust` (system, additional, only, pinned) and `ClientTLSContext`
- [x] Loopback handshake tests between the package's own server and client halves
- [x] DocC catalogue with four articles; README; CHANGELOG
- [x] 0.1.0
- [x] First adopters: IconquerServer (`feat/tls`, PR #4) and IconquerClient (`feat/wss`, PR #2)
  moved to 0.1.0
- [x] Adopter feedback, on `feat/adopter-feedback` — released as **0.2.0**, 2026-10-06:
  - [x] swift-crypto 3.0.0..<5.0.0
  - [x] `reloadIfChanged` covers the key file; `ReloadMode`; `reloadOnEach(_:mode:report:)`
  - [x] `IncompleteServerIdentity` (source break)
  - [x] `isLoopback(host:)`
  - [x] `ClientHandshakeFailure`
  - [x] `SwiftTLSKitTestSupport`
  - [x] tvOS 17, visionOS 1
  - [x] `ReloadOutcome.suggestedLogLevel`
- [x] **0.2.1**, 2026-10-09:
  - [x] The stated reason for refusing a leading-zero octet corrected (`inet_aton` is the
    octal reader, not `getaddrinfo`); the rule itself pinned by a test that names no resolver
  - [x] `SeededGenerator` in `SwiftTLSKitTestSupport`
- [x] **Readiness for 1.0, 2026-11-11 to 2026-11-13** (`project/plans/upcoming/SwiftTLSKit-1.0-readiness.md`):
  - [x] CI on Linux (x86_64, arm64; Swift 6.2 and latest), macOS, and iOS/tvOS/visionOS device
    builds (PR #4). Linux needed no source change.
  - [x] Subject alternative names read from the DER, not NIOSSL's underscored API (PR #5)
  - [x] `ClientHandshakeFailure` reads the reason name as well as the number (PR #6)
  - [x] Independent security review: a fail-open in `isLoopback` for a host with a NUL byte,
    fixed, and four more (PR #7; `security_review_1.0.md`)
  - [x] A key is refused for owner, writable ancestor directory, or an ACL; `noPeerCertificate`;
    the NIO surface narrowed; the enums closed (PR #8; `api_audit_1.0.md`)
  - [x] `StabilityPolicy.md`; this reconciliation
  - [x] Tagged `1.0.0-beta.1`, 2026-11-13

### What's Next
- [x] ~~First adopter (see Roadmap, Phase 2). Nothing depends on this package yet.~~ — seven
  packages depend on 0.2.1 (see Target Users).
- [x] ~~Merge `feat/adopter-feedback`, tag 0.2.0~~ (done 2026-10-06)
- [x] ~~Move the two adopters to it~~ — every adopter found on 2026-11-13 is on 0.2.1.
- [x] ~~Tag `1.0.0-beta.1`~~ — done 2026-11-13. Adopters do not receive it until they ask for it:
  a prerelease is never selected by `.upToNextMinor(from: "0.2.1")`.
- [ ] Move the adopters to the beta, one at a time, and record what each finds. **The criterion
  for 1.0.0** is that every adopter that has moved reports nothing that needs a source change
  to this package, and the security review's decisions still hold. Findings that would need a
  new case in a closed enum are the reason to keep the beta open.
- [x] ~~Build and test on Linux, then declare it.~~ Done 2026-11-11 (PR #4): all four Linux jobs
  green first time, 135 tests. The plan had expected failures to fix; there were none.

### Known limits
- ~~Not built or tested on Linux.~~ Built and tested in CI (2026-11-11). One branch is still
  unrun on Linux: see `ClientHandshakeFailure.wrongHostname(under:)` below.
- No mutual TLS; no encrypted private keys.
- ~~The key's owner is not checked, only its mode.~~ Checked, with every ancestor directory's
  write bits and (macOS) an ACL. **Not** checked: who *owns* those directories (a directory owned
  by another user and not writable by anyone else still lets its owner replace the key); the
  certificate chain at all (it is public). A leaf written without its intermediates is served
  until the next reload; the remedy is to rename a finished file into place, as certbot does.
- ~~`CertificateSummary.subjectAlternativeNames` depends on NIOSSL's underscored
  `_subjectAlternativeNames()`.~~ Read from the certificate's DER by `DERSubjectAlternativeNames`
  instead (PR #5, in 1.0.0-beta.1).
- ~~`ClientHandshakeFailure.wrongHostname(under:)` has a non-Apple branch that nothing here has
  run.~~ Run on Linux in CI since 2026-11-11: the wrong-hostname test expects
  `.hostnameMismatch` there, and passes on all four Linux jobs.
- `ClientHandshakeFailure` reads BoringSSL's error from the *text* of NIOSSL's description (the
  packed number and the reason name), because NIOSSL keeps both private. If NIOSSL changes the
  format of both, the result is `.other(description)`, never a wrong class; the handshake tests
  catch it, the compiler does not.
- A consumer of `SwiftTLSKit` alone still *resolves* swift-certificates and swift-asn1 —
  SwiftPM declares dependencies per package. It does not build or link them.
- This suite's test keys are reproducible from a seed in the repository (the gate requires a
  seeded generator in tests). They are trusted by nothing outside a test.
- ~~No CI workflow.~~ CI builds and tests on GitHub (since 2026-11-11). It does not run
  `quality-gate`, which is the owner's tool; the local hooks run the full gate on every commit
  and push. The repository is public (2026-11-13) so that hosted runners are available.
- Pinning is judged after the handshake, not during it (decision 8).

---

## Quality Standards

### Code Quality
- All code follows `coding_rules.md`
- TDD: failing tests before implementation
- Documentation for all public APIs
- No warnings in build output
- Quality gate: 0 errors, 0 warnings before every commit

### Documentation Quality
- DocC comments for all public functions
- Usage examples in documentation
- Articles for complex topics

---

## Collaboration Principles

### AI as Sparring Partner, Not Oracle

AI proposes; the human interrogates. High AI confidence triggers harder questions, not faster acceptance.

- **Interrogate confident outputs.** When the AI states something with certainty, ask for the counterargument before accepting.
- **Demand counterarguments.** Before locking in an approach, require an explicit case for the strongest alternative.
- **Sit with discomfort.** Resist the pull to take the first plausible answer.

This principle is operationalized in the **Adversarial Review** step of `design_proposal.md`.

---

## Roadmap

### Phase 1: 0.1.0 — the package
- [x] ~~Server identity, server context, reload, client trust, bind exposure~~ — shipped in
  0.1.0, 2026-10-06.

### Phase 2: Adoption — seven packages on 0.2.1 (checked 2026-11-13)
Each replaces a hand-written copy. (This heading read "none started" when 0.1.0 was tagged,
and "two of six started" until 2026-11-13, when the manifests were read.) Seven packages in the
workspace are on 0.2.1: FleetWatch, FleetWatch-infoplist, ijs-dashboard-server, SwiftHTTPService,
SwiftPushHub, SwiftDiagnosticsHub, SwiftPenTest. The items below are the packages named in the
original plan, **not checked** on that date:
- [ ] IconquerServer — started: on 0.1.0 on `feat/tls` (PR #4), 2026-10-06. Open until it is
  on 0.2.0, where it can delete the workarounds it wrote for 0.1.0.
- [ ] IconquerClient — started: on 0.1.0 on `feat/wss` (PR #2), 2026-10-06. Likewise.
- [ ] SwiftMCPServer — replaces the `if let certPath, let keyPath` block in
  `HTTPServerTransport.connect()`, which serves plaintext when given one of the two
- [ ] VaultMCP web — replaces the second copy in `VaultMCPWebMain/main.swift`
- [ ] IconquerTournament
- [ ] SwiftMCPClient — `ServerTrust` maps onto `ClientTrust` case for case; its AsyncHTTPClient
  path takes `makeTLSConfiguration()`

Before a server moves to the beta: confirm on the deployment host that every deployed
`privkey.pem` is mode `0600`, **owned by the user the service runs as (or root)**, and in a
directory that only its owner can write (the key's own directory and every one above it).
`renew-certs.sh` installs them `0600`; a copy left by the script it replaced would be `0644`
and is refused. The owner and directory checks are new in the beta and can refuse a key that
loaded before.

### Phase 3: What the first adopters found — done on `feat/adopter-feedback`, unreleased
The plan for 0.1.0 did not have this phase. It assumed the API was right until an adopter
said otherwise, and two said otherwise the same day. Recorded as they reported it:
- [x] ~~`from: "3.0.0"` for swift-crypto excluded 4.x and downgraded a consumer~~
- [x] ~~A reload on a signal could report "unchanged" after a renewal; the documented SIGHUP
  snippet was built on it~~ — fixed both ways: detection covers the key file, and the trigger
  loop takes an explicit mode. The original claim that a *renewal could be missed* did not
  hold on inspection — a key that is not the leaf's is refused, so a new key implies a new
  chain — and the fix is recorded as what it is: "unchanged" now means both files.
- [x] ~~`resolve` threw the whole `ServerIdentityError` and promised plaintext~~ — a source
  break, taken deliberately.
- [x] ~~Both adopters used `BindExposure.classify` to ask "is this loopback", one of a dial
  host~~ — and writing the table found the definition too loose (`0127.0.0.1`, `[localhost]`,
  `::1%lo0`).
- [x] ~~The handshake classifier was test-only, so both re-derived it~~
- [x] ~~Both copied the test certificates and wrote keys to disk to get a server context~~
- [x] ~~tvOS and visionOS were not declared~~
- [x] ~~An adopter had to decide a failed reload's log level for itself~~
- [x] ~~README said the package resolves over SSH; it resolves over HTTPS too~~

### Phase 4: What the adopters found next — done on a branch, unreleased (intended 0.2.1)
- [x] ~~The documentation said `getaddrinfo` reads `0127.0.0.1` as octal~~ — an adopter
  measured it; it is `inet_aton`. The plan's own Phase 3 line above ("writing the table found
  the definition too loose") was right about the definition and silent about the reason,
  which is where the error was.
- [x] ~~Three test targets each carried a copy of SplitMix64~~ — shipped as `SeededGenerator`.
  This reverses a decision recorded at 0.2.0 ("a consumer brings its own generator"). It was
  made before anyone had brought one; all three brought the same one.

### Phase 5: 1.0 readiness — done 2026-11-13, beta pending
Planned in `project/plans/upcoming/SwiftTLSKit-1.0-readiness.md` against five gaps an outside
review named. All five shipped (Linux and CI; the underscored SAN API; the API audit and
freeze; the security review; documentation), and the review found more than the plan named:
- [x] ~~Linux: build, test, declare~~ — green first time.
- [x] ~~CI~~ — see Known limits for the one thing it does not run.
- [x] ~~`_subjectAlternativeNames()`~~ — replaced by a DER reader, which also fixed IPv6 text and
  made unprintable names safe to log.
- [x] ~~Underscored/string-parsed BoringSSL errors~~ — not in the named five; found while
  investigating the fourth. No typed path exists; both signals are now read.
- [x] ~~API audit and freeze~~ — enums closed; NIO surface narrowed.
- [x] ~~Security review~~ — one high-severity fail-open (a NUL byte in a host), found by a
  reviewer, not by the 0.2.1 tests, which had pinned every other spelling of loopback. The
  lesson recorded in the review: a table of known-bad spellings is not a review of the parser.
- [x] ~~The plan assumed adopters would auto-resolve a breaking 0.3.0~~ — wrong; every adopter
  pins `.upToNextMinor`. Recorded in the proposal where it was corrected.
- [x] ~~`1.0.0-beta.1`~~ tagged 2026-11-13. [ ] Then adopters, then `1.0.0`.

### Future
- Pinning during the handshake, if NIOSSL stabilises its additional-verification callback.
- Checking who owns the directories above a key.
- A peer-certificate fingerprint after a client handshake, without naming
  `NIOSSLClientHandler`: both this suite and IconquerServer's test client read
  `peerCertificate` and hash it themselves. Not asked for; noticed while writing the
  migration notes.
- ~~Linux: build, test, declare.~~ Shipped 2026-11-11.
- Client certificates (mutual TLS) on the server side.
- ~~A CI workflow, if the repository gains a second contributor or a self-hosted runner.~~
  Shipped 2026-11-11 despite that bar: six packages now depend on this one, which is the case
  the bar was standing in for.

---

**Last Updated:** 2026-11-13, 1.0.0-beta.1 tagged (CHANGELOG section and link references, status and What's Next ticked). Earlier the same day, reconciled for 1.0.0-beta.1 against the code on `main` after PRs #4–#8: Target Users (seven adopters read from their manifests; the rest marked unchecked), Technology Stack, module tree, type table, data flow, decisions 17–21 and 8, Current Status, What's Next (with the 1.0.0 criterion), Known limits (three struck, two added), Phase 2, new Phase 5. Also reconciled: `capability_map.md`. Not re-audited: the unchecked packages' current state. Before that: 2026-11-11, CI and Linux shipped (PR #4): Platforms, Known limits, What's Next and Future reconciled for Linux and CI only. Before that: 2026-10-09, 0.2.1 tagged (CHANGELOG section, link reference, README install line). Before that: 2026-10-09 — after 0.2.0, unreleased and intended as 0.2.1: the module tree,
type table, decision 15, Current Status and Roadmap (new Phase 4) reconciled against
`fix/loopback-reason-and-seeded-generator`, which adds `SeededGenerator` to the test-support
product and corrects the stated reason for the leading-zero rule. The "Tested on macOS arm64"
and Known limits lines were not re-audited. Previous entry:
2026-10-06, 0.2.0 tagged (CHANGELOG section, link references and README install line moved to 0.2.0); earlier the same day (adopter feedback: module structure, type
table, data flow and decisions 10–16 rewritten against the code on `feat/adopter-feedback`;
"nothing has adopted it" corrected to two adopters; Phase 2's first two items marked started,
not finished; Phase 3 added and struck through as done but unreleased; the claim in
the adopters' report that a renewal could be missed recorded as not holding. Previous entry:
0.1.0 — architecture, type table, status and roadmap written against the shipped code.)
