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
- The owner's NIO servers: SwiftMCPServer, VaultMCP's web view, IconquerServer, IconquerTournament.
- The owner's NIO clients: IconquerClient, SwiftMCPClient.

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
  products built for generic iOS, tvOS and visionOS devices with `xcodebuild`. Linux is not
  declared and has not been built.
- **Products:** `SwiftTLSKit` (the library) and `SwiftTLSKitTestSupport` (for consumers' test
  targets).
- **Dependencies of `SwiftTLSKit`:** swift-nio 2.102.0+ (`NIOCore`, `NIOConcurrencyHelpers`,
  `NIOTLS`), swift-nio-ssl 2.37.4+ (`NIOSSL`), swift-crypto 3.0.0..<5.0.0 (`Crypto`, for
  SHA-256).
- **Dependencies of `SwiftTLSKitTestSupport` only:** swift-certificates, swift-asn1. They were
  test-only until the test-support product; the library target still must not import them.
  This package's own tests add `NIOPosix`.
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
├── PEMFile.swift                   open / fstat / read, with the permission check (internal)
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
└── SwiftTLSKit.docc/               landing page and four articles

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
| `ServerIdentityError` | Typed refusals from loading: unreadable, not a regular file, too large, key permissions, empty or damaged chain, damaged key, key mismatch, expired, not yet valid |
| `CertificateSummary` | Leaf subject alternative names, validity, certificate and public-key SHA-256 |
| `ServerTLSOptions`, `MinimumTLSVersion` | TLS 1.2 minimum (or 1.3 only), ALPN list |
| `ServerTLSContext` | The server `NIOSSLContext` and `addHandler(to:)` |
| `ReloadableServerTLS`, `ReloadMode`, `ReloadOutcome` | Owns the current context; `reload()`, `reloadIfChanged()` (chain and key file), `reloadOnEach(_:mode:report:)` |
| `SuggestedLogLevel` | What `ReloadOutcome.suggestedLogLevel` returns: info, notice, warning |
| `ClientTrust`, `CertificateSource` | System roots, additional roots, only roots, or pinned — never "trust anything" |
| `CertificatePin` | SHA-256 of a certificate or of its SubjectPublicKeyInfo |
| `ClientTLSContext` | The client context; `addHandlers(to:serverHostname:)` with SNI and hostname verification |
| `ClientTrustError` | Typed client refusals, including `pinMismatch` |
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
                                             NIOSSLServerHandler
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
   callback replaces chain validation rather than adding to it.
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
16. **BoringSSL's errors are read by code, from an error that is structurally one** — not by
    searching an error's text for a reason name.

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
- [x] After 0.2.0, on `fix/loopback-reason-and-seeded-generator` — unreleased, intended 0.2.1:
  - [x] The stated reason for refusing a leading-zero octet corrected (`inet_aton` is the
    octal reader, not `getaddrinfo`); the rule itself pinned by a test that names no resolver
  - [x] `SeededGenerator` in `SwiftTLSKitTestSupport`

### What's Next
- [ ] ~~First adopter (see Roadmap, Phase 2). Nothing depends on this package yet.~~ — two
  adopted 0.1.0 on 2026-10-06 and reported the nine items above.
- [x] ~~Merge `feat/adopter-feedback`, tag 0.2.0~~ (done 2026-10-06)
- [ ] Move the two adopters to it (each has a
  list of what it can delete in CHANGELOG.md).
- [ ] Build and test on Linux, then declare it.

### Known limits
- Not built or tested on Linux.
- No mutual TLS; no encrypted private keys; the key's owner is not checked, only its mode.
- `CertificateSummary.subjectAlternativeNames` depends on NIOSSL's underscored
  `_subjectAlternativeNames()`.
- `ClientHandshakeFailure.wrongHostname(under:)` has a non-Apple branch that nothing here has
  run; it states NIOSSL's documented behaviour.
- `ClientHandshakeFailure` reads BoringSSL's packed error code from the front of NIOSSL's
  description, because NIOSSL keeps the code private. A change in that format is caught by
  the handshake tests, not by the compiler.
- A consumer of `SwiftTLSKit` alone still *resolves* swift-certificates and swift-asn1 —
  SwiftPM declares dependencies per package. It does not build or link them.
- This suite's test keys are reproducible from a seed in the repository (the gate requires a
  seeded generator in tests). They are trusted by nothing outside a test.
- No CI workflow. The repository is private, the siblings' workflow needs repository secrets
  that have not been set here, and hosted macOS minutes are billed on private repositories.
  The local hooks run the full gate on every commit and push.

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

### Phase 2: Adoption — two of six started
In this order. Each replaces a hand-written copy. (This heading read "none started" when
0.1.0 was tagged.)
- [ ] IconquerServer — started: on 0.1.0 on `feat/tls` (PR #4), 2026-10-06. Open until it is
  on 0.2.0, where it can delete the workarounds it wrote for 0.1.0.
- [ ] IconquerClient — started: on 0.1.0 on `feat/wss` (PR #2), 2026-10-06. Likewise.
- [ ] SwiftMCPServer — replaces the `if let certPath, let keyPath` block in
  `HTTPServerTransport.connect()`, which serves plaintext when given one of the two
- [ ] VaultMCP web — replaces the second copy in `VaultMCPWebMain/main.swift`
- [ ] IconquerTournament
- [ ] SwiftMCPClient — `ServerTrust` maps onto `ClientTrust` case for case; its AsyncHTTPClient
  path takes `makeTLSConfiguration()`

Before the first server adopts it: confirm on the deployment host that every deployed
`privkey.pem` is mode `0600`. `renew-certs.sh` installs them that way; a copy left by the
script it replaced would be `0644` and is refused.

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

### Future
- A peer-certificate fingerprint after a client handshake, without naming
  `NIOSSLClientHandler`: both this suite and IconquerServer's test client read
  `peerCertificate` and hash it themselves. Not asked for; noticed while writing the
  migration notes.
- Linux: build, test, declare.
- Client certificates (mutual TLS) on the server side.
- A CI workflow, if the repository gains a second contributor or a self-hosted runner.

---

**Last Updated:** 2026-10-09, 0.2.1 tagged (CHANGELOG section, link reference, README install line). Before that: 2026-10-09 — after 0.2.0, unreleased and intended as 0.2.1: the module tree,
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
