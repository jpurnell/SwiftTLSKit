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
- **Platforms:** macOS 14+, iOS 17+. Built for macOS arm64 and x86_64 and generic iOS; tested
  on macOS arm64. Linux is not declared and has not been built.
- **Dependencies:** swift-nio 2.102.0+ (`NIOCore`, `NIOConcurrencyHelpers`, `NIOTLS`),
  swift-nio-ssl 2.37.4+ (`NIOSSL`), swift-crypto 3+ (`Crypto`, for SHA-256).
  Test-only: swift-certificates, swift-asn1, `NIOPosix`.
- **No dependency on any other package of the owner's, and no logging dependency.**

### Module Structure

```
Sources/SwiftTLSKit/
├── ServerIdentity.swift          the two paths; resolve(…) and load(now:)
├── ServerIdentityError.swift     every refusal, typed, with its message
├── PEMFile.swift                 open / fstat / read, with the permission check (internal)
├── CertificateSummary.swift      names, validity, SHA-256 fingerprints
├── ServerTLSContext.swift        MinimumTLSVersion, ServerTLSOptions, ServerTLSContext
├── ReloadableServerTLS.swift     the current context, reload(), ReloadOutcome
├── ClientTrust.swift             CertificateSource, ClientTrust, resolution of roots
├── ClientTrustError.swift        every client-side refusal
├── ClientTLSContext.swift        the client context and its handlers
├── CertificatePin.swift          a SHA-256 pin on a certificate or public key
├── PinVerificationHandler.swift  checks the pin after the handshake (internal)
├── BindExposure.swift            loopback / exposed plaintext classification
├── IPAddressLiteral.swift        IPv4 / IPv6 literal parsing (internal)
└── SwiftTLSKit.docc/             landing page and four articles
```

### Key Types

| Type | Purpose |
|------|---------|
| `ServerIdentity` | Names a PEM certificate chain and private key; `resolve` turns two optionals into nil, an identity, or `incompletePair` |
| `LoadedServerIdentity` | An identity read from disk and found fit to serve; the only input a server context accepts |
| `ServerIdentityError` | Typed refusals: half pair, unreadable, not a regular file, too large, key permissions, empty or damaged chain, damaged key, key mismatch, expired, not yet valid |
| `CertificateSummary` | Leaf subject alternative names, validity, certificate and public-key SHA-256 |
| `ServerTLSOptions`, `MinimumTLSVersion` | TLS 1.2 minimum (or 1.3 only), ALPN list |
| `ServerTLSContext` | The server `NIOSSLContext` and `addHandler(to:)` |
| `ReloadableServerTLS`, `ReloadOutcome` | Owns the current context; `reload()`, `reloadIfChanged()`, `reloadOnEach(_:report:)` |
| `ClientTrust`, `CertificateSource` | System roots, additional roots, only roots, or pinned — never "trust anything" |
| `CertificatePin` | SHA-256 of a certificate or of its SubjectPublicKeyInfo |
| `ClientTLSContext` | The client context; `addHandlers(to:serverHostname:)` with SNI and hostname verification |
| `ClientTrustError` | Typed client refusals, including `pinMismatch` |
| `BindExposure` | Classifies a bind host and TLS flag as TLS, loopback plaintext, or exposed plaintext |

### Data Flow

```
Server
  --tls-cert? --tls-key?
        │  ServerIdentity.resolve            nil ─▶ plaintext ─▶ BindExposure.classify
        ▼                                    throws incompletePair for one of two
  ServerIdentity
        │  load(now:)                        throws ServerIdentityError
        ▼
  LoadedServerIdentity ─▶ ServerTLSContext ─▶ ReloadableServerTLS.current
                                                   │ addHandler(to:)   per connection
                                                   ▼
                                             NIOSSLServerHandler
  reload() / reloadIfChanged() ─▶ load + build ─▶ swap, or keep the old one and return the error

Client
  ClientTrust ─▶ ClientTLSContext ─▶ addHandlers(to:serverHostname:)
                                        ├─ NIOSSLClientHandler   (chain + hostname, always)
                                        └─ PinVerificationHandler (pinned trust only)
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
9. **Test certificates are generated when the tests run.** No private key is checked in.

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

### What's Next
- [ ] First adopter (see Roadmap, Phase 2). Nothing depends on this package yet.
- [ ] Build and test on Linux, then declare it.

### Known limits
- Not built or tested on Linux.
- No mutual TLS; no encrypted private keys; the key's owner is not checked, only its mode.
- `CertificateSummary.subjectAlternativeNames` depends on NIOSSL's underscored
  `_subjectAlternativeNames()`.
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

### Phase 2: Adoption — none started
In this order. Each replaces a hand-written copy; none has been touched.
- [ ] IconquerServer
- [ ] IconquerClient
- [ ] SwiftMCPServer — replaces the `if let certPath, let keyPath` block in
  `HTTPServerTransport.connect()`, which serves plaintext when given one of the two
- [ ] VaultMCP web — replaces the second copy in `VaultMCPWebMain/main.swift`
- [ ] IconquerTournament
- [ ] SwiftMCPClient — `ServerTrust` maps onto `ClientTrust` case for case; its AsyncHTTPClient
  path takes `makeTLSConfiguration()`

Before the first server adopts it: confirm on the deployment host that every deployed
`privkey.pem` is mode `0600`. `renew-certs.sh` installs them that way; a copy left by the
script it replaced would be `0644` and is refused.

### Future
- Linux: build, test, declare.
- Client certificates (mutual TLS) on the server side.
- A CI workflow, if the repository gains a second contributor or a self-hosted runner.

---

**Last Updated:** 2026-10-06 (0.1.0: architecture, type table, status and roadmap written
against the shipped code; Phase 1 struck through as shipped; adoption listed as not started)
