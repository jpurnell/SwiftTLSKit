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
- **Concurrency:** Swift 6 strict concurrency throughout
- **Platforms:** macOS 14+, iOS 17+
- **Dependencies:** swift-nio (`NIOCore`, `NIOConcurrencyHelpers`), swift-nio-ssl (`NIOSSL`),
  swift-crypto (`Crypto`, for SHA-256). Test-only: swift-certificates, swift-asn1.
- **No dependency on any other package of the owner's.**

### Module Structure

```
Sources/SwiftTLSKit/
├── BindExposure.swift        loopback / exposed plaintext classification
└── SwiftTLSKit.docc/         documentation catalogue
```

### Key Types

| Type | Purpose |
|------|---------|
| `BindExposure` | Classifies a bind host and TLS flag as TLS, loopback plaintext, or exposed plaintext |

### Data Flow

```
bind host + "is TLS configured" ──▶ BindExposure ──▶ the server decides: warn, or refuse
```

---

## Core Architectural Decisions

1. **Configuration, not a listener framework.** The package produces values and NIO handlers;
   the consumer keeps its own bootstrap.
2. **Time is a parameter.** Nothing in the library reads the clock; validity checks take the
   current time from the caller.
3. **Test certificates are generated when the tests run.** No private key is checked in.

---

## Current Status

### What's Working
- [x] SwiftTLSKit library target, vendored guidelines, hooks, gate configuration
- [x] `BindExposure`

### What's Next
- [ ] Server identity: resolving a certificate/key pair of options, and loading with refusals
- [ ] Server context and the one-line pipeline helper
- [ ] Reload without restart
- [ ] Client trust

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
- [ ] Server identity, server context, reload, client trust, bind exposure

### Phase 2: Adoption (none started)
- [ ] IconquerServer
- [ ] IconquerClient
- [ ] SwiftMCPServer
- [ ] VaultMCP web
- [ ] IconquerTournament
- [ ] SwiftMCPClient

### Future
- Client certificates (mutual TLS) on the server side.

---

**Last Updated:** 2026-10-06 (created; `BindExposure` only)
