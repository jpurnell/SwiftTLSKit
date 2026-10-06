# Design Record: SwiftTLSKit 0.1.0

| Date | Status |
| :--- | :--- |
| 2026-10-06 | Implemented in the same session it was written. **Not reviewed by the owner before implementation** — the brief fixed the scope and left the details to be decided and justified. |

## Objective

Extract the TLS configuration duplicated across the owner's servers and clients into one
package: server identity, server context, reload without restart, client trust, and a small
bind/TLS policy helper. Configuration only; not a listener framework.

## Inputs read before designing

| Source | What it showed |
|---|---|
| `SwiftMCPServer/…/Transport/HTTPServerTransport.swift` | A context built only `if let certPath, let keyPath`. One of the two serves plaintext, silently. Minimum TLS 1.2. Logs the certificate path. |
| `SwiftMCPServer/…/MCPServer.swift` | `--tls-cert` / `--tls-key` parsed into two independent optionals; the scheme is reported from the certificate path alone. |
| `VaultMCP/…/VaultMCPWebMain/main.swift` | A second copy of the same block, with the same `if let … , let …`. |
| `SwiftMCPClient/…/Transport/ServerTrust.swift` | `system` / `additionalRoots` / `onlyRoots`, no "insecure" case, roots parsed at construction, fingerprints exposed. Declines hash pins because not every transport could enforce one. |
| `roseclub-ops/bin/renew-certs.sh` | Copies with `install -m 0644` (chain) and `install -m 0600` (key), owner the service user, then restarts every service because each loads its certificate once at start-up. Its history is a list of services that were missed. |

## Decisions

Recorded with their reasoning in
`Sources/SwiftTLSKit/SwiftTLSKit.docc/DesignNotes.md`, which is the maintained copy. In brief:

1. `ServerIdentity.resolve` returns `nil`, an identity, or throws `incompletePair`.
2. `ServerTLSContext` can only be built from a `LoadedServerIdentity`.
3. Refusals are typed, carry the path and the reason, and never file contents.
4. The current time is a parameter everywhere.
5. The library has no logger.
6. `ReloadableServerTLS` is a class with a lock; reload validates fully before swapping.
7. `ClientTrust` has no case that disables verification; the hostname is non-optional.

## Adversarial review — the strongest alternatives, and why they lost

- **Return a `Result`/enum from `resolve` instead of `Optional` + `throws`.** An explicit
  `.plaintext` case reads better at the call site. Rejected narrowly: the defect was the
  half-pair, which is the thrown error; `nil` for "no TLS configured" is not ambiguous.
- **An actor for the reloader.** Rejected: a channel initializer cannot `await`.
- **A file watcher.** Rejected: two platform implementations, a guaranteed mismatch window on
  every renewal, and no way to test it without waiting.
- **Pin inside NIOSSL's verification callback.** Rejected: the callback replaces chain
  validation. The cost of the alternative chosen is that the handshake completes before the
  pin is judged; application data is held back until then.
- **Parse certificates with swift-certificates in the library.** It would give stable access
  to names and keys. Rejected to keep the library's dependencies to NIO, NIOSSL and
  swift-crypto; the price is one underscored NIOSSL API for subject alternative names.
- **Check the key's owner as well as its mode.** Deferred: under launchd the service user
  owns its copy, and a root-owned `0600` key read by a root process is legitimate.

## Deviations from the brief

- swift-crypto added as a library dependency (SHA-256 for pins and fingerprints).
- No file watcher (the brief made it conditional on being cheap and testable).
- Linux is not declared: SwiftMCPServer does not declare it, and it could not be built here.
- No CI workflow copied: the repository is private and the siblings' workflow needs
  repository secrets.
