# Changelog

All notable changes to SwiftTLSKit will be documented in this file.

## [Unreleased]

## [0.1.0] - 2026-10-06

First release. TLS configuration that was duplicated across SwiftMCPServer, VaultMCP's web
view and SwiftMCPClient, written once. Nothing has adopted it yet.

### Added
- `ReloadableServerTLS`, which owns the current `ServerTLSContext` and replaces it from disk
  without a restart. `reload()` validates completely before swapping; a failed reload keeps
  the previous context and returns the error as `ReloadOutcome.failed`; live connections keep
  the context they were accepted under. `reloadIfChanged()` swaps only when the chain on disk
  differs, and `reloadOnEach(_:report:)` runs it for each element of any `AsyncSequence` — a
  timer or a stream of `SIGHUP`s. There is deliberately no file watcher.
- DocC articles: Serving TLS, Reloading Without Restarting, Connecting as a Client, and
  Design Notes.
- `ClientTrust.pinned(_:additionalRoots:)` and `CertificatePin`: after the chain and hostname
  are verified as usual, the leaf must also match a pinned SHA-256 of the certificate or of
  its public key. A pin narrows trust and never widens it. It is checked by a handler directly
  after the handshake, which holds application writes until the verdict; a pinned trust
  refuses to be flattened into a bare `TLSConfiguration`, which could not enforce it.
- `ServerTLSContext`, built only from a `LoadedServerIdentity`: minimum TLS 1.2 (TLS 1.3 only
  with `ServerTLSOptions(minimumVersion: .tls13)`), optional ALPN, no client certificate
  requested. `addHandler(to:)` puts a `NIOSSLServerHandler` at the front of a pipeline.
- `ClientTrust` — `systemRoots`, `additionalRoots`, `onlyRoots` — and `ClientTLSContext`,
  whose `addHandlers(to:serverHostname:)` sets SNI and always verifies the chain and the
  hostname. There is no case that disables verification.
- `ServerIdentity`, naming a PEM certificate chain and private key.
  `ServerIdentity.resolve(certificateChainPath:privateKeyPath:)` takes the two optional
  settings a server is configured with and returns no identity when neither is present, the
  identity when both are, and throws `ServerIdentityError.incompletePair` when exactly one
  is. Half a pair is never served as plaintext.
- `ServerIdentity.load(now:)`, which reads both files and refuses, with a typed error naming
  the path: a missing or unreadable file; anything that is not a regular file; a file over
  1 MiB; a private key its group or others can read or write (checked with `fstat` on the
  descriptor that is then read); a chain with no certificate; a damaged certificate or key;
  a key that is not the leaf's; a leaf that has expired or is not yet valid at `now`.
- `CertificateSummary`: the leaf's subject alternative names, validity and SHA-256
  fingerprints, for a start-up log line.
- `BindExposure`, a pure classification of a bind host and whether TLS is configured:
  `tls`, `loopbackPlaintext`, or `exposedPlaintext(host:)`. It decides nothing; whether
  exposed plaintext is a warning or a refusal belongs to the server that asked.
- Platforms: macOS 14 and iOS 17. Built for macOS arm64 and x86_64 and for generic iOS; tested
  on macOS arm64. Linux is not declared and has not been built.

### Notes
- Dependencies: swift-nio 2.102.0+, swift-nio-ssl 2.37.4+, swift-crypto 3+ (SHA-256 for pins
  and fingerprints). swift-certificates and swift-asn1 are test-only.
- The private-key permission rule (no access for group or others) matches what
  `roseclub-ops/bin/renew-certs.sh` installs: `install -m 0600`. A key copied there by the
  script it replaced, with `cp`, is `0644` and will be refused until the next renewal
  rewrites it or it is `chmod 600`ed.

[Unreleased]: https://github.com/jpurnell/SwiftTLSKit/compare/0.1.0...HEAD
[0.1.0]: https://github.com/jpurnell/SwiftTLSKit/releases/tag/0.1.0
