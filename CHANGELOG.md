# Changelog

All notable changes to SwiftTLSKit will be documented in this file.

## [Unreleased]

### Added
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

[Unreleased]: https://github.com/jpurnell/SwiftTLSKit/commits/main
