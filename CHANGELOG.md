# Changelog

All notable changes to SwiftTLSKit will be documented in this file.

## [Unreleased]

### Added
- `BindExposure`, a pure classification of a bind host and whether TLS is configured:
  `tls`, `loopbackPlaintext`, or `exposedPlaintext(host:)`. It decides nothing; whether
  exposed plaintext is a warning or a refusal belongs to the server that asked.

[Unreleased]: https://github.com/jpurnell/SwiftTLSKit/commits/main
