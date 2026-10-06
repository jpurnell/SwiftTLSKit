# SwiftTLSKit Capability Map

**Purpose:** Scannable inventory of what this project can do — feature areas, key types, external interfaces, and application domains.

**Last reviewed:** 2026-10-06

> **Format reference:** See `development-guidelines/rules/capability_map.md` for field definitions,
> naming conventions, and maintenance rules.

---

## Server identity

**Key types:** `ServerIdentity`, `IncompleteServerIdentity`, `LoadedServerIdentity`, `CertificateSummary`, `ServerIdentityError`
**Interfaces:** Swift library API
**Applications:** Turning `--tls-cert` / `--tls-key` into a validated identity or a typed refusal; logging which certificate a server holds and when it expires.

## Serving TLS

**Key types:** `ServerTLSContext`, `ServerTLSOptions`, `MinimumTLSVersion`
**Interfaces:** Swift library API; produces `NIOSSLServerHandler`
**Applications:** Adding TLS to a SwiftNIO server's connections with one line.
**Dependencies:** swift-nio, swift-nio-ssl

## Reload without restart

**Key types:** `ReloadableServerTLS`, `ReloadMode`, `ReloadOutcome`, `SuggestedLogLevel`
**Interfaces:** Swift library API
**Applications:** Serving a renewed certificate to new connections without restarting the service or dropping live connections; reloading on a signal (always) or a timer (only when the chain or key file changed); logging each outcome at a suggested level.

## Client trust

**Key types:** `ClientTrust`, `CertificateSource`, `CertificatePin`, `ClientTLSContext`, `ClientTrustError`, `ClientHandshakeFailure`
**Interfaces:** Swift library API; produces `NIOSSLClientHandler` and a `TLSConfiguration`
**Applications:** Connecting to public servers, private authorities and pinned servers with chain and hostname verification always on; telling an untrusted certificate from a wrong hostname, a failed pin, a plaintext listener and a version mismatch without depending on swift-nio-ssl.
**Dependencies:** swift-nio, swift-nio-ssl, swift-crypto

## Bind exposure

**Key types:** `BindExposure`, `isLoopback(host:)`
**Interfaces:** Swift library API
**Applications:** Deciding at start-up whether a plaintext listener is reachable from other machines; deciding whether a host a client dials is this machine.

## Test support

**Key types:** `TestAuthority`, `TestLeaf`, `TestInstant`, `InMemoryServerIdentity`, `TestCertificateError`
**Interfaces:** Swift library API, product `SwiftTLSKitTestSupport`; for test targets
**Applications:** Generating a certificate authority and server certificates when tests run, from an injected generator; serving and reloading them from memory so no private key is written to disk; dates that stay outside Apple's 825-day rule.
**Dependencies:** swift-certificates, swift-asn1, swift-crypto
