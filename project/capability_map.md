# SwiftTLSKit Capability Map

**Purpose:** Scannable inventory of what this project can do — feature areas, key types, external interfaces, and application domains.

**Last reviewed:** 2026-10-06

> **Format reference:** See `development-guidelines/rules/capability_map.md` for field definitions,
> naming conventions, and maintenance rules.

---

## Server identity

**Key types:** `ServerIdentity`, `LoadedServerIdentity`, `CertificateSummary`, `ServerIdentityError`
**Interfaces:** Swift library API
**Applications:** Turning `--tls-cert` / `--tls-key` into a validated identity or a typed refusal; logging which certificate a server holds and when it expires.

## Serving TLS

**Key types:** `ServerTLSContext`, `ServerTLSOptions`, `MinimumTLSVersion`
**Interfaces:** Swift library API; produces `NIOSSLServerHandler`
**Applications:** Adding TLS to a SwiftNIO server's connections with one line.
**Dependencies:** swift-nio, swift-nio-ssl

## Reload without restart

**Key types:** `ReloadableServerTLS`, `ReloadOutcome`
**Interfaces:** Swift library API
**Applications:** Serving a renewed certificate to new connections without restarting the service or dropping live connections.

## Client trust

**Key types:** `ClientTrust`, `CertificateSource`, `CertificatePin`, `ClientTLSContext`, `ClientTrustError`
**Interfaces:** Swift library API; produces `NIOSSLClientHandler` and a `TLSConfiguration`
**Applications:** Connecting to public servers, private authorities and pinned servers with chain and hostname verification always on.
**Dependencies:** swift-nio, swift-nio-ssl, swift-crypto

## Bind exposure

**Key types:** `BindExposure`
**Interfaces:** Swift library API
**Applications:** Deciding at start-up whether a plaintext listener is reachable from other machines.
