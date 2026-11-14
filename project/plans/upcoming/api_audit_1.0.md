# API audit for 1.0

**Date:** 2026-11-13. **Against:** tag `0.2.1`. **Tools:** `swift package diagnose-api-breaking-changes 0.2.1`
plus a by-hand pass, because the digester treats `package` access as still part of the surface and so
**does not report the three removals marked †** below.

## Changes since 0.2.1 that an adopter can see

| Change | Kind | Reported by digester |
|---|---|---|
| `ServerIdentityError.privateKeyOwnedByAnotherUser(path:ownerID:)` added | new case in an exhaustive enum | yes |
| `ServerIdentityError.privateKeyDirectoryWritable(path:directory:mode:)` added | new case | yes |
| `ServerIdentityError.privateKeyHasAccessControlList(path:)` added | new case | yes |
| `ClientTrustError.noPeerCertificate` added | new case | yes |
| `ServerTLSContext.makeHandler()` returns `any ChannelHandler`, was `NIOSSLServerHandler` | return type | yes |
| `ReloadableServerTLS.makeHandler()` likewise | return type | yes |
| `ServerTLSContext.sslContext` is `package`, was `public` † | removal | **no** |
| `LoadedServerIdentity.certificateChain` is `package`, was `public` † | removal | **no** |
| `ClientTLSContext.makeHandlers(serverHostname:)` is `package`, was `public` † | removal | **no** |
| IPv6 in `CertificateSummary.subjectAlternativeNames` is `::1`, was `0:0:0:0:0:0:0:1` | behaviour | n/a |
| A DNS name in the certificate that is not printable ASCII is left out of the summary | behaviour | n/a |
| A pin's colons must separate bytes | behaviour (stricter) | n/a |
| A key is refused for owner, writable ancestor directory, or (macOS) ACL | behaviour (stricter) | n/a |
| A host or path containing a NUL is refused | behaviour (stricter) | n/a |
| `ClientHandshakeFailure` reads the reason name as well as the number | none for any error NIOSSL produces today | n/a |

**Adopters.** Of the six packages in the owner's workspace that depend on 0.2.1 (all
`.upToNextMinor(from: "0.2.1")`, so none receives any of this until it edits its manifest), none uses
a removal †, none matches on a `ServerIdentityError` or `ClientTrustError` case (SwiftHTTPService
carries a `ServerIdentityError` as a payload only), and none calls `makeHandler()`. IconquerClient is
not in the workspace and was not checked.

## Decisions made by the audit

| # | Question | Decision |
|---|---|---|
| 1 | Which enums may grow after 1.0? | None. Exhaustive, new case is a major version. The cases above are the last before the freeze. |
| 2 | NIO and NIOSSL types in the public interface | Reduced to `ChannelPipeline.SynchronousOperations`, `any ChannelHandler`, and `TLSConfiguration` in `ClientTrust.makeTLSConfiguration` (the one function whose purpose is to hand a configuration to another library). A NIO 3 or NIOSSL 3 move is package 2.0. |
| 3 | Is `description` text API? | No. Stated in `StabilityPolicy`. |
| 4 | `makeHandlers` | `package`. `addHandlers(to:serverHostname:)` stays public. |
| 5 | IPv6 text | RFC 5952. Done. |

## The public surface, type by type

All 19 public top-level types and the one free function, with the verdict.

| Symbol | Verdict |
|---|---|
| `ServerIdentity` | Keep. Struct, `Sendable, Hashable`. `resolve`, `load(now:)`. |
| `IncompleteServerIdentity` (+ `.Half`) | Keep. A closed two-case enum nested in it. `description(certificateChainSetting:privateKeySetting:)` kept: it is how a caller names its own settings in the message. |
| `LoadedServerIdentity` | Keep; `certificateChain` now `package`. Public: `identity`, `leaf`. |
| `CertificateSummary` | Keep. IPv6 and unprintable-name behaviour documented. |
| `ServerIdentityError` | Keep; 3 cases added; closed. |
| `ServerTLSContext`, `ServerTLSOptions`, `MinimumTLSVersion` | Keep; `sslContext` now `package`; `makeHandler()` returns `any ChannelHandler`. `MinimumTLSVersion` offers only 1.2 and 1.3 and is closed. |
| `ReloadableServerTLS`, `ReloadMode`, `ReloadOutcome`, `SuggestedLogLevel` | Keep. `reloadOnEach` is generic over stdlib `AsyncSequence`, no NIO type. |
| `ClientTrust`, `CertificateSource` | Keep. No case disables verification (still true; checked by the security review). |
| `CertificatePin` (+ `.Subject`) | Keep. The gate notes `Subject` is public and used only in-module; it is the type of the public `subject` property and must stay public. |
| `ClientTLSContext` | Keep; `makeHandlers` now `package`. |
| `ClientTrustError` | Keep; `noPeerCertificate` added; closed. |
| `ClientHandshakeFailure` | Keep; closed. `wrongHostname(under:)` and `ClientTrust.consultsSystemRoots` kept: they let a test state its expectation once per platform. |
| `BindExposure`, `isLoopback(host:)` | Keep. NUL and control characters are now refused. |

## Followed up, not done

- **Ownership of the directories above a key** is not checked (documented in `StabilityPolicy`).
- **Pin after the handshake, not during it.** NIOSSL's `additionalPeerCertificateVerificationCallback`
  would close the window but is underscored; a candidate for 1.x if NIOSSL stabilises it.
