# Changelog

All notable changes to SwiftTLSKit will be documented in this file.

## [Unreleased]

Intended as 0.2.1: a correction to what the documentation says, and one addition to the
test-support product. Nothing a caller of `SwiftTLSKit` writes changes, and no behaviour
changes.

Why a patch and not 0.3.0. Before 1.0 this package signals a source break with the minor
version (0.2.0 said so and did it), and the README tells consumers to depend on it with
`.upToNextMinor(from:)` for that reason. Both adopters do. An addition that breaks nothing
therefore belongs in the patch: 0.2.1 reaches them with no manifest change, where 0.3.0 would
make each of them edit a requirement to receive thirty lines they already have. A test target
that declares its own `SeededGenerator` keeps compiling — a module's own declaration takes
precedence over an imported one — so the addition cannot break an adopter that has not yet
deleted its copy. One that deletes its copy should raise its floor to 0.2.1.

### Fixed — documentation
- **The reason given for refusing a leading-zero octet was wrong.** The `isLoopback(host:)`
  documentation, the design notes and the 0.2.0 entry below said `0127.0.0.1` is 87.0.0.1 to
  `getaddrinfo`. It is not. Measured on macOS 27.0.1 (arm64) by an adopter, and again here:

  | Text | `getaddrinfo` | `inet_pton` | `inet_aton` |
  | --- | --- | --- | --- |
  | `0127.0.0.1` | 127.0.0.1 | 127.0.0.1 | 87.0.0.1 |
  | `0177.0.0.1` | 177.0.0.1 | 177.0.0.1 | 127.0.0.1 |

  The parser that reads a leading zero as octal is `inet_aton`. The rule is right and is
  unchanged — the same text is two different addresses depending on who parses it, and a
  caller cannot know who will — but it was justified by naming the wrong function. Corrected
  in the doc comment, in `DesignNotes`, in two test comments, and by a dated note in the
  0.2.0 entry and in that session's summary, whose original sentences are left standing.

### Added
- **`SeededGenerator`, in `SwiftTLSKitTestSupport` only**: SplitMix64, `init(seed:)`,
  `next()`. `TestAuthority` requires a `generator:`, the product shipped none, and the quality
  gate refuses `SystemRandomNumberGenerator` in tests — so IconquerServer, IconquerClient and
  this package's own suite each carried the same thirty lines. Its documentation says that
  nothing it produces is secret: the output is a function of a seed that sits in a test file.
  It is checked against the reference implementation's published values for two seeds.
  The package still has no randomness of its own: the caller constructs the generator and
  chooses the seed.

### Tests
- An octet with a leading zero is refused by `isLoopback(host:)` in every position, in a
  mapped address and in brackets — eighteen spellings — and an octet that is exactly `0` is
  not a leading zero. Those tests state the package's rule and assert nothing about any
  resolver. They pinned existing behaviour and passed when written; removing the check from
  `isLoopback` fails them.
- This suite's own copy of the generator is deleted; it uses the shipped one.

### What an adopter can delete
- **IconquerServer**: the `SeededGenerator` struct in
  `Tests/IconquerServerTests/TLSTestSupport.swift` (its `TestSeed` and the rest of the file
  stay).
- **IconquerClient**: the `SeededGenerator` struct in
  `Tests/IconquerClientTests/Support/SeededGenerator.swift` (its `TestSeed` stays, so the file
  wants renaming rather than deleting).

  The sequence is the same algorithm with the same constants, so the same seeds give the same
  keys as before.

## [0.2.0] - 2026-10-06

Not 0.1.1: one change breaks source (`resolve`, below), and before 1.0 the minor version is
where a break is signalled.

What the first two adopters — IconquerServer and IconquerClient — reported after moving to
0.1.0, fixed. Each had worked round something by writing it again; the migration notes at the
end say what each can now delete.

### Changed — breaks source
- **`ServerIdentity.resolve` throws `IncompleteServerIdentity`, not `ServerIdentityError`.** It
  could only ever fail one way, and now its type says so: `present`, `missing`, `path`. Its
  message no longer ends "or neither to serve plaintext", which was false for a consumer that
  refuses plaintext; it stops at "A server identity needs both; one without the other is
  refused." `description(certificateChainSetting:privateKeySetting:)` writes the same sentence
  with the consumer's own option names.
- **`ServerIdentityError.incompletePair(present:path:)` and `ServerIdentityError.Component` are
  removed.** Nothing can produce them any more, and an error type with a case its thrower
  cannot throw is the same over-wide type from the other side. `Component` is
  `IncompleteServerIdentity.Half`.

  What breaks: code that names `.incompletePair`, and code that catches `resolve`'s error into
  something typed as `ServerIdentityError`. A plain `try` in a throwing function, or
  `catch { print(error) }`, is unaffected.

### Changed — behaviour
- **`reloadIfChanged()` compares the private key file as well as the chain.** In 0.1.0 it
  compared the chain only, so a key file rewritten under an unchanged chain was reported as
  `.unchanged`. The key file is compared by a SHA-256 of its bytes, held in memory in a type
  with no accessor that describes itself as redacted and reflects as empty; it cannot reach a
  log, a `dump` or a debugger summary, and a test walks everything reflection can reach to
  confirm it. For the record, 0.1.0 never served a stale key: `load` refuses a key that is not
  the leaf's, so a new key that validates always arrives with a new chain. What was wrong was
  that "unchanged" claimed more than had been checked.
- **Loopback is stricter**, and `BindExposure.classify` with it. No longer loopback: an IPv4
  octet with a leading zero (`0127.0.0.1` is 127.0.0.1 to `inet_pton` here and 87.0.0.1 to
  `getaddrinfo`, which reads it as octal), square brackets around anything but an IPv6 literal
  (`[127.0.0.1]`, `[localhost]`), and a zone identifier (`::1%lo0`). All three now classify as
  exposed, which is the answer that makes a server warn or refuse.

  > **Correction, 2026-10-09.** The parenthesis above names the wrong function, and is left
  > as released. `getaddrinfo` reads `0127.0.0.1` as 127.0.0.1, as `inet_pton` does; it is
  > `inet_aton` that reads it as octal, 87.0.0.1 (macOS 27.0.1). The change itself was right,
  > because the parsers disagree. See the entry above this release.
- `ReloadableServerTLS.init(identity:options:now:)` is a convenience initializer. Nothing a
  caller writes changes.

### Added
- **`isLoopback(host:)`**, public: the one definition of loopback — `localhost`, `127.0.0.0/8`,
  `::1`, either in brackets where brackets belong, and IPv4-mapped loopback. Names are not
  resolved and `0.0.0.0` is not loopback. For a host a server binds *or* a host a client dials;
  `BindExposure` is now built on it.
- **`ReloadMode`** (`.always`, `.ifChanged`), **`reloadOnEach(_:mode:report:)`** and
  **`reload(_:)`**. The mode has no default: a signal should be `.always` and a timer
  `.ifChanged`, and the call site is where that is known. `reloadOnEach(_:report:)` is kept
  and still means `.ifChanged`.
- **`ReloadOutcome.suggestedLogLevel`** and **`SuggestedLogLevel`** (`info`, `notice`,
  `warning`): reloaded is `notice`, unchanged is `info`, failed is `warning`. Raw values are
  swift-log's level names. Still no logging dependency.
- **`ClientHandshakeFailure`**: `ClientHandshakeFailure(error)` classifies an error from a
  failed client handshake as `certificateNotTrusted`, `hostnameMismatch`,
  `pinMismatch(certificateSHA256:publicKeySHA256:)`, `peerDoesNotSpeakTLS`,
  `noSharedProtocolVersion` or `other(_:)`. BoringSSL's errors are read by packed code from an
  error that is structurally one, not by searching text. Each class is produced in the suite
  by a real handshake.
- **`ClientTrust.consultsSystemRoots`** and **`ClientHandshakeFailure.wrongHostname(under:)`**,
  for the documented Apple behaviour: with the system's roots consulted, Security.framework
  judges chain and name together, so a certificate for the wrong host is
  `certificateNotTrusted` rather than `hostnameMismatch`.
- **`SwiftTLSKitTestSupport`**, a second library product for test targets: `TestAuthority`,
  `TestLeaf`, `TestInstant`, `InMemoryServerIdentity`, `TestCertificateError`. An authority and
  leaves generated when tests run, from a generator the caller injects; and
  `TestLeaf.serverContext(options:now:)` and `InMemoryServerIdentity.reloadableServerTLS(options:now:)`,
  which build a server context from memory so that a test need not write a private key to
  disk. The in-memory entry points in `SwiftTLSKit` itself are `package`, not public.
- **Platforms: tvOS 17 and visionOS 1**, beside macOS 14 and iOS 17. Both products built for
  generic iOS, tvOS and visionOS devices with `xcodebuild`.
- DocC: `IncompleteServerIdentity` and a renamed-settings example in *Serving TLS*; a
  rewritten *Triggers* section and SIGHUP snippet in *Reloading Without Restarting*; *When the
  handshake fails* and the Apple hostname table in *Connecting as a Client*.

### Fixed
- **swift-crypto 4.x is accepted.** The requirement was `from: "3.0.0"`, which stops at 4.0.0
  and pulled a consumer on 4.5.0 back to 3.15.1. It is now `"3.0.0"..<"5.0.0"`. This package
  resolves 4.5.2 and its suite runs against it; the library target was also built against
  exactly 3.0.0. (`SwiftTLSKitTestSupport` cannot go that low: swift-certificates has its own
  floor for swift-crypto.)
- The *Reloading Without Restarting* article's SIGHUP snippet used `reloadOnEach`, and so
  `reloadIfChanged`. It now uses `mode: .always`, buffers at most one pending hangup, and
  finishes its stream when the signal source is cancelled.
- README: the package resolves over HTTPS as well as SSH; it said SSH only.

### Notes
- swift-certificates and swift-asn1 were test-only dependencies of the package. They are now
  dependencies of the `SwiftTLSKitTestSupport` product. A consumer of `SwiftTLSKit` alone
  still resolves them — dependencies are declared per package — and neither builds nor links
  them: a scratch consumer's binary was checked and holds no symbol from the X509 module.
- Apple's 825-day rule, measured: by bisection with real handshakes on macOS 27.0.1, a
  long-lived server certificate is refused when its "not before" is 2019-06-30T23:00:00Z or
  later, whatever the machine's time zone — an hour before the 1 July the policy names. The
  test certificates start on 1 January 2019.
- This package's own suite now uses a seeded generator, because the quality gate refuses
  `SystemRandomNumberGenerator` in tests. Its test keys are therefore reproducible from a seed
  in the repository. They belong to an authority that only a client built by a test trusts.
- `from: "0.1.0"` in a consumer's manifest admits this release. Before 1.0, prefer
  `.upToNextMinor(from:)`.

### Migrating from 0.1.0

**Everyone**
- `try ServerIdentity.resolve(...)` whose error is rethrown or printed: no change.
- Naming the error: `ServerIdentityError.incompletePair(present: p, path: q)` becomes
  `IncompleteServerIdentity(present: p, path: q)`; `ServerIdentityError.Component` becomes
  `IncompleteServerIdentity.Half`.

**IconquerServer** (`feat/tls`) can delete:
- In `TransportSecurity.swift`: the `BindExposure.classify(host:tlsConfigured: false).isExposedPlaintext`
  detour — it is `!isLoopback(host: host)`. `TransportSecurityError.identity` takes an
  `IncompleteServerIdentity`; its two `--tls-cert` / `--tls-key` branches become
  `error.description(certificateChainSetting: "--tls-cert", privateKeySetting: "--tls-key")`,
  and the catch-all `.identity(let error)` branch goes, since nothing else can arrive there.
  (`pairRemedy` stays only if the wording "rather than served as plain ws://" is wanted.)
- In `CertificateReload.swift`: `CertificateReload.reload(_:onEach:report:)`, which exists to
  call `reload()` instead of `reloadIfChanged()` — it is `tls.reloadOnEach(stream, mode: .always, report:)` —
  and `CertificateReload.level(for:)`, which is
  `Logger.Level(rawValue: outcome.suggestedLogLevel.rawValue)`. `HangupSignals` stays: signal
  handling is the executable's.
- In `Tests/…/TLSTestSupport.swift`: `TestInstant`, `TestAuthority` and `TestLeaf` — import
  `SwiftTLSKitTestSupport`. `TemporaryDirectory.install` and the free `summary(of:at:)` go
  wherever the test is not about files: `InMemoryServerIdentity` and `leaf.summary(now:)`
  replace them. Keep `install` for the tests of key permissions and of a reload landing
  between two writes. The `lowercaseHex` extension stays: `WebSocketTestClient` uses it.
- In `Tests/…/WebSocketTestClient.swift`: the `CERTIFICATE_VERIFY_FAILED` string match —
  `ClientHandshakeFailure(error) == .certificateNotTrusted`.
- In `Package.swift`: the test dependencies on swift-certificates and swift-asn1; add
  `SwiftTLSKitTestSupport` to the test target. swift-nio-ssl and swift-crypto stay as test
  dependencies, because `WebSocketTestClient` reads the peer's certificate from
  `NIOSSLClientHandler` and hashes it.

**IconquerClient** (`feat/wss`) can delete:
- In `ServerEndpoint.swift`: `BindExposure.classify(host: host, tlsConfigured: false) == .loopbackPlaintext`,
  a bind-host question asked of a dial host — it is `isLoopback(host: host)`.
- In `ServerConnection.swift`: `verificationFailureMarker`, the `NIOSSLExtraError` cast, and the
  `ClientTrustError.pinMismatch` unpacking in `failure(for:host:handshakeCompleted:)` — one
  `switch ClientHandshakeFailure(error)`. `peerDoesNotSpeakTLS` and `noSharedProtocolVersion`
  are new distinctions it can surface or fold into `handshakeFailed`.
- In `Package.swift`: the package's direct dependency on swift-nio-ssl and the library
  target's `NIOSSL` product, there only to name `NIOSSLExtraError` (`import NIOSSL` in
  `ServerConnection.swift` goes with it; `NIOTLS` is swift-nio's and stays); and the test
  dependencies on swift-crypto, swift-certificates and swift-asn1, which only
  `TestCertificates.swift` uses.
- In `Tests/…/Support/TestCertificates.swift`: everything but `TestToken` — `TestInstant`,
  `TestAuthority`, `TestLeaf`, and `IdentityDirectory` entirely. `leaf.serverContext(now:)`
  builds the context without the directory, the two files, or the key on disk.
- Its platform floors need no change; tvOS and visionOS are now declared here.

**Both**, when adopting the test-support types: `TestAuthority(commonName:)` takes a
`generator:`; `chainPEM`, `certificatePEM` and `certificateSHA256` are plain properties, so
their `try` goes; `keyPEM` is `privateKeyPEM`; `TestInstant.validFrom` / `validUntil` are
`longLivedStart` / `longLivedEnd`; `issueLeaf(key:)` is `issueLeaf(reusingKeyOf:)`.

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

[Unreleased]: https://github.com/jpurnell/SwiftTLSKit/compare/0.2.0...HEAD
[0.2.0]: https://github.com/jpurnell/SwiftTLSKit/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/jpurnell/SwiftTLSKit/releases/tag/0.1.0
