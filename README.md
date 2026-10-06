# SwiftTLSKit

TLS configuration for SwiftNIO servers and clients, written once.

It holds the decisions that were being re-made in every server and client: which files are a
server's identity, what makes them unfit to serve, how a running server takes a renewed
certificate, and what a client is prepared to trust. It is configuration only — no sockets,
no event loops, no listener framework.

- **Half an identity is an error, never plaintext.** A certificate path without a key path
  throws. The code this replaces served plaintext in that case, silently.
- **An identity is judged before it is served**: missing files, a world-readable key, a key
  that does not match, an expired leaf — each a typed error naming the path, never the
  contents.
- **A renewed certificate does not need a restart.**
- **Client verification cannot be switched off.** There is no "trust anything" case.

## Requirements

- Swift 6.2 or later
- macOS 14, iOS 17, tvOS 17 or visionOS 1, or later. Tested on macOS (arm64); built for
  generic iOS, tvOS and visionOS devices with `xcodebuild`. Linux is not declared: the code
  avoids Darwin-only API, but it has not been built or tested there.

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/jpurnell/SwiftTLSKit.git", .upToNextMinor(from: "0.2.0")),
],
targets: [
    .target(name: "MyServer", dependencies: [
        .product(name: "SwiftTLSKit", package: "SwiftTLSKit"),
    ]),
    .testTarget(name: "MyServerTests", dependencies: [
        "MyServer",
        // Test targets only: certificates generated when the tests run.
        .product(name: "SwiftTLSKitTestSupport", package: "SwiftTLSKit"),
    ]),
]
```

The repository is private. It resolves over **HTTPS**, as above, with whatever credentials
git already has for github.com — a credential helper, `gh auth setup-git`, or a `.netrc` —
and equally over **SSH** as `git@github.com:jpurnell/SwiftTLSKit.git`. Both adopters use the
HTTPS form. Use one form throughout a dependency graph, so that the package is not named by
two URLs.

`.upToNextMinor`, not `from:`. Before 1.0 a minor version may break source — 0.2.0
did, see the CHANGELOG — and `from: "0.1.0"` means "anything below 1.0.0", so it
takes such a release at the next `swift package update`.

Two products:

| Product | For | Brings in |
|---|---|---|
| `SwiftTLSKit` | servers and clients | swift-nio, swift-nio-ssl, swift-crypto |
| `SwiftTLSKitTestSupport` | their test targets | the above, and swift-certificates and swift-asn1 |

swift-certificates is linked only by a target that asks for `SwiftTLSKitTestSupport`. SwiftPM
still fetches it when resolving, because dependencies are declared per package; it is not
built into, or linked by, anything that uses `SwiftTLSKit` alone.

## Server

```swift
import Foundation
import NIOCore
import NIOPosix
import SwiftTLSKit

// 1. Two optional settings become: no identity, an identity, or a thrown error.
let identity: ServerIdentity?
do {
    identity = try ServerIdentity.resolve(
        certificateChainPath: arguments.tlsCertPath,   // String?
        privateKeyPath: arguments.tlsKeyPath)          // String?
} catch {
    // `error` is an IncompleteServerIdentity: which half was given, and its path.
    fatalError(error.description(certificateChainSetting: "--tls-cert", privateKeySetting: "--tls-key"))
}

// 2. Load and validate. Throws rather than start a server it should not.
let tls = try identity.map { try ReloadableServerTLS(identity: $0, now: { Date() }) }

// 3. Say what plaintext exposes; the decision is yours.
let exposure = BindExposure.classify(host: host, tlsConfigured: tls != nil)
if exposure.isExposedPlaintext { /* warn, or refuse to start */ }

// 4. One line per connection.
let bootstrap = ServerBootstrap(group: group)
    .childChannelInitializer { channel in
        channel.eventLoop.makeCompletedFuture {
            try tls?.addHandler(to: channel.pipeline.syncOperations)
            // ...the application's handlers
        }
    }
```

`resolve` returning `nil` means no identity was configured. It does not mean "serve
plaintext": whether to do that, and on which hosts, is the server's decision, and no message
from this package tells an operator otherwise.

What `load` refuses, with the exact messages, is in the *Serving TLS* article.

### Is this host loopback?

```swift
isLoopback(host: "127.0.0.1")   // true: localhost, 127.0.0.0/8, ::1, [::1], ::ffff:127.0.0.1
isLoopback(host: "0.0.0.0")     // false: the wildcard is every interface
isLoopback(host: "example.com") // false: names are not resolved
```

One definition for both ends: `BindExposure` uses it for a host a server binds, and a client
calls it directly for a host it dials. Anything two parsers could read differently —
`0127.0.0.1`, `127.1`, `::1%lo0` — is not loopback.

## Reload

```swift
// On a signal, an admin endpoint, a renewal hook - somebody asked: reload unconditionally.
await tls.reloadOnEach(hangups, mode: .always) { outcome in
    // swift-log; with os.Logger, switch on suggestedLogLevel instead.
    logger.log(level: Logger.Level(rawValue: outcome.suggestedLogLevel.rawValue) ?? .notice, "\(outcome)")
}

// On a timer - nobody asked: swap only if the chain or the key file changed.
await tls.reloadOnEach(ticks, mode: .ifChanged) { outcome in
    if case .unchanged = outcome { return }
    logger.notice("\(outcome)")
}

// Or once, directly:
let outcome = tls.reload()          // .reloaded / .failed(error, stillServing:)
```

A reload validates completely before it replaces anything. If the new files are bad, the old
identity keeps being served and the error is returned. Connections already open are not
touched.

`outcome.suggestedLogLevel` is `notice` for a reload, `info` for no change and `warning` for a
failure — a warning because the old identity is still served, and because a renewal is two
writes and a reload can land between them. Its raw values are swift-log's level names; the
package itself has no logging dependency.

`SIGHUP` wiring is the executable's; the *Reloading Without Restarting* article has the
snippet.

## Client

```swift
import NIOCore
import NIOPosix
import SwiftTLSKit

let tls = try ClientTLSContext(trust: .systemRoots)
// .additionalRoots([.pemFile("/etc/ca/dev.pem")])   system roots plus a private authority
// .onlyRoots([.pemFile("/etc/ca/dev.pem")])         that authority and nothing else
// .pinned([try .publicKey(sha256: "…")])            verified as usual, and the leaf must match

let bootstrap = ClientBootstrap(group: group)
    .channelInitializer { channel in
        channel.eventLoop.makeCompletedFuture {
            try tls.addHandlers(to: channel.pipeline.syncOperations, serverHostname: host)
            // ...HTTP and WebSocket upgrade handlers
        }
    }
```

The hostname is required. A name is sent as SNI and checked against the certificate; an IP
address is checked against the certificate's IP names.

### When the handshake fails

```swift
switch ClientHandshakeFailure(error) {       // an error from before the handshake completed
case .certificateNotTrusted: ...             // untrusted, expired, or otherwise invalid chain
case .hostnameMismatch: ...                  // trusted, but issued for another host
case .pinMismatch(let certificateSHA256, let publicKeySHA256): ...   // what was served
case .peerDoesNotSpeakTLS: ...               // a plaintext listener answered
case .noSharedProtocolVersion: ...
case .other(let reason): ...                 // the library's description
}
```

A client does not need its own dependency on swift-nio-ssl, or its own copy of the string
`CERTIFICATE_VERIFY_FAILED`, to tell these apart.

On Apple platforms, when the system's roots are consulted (every trust except `.onlyRoots`),
Security.framework judges the chain and the name together, so **a certificate for the wrong
host is `.certificateNotTrusted`, not `.hostnameMismatch`**. `ClientTrust.consultsSystemRoots`
and `ClientHandshakeFailure.wrongHostname(under:)` say which to expect.

## Testing against it

`SwiftTLSKitTestSupport` gives a test target an authority, leaves, and a server context,
without a certificate dependency of its own and without writing a private key to disk:

```swift
import SwiftTLSKit
import SwiftTLSKitTestSupport

let authority = try TestAuthority(commonName: "Test Authority", generator: generator)
let leaf = try authority.issueLeaf(dnsNames: ["localhost"])

let server = try leaf.serverContext(now: TestInstant.now)       // built in memory
let client = try authority.clientContext()                      // trusts that authority only

// A reloadable identity that a test can renew, also in memory:
let identity = InMemoryServerIdentity(leaf)
let tls = try identity.reloadableServerTLS(now: { TestInstant.now })
identity.replace(with: try authority.issueLeaf())
tls.reload()
```

- **The generator is yours.** Every key and serial number comes from the one you pass. A
  seeded generator makes a suite reproducible, and makes its test keys public — which is fine
  for an authority nothing trusts outside a test. The product does not ship a generator.
- **Dates are fixed, and chosen.** Certificates run from 1 January 2019 to 2090 by default.
  Apple refuses a server certificate issued from 1 July 2019 with more than 825 days of
  validity whenever the system's roots are consulted, so a long-lived test certificate has to
  be dated before that; `TestInstant` has the dates and the reasoning.
- **Files when files are the point.** `leaf.chainPEM` and `leaf.privateKeyPEM` are there for
  tests of permissions, missing files and mismatched pairs.

## Documentation

```bash
swift package generate-documentation --target SwiftTLSKit
```

Articles: Serving TLS, Reloading Without Restarting, Connecting as a Client, Design Notes.

## Development

```bash
./scripts/bootstrap.sh     # once per clone: enables the git hooks
swift test
quality-gate --check all
```

Test certificates and keys are generated when the tests run. No private key file is checked
in. The suite's generator is seeded, so its test keys are the same on every run and are to be
treated as public; they belong to an authority that only a test's own client trusts.
The project follows the workflow in `development-guidelines/` (vendored, gitignored); see
`CLAUDE.md` and `project/master_plan.md`.
