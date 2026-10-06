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
- macOS 14 or iOS 17, or later. Verified on macOS (arm64 and x86_64 builds) and by building
  for iOS. Linux is not declared: the code avoids Darwin-only API, but it has not been built
  or tested there.

## Installation

```swift
dependencies: [
    .package(url: "git@github.com:jpurnell/SwiftTLSKit.git", from: "0.1.0"),
],
targets: [
    .target(name: "MyServer", dependencies: [
        .product(name: "SwiftTLSKit", package: "SwiftTLSKit"),
    ]),
]
```

The repository is private, so it resolves over SSH with the owner's credentials, like
SwiftIdentity.

## Server

```swift
import Foundation
import NIOCore
import NIOPosix
import SwiftTLSKit

// 1. Two optional settings become: no TLS, an identity, or a thrown error.
let identity = try ServerIdentity.resolve(
    certificateChainPath: arguments.tlsCertPath,   // String?
    privateKeyPath: arguments.tlsKeyPath)          // String?

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

What `load` refuses, with the exact messages, is in the *Serving TLS* article.

## Reload

```swift
// Explicitly — from an admin endpoint, a signal, anything:
let outcome = tls.reload()          // .reloaded / .failed(error, stillServing:)

// Or on a schedule, swapping only when the chain on disk changed:
await tls.reloadOnEach(ticks) { outcome in
    logger.notice("\(outcome.description, privacy: .public)")
}
```

A reload validates completely before it replaces anything. If the new files are bad, the old
identity keeps being served and the error is returned. Connections already open are not
touched. `SIGHUP` wiring is the executable's; the *Reloading Without Restarting* article has
the snippet.

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

Test certificates and keys are generated when the tests run. No private key is checked in.
The project follows the workflow in `development-guidelines/` (vendored, gitignored); see
`CLAUDE.md` and `project/master_plan.md`.
