# Serving TLS

Turn two optional paths into a validated identity, and add TLS to each connection with one line.

## Overview

A server's TLS settings usually arrive as two optional strings — `--tls-cert` and `--tls-key`,
or two entries in a configuration file. There are three things those two optionals can mean,
and ``ServerIdentity/resolve(certificateChainPath:privateKeyPath:)`` gives each its own answer:

| Certificate chain | Private key | Result |
|---|---|---|
| absent | absent | `nil` — no identity was configured |
| present | present | a ``ServerIdentity`` |
| present | absent | throws ``IncompleteServerIdentity`` |
| absent | present | throws ``IncompleteServerIdentity`` |

The last two rows are why the function exists. Written as `if let certPath, let keyPath`, they
fall through to plaintext, and an operator who mistyped one flag is running an unencrypted
server that started without complaint.

``IncompleteServerIdentity`` is all `resolve` can throw. It carries the half that was given
and its path, and its message can be written in the server's own vocabulary:

```swift
import SwiftTLSKit

func identity(tlsCert: String?, tlsKey: String?) -> ServerIdentity? {
    do {
        return try ServerIdentity.resolve(certificateChainPath: tlsCert, privateKeyPath: tlsKey)
    } catch {
        print(error.description(certificateChainSetting: "--tls-cert", privateKeySetting: "--tls-key"))
        return nil
    }
}
_ = identity(tlsCert: "/certs/fullchain.pem", tlsKey: nil)
// Prints "--tls-cert was given (/certs/fullchain.pem) without --tls-key. A server identity needs both; one without the other is refused."
```

The first row is the caller's to interpret. `nil` says no identity was configured; it does not
say "serve plaintext". A server that would rather not start than listen unencrypted on a
public address asks ``BindExposure`` and refuses — see "Plaintext, and where it is bound"
below — and nothing in a message from this package tells its operator otherwise.

## Adopting it in a NIO server

Three pieces: resolve the settings, load the identity, and add the handler in the child
channel initializer.

```swift
import Foundation
import NIOCore
import SwiftTLSKit

/// At start-up. `nil` means "no identity was configured"; a thrown error means "do not start".
func makeServerTLS(certificatePath: String?, keyPath: String?) throws -> ReloadableServerTLS? {
    guard let identity = try ServerIdentity.resolve(
        certificateChainPath: certificatePath, privateKeyPath: keyPath)
    else { return nil }
    return try ReloadableServerTLS(identity: identity, now: { Date() })
}

/// In `ServerBootstrap.childChannelInitializer`, before the application's own handlers
/// or after them — the TLS handler is put at the front of the pipeline either way.
func addTLS(_ tls: ReloadableServerTLS?, to channel: any Channel) -> EventLoopFuture<Void> {
    channel.eventLoop.makeCompletedFuture {
        try tls?.addHandler(to: channel.pipeline.syncOperations)
    }
}
```

A server that never reloads can use ``ServerTLSContext`` directly; it has the same
`addHandler(to:)`. ``ReloadableServerTLS`` costs nothing extra and means a renewal does not
need a restart — see <doc:ReloadingWithoutRestart>.

## What is refused, and what the message says

`resolve` refuses one thing, as an ``IncompleteServerIdentity``:

| Refused | Message |
|---|---|
| One of the two paths | `A TLS certificate chain was given (PATH) without a private key. A server identity needs both; one without the other is refused.` |

``ServerIdentity/load(now:)`` — which ``ReloadableServerTLS`` and
``ServerTLSContext/load(_:options:now:)`` both call — refuses the following. Each is a
``ServerIdentityError`` whose description is the sentence shown, with the real path in it.

| Refused | Message |
|---|---|
| A file that cannot be opened | `Cannot read PATH: No such file or directory.` |
| A directory, FIFO or device | `PATH is not a regular file.` |
| A file over 1 MiB | `PATH is larger than 1048576 bytes, which no certificate chain or private key is.` |
| A key its group or others can reach | `The private key at PATH has mode 0644, which lets group or others read or write it. Run: chmod 600 PATH` |
| A chain with no certificate | `PATH holds no certificates.` |
| A damaged certificate | `PATH holds a certificate that cannot be read as PEM.` |
| A damaged or encrypted key | `PATH does not hold a private key that can be read as unencrypted PEM.` |
| A key that is not the leaf's | `The private key at KEYPATH does not match the leaf certificate in CHAINPATH.` |
| An expired leaf | `The leaf certificate in PATH expired at 2026-01-01T00:00:00Z.` |
| A leaf not yet valid | `The leaf certificate in PATH is not valid until 2027-01-01T00:00:00Z.` |

No message contains anything read from a file. The key's own parse error is discarded rather
than quoted, so nothing derived from the key can reach a log.

### The private key's permissions

The key must not be readable or writable by its group or by others: any of the bits `0o077`
is refused, so `0600` and `0400` pass and `0640` does not. The check is `fstat` on the file
descriptor that is then read, not `stat` on the path, so the file examined is the file used.
A symbolic link is followed and the mode judged is the target's — certbot's `live/` directory
is symbolic links into `archive/`.

The certificate chain is public and may have any mode.

### Time is supplied by the caller

`load(now:)` takes the current time as an argument, and ``ReloadableServerTLS`` takes a
closure it calls at each load. Nothing in the package reads the clock. A server passes
`{ Date() }`; a test passes any instant it wants to ask about.

## Logging what is being served

``CertificateSummary`` is there so a start-up log can say which certificate the server holds
and when it stops being valid. Everything in it is public information — names, dates and
fingerprints — so it can be logged in full:

```swift
import SwiftTLSKit
import os

func logServing(_ tls: ReloadableServerTLS, to logger: Logger) {
    logger.info("TLS enabled: \(tls.current.leaf.description, privacy: .public)")
}
```

## Protocol versions and ALPN

The minimum is TLS 1.2. ``ServerTLSOptions`` can raise it to TLS 1.3 only, and can list ALPN
protocols; it cannot lower it. Clients are not asked for a certificate.

```swift
import SwiftTLSKit

let strict = ServerTLSOptions(minimumVersion: .tls13, applicationProtocols: ["h2", "http/1.1"])
print(strict.applicationProtocols)
// Prints "["h2", "http/1.1"]"
```

## Plaintext, and where it is bound

When there is no identity, ``BindExposure`` says what the plaintext listener exposes. It
decides nothing — whether exposed plaintext is a warning or a refusal to start is the
server's call:

```swift
import SwiftTLSKit

let exposure = BindExposure.classify(host: "0.0.0.0", tlsConfigured: false)
print(exposure)
// Prints "Plaintext on 0.0.0.0: this listener is reachable from other machines without TLS. Supply a certificate chain and private key, or bind to 127.0.0.1."
```
