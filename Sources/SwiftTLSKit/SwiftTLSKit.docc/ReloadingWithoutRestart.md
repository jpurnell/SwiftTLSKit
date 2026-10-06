# Reloading Without Restarting

Serve a renewed certificate to new connections without dropping the ones already open.

## Overview

A server that reads its certificate once, at start-up, serves that certificate until it is
restarted. Renewing the file on disk changes nothing it can observe, so every renewal has to
be followed by a restart of every service that holds a copy — and a service left off that
list goes on serving the old certificate until it expires.

``ReloadableServerTLS`` owns the current ``ServerTLSContext`` and can replace it:

```swift
import Foundation
import SwiftTLSKit

func reloadNow(_ tls: ReloadableServerTLS) -> String {
    tls.reload().description
}
```

## What a reload guarantees

- **Validation comes first, and it is complete.** The files go through every check a first
  load makes and a context is built from them. Only then is the current context replaced.
- **A failed reload changes nothing.** The previous context is still current and still
  served. The failure comes back as ``ReloadOutcome/failed(_:stillServing:)``, carrying the
  same typed error a first load would have thrown.
- **Live connections are left alone.** A connection keeps the context it was accepted under.
  Nothing is closed or renegotiated; the old context is released when its last connection
  ends.
- **New connections see one context or the other.** The swap is one assignment under a lock.
- **Reloads are serialised.** Two triggers arriving together run one after the other.

What it does not do is watch the filesystem. See "Why there is no file watcher" below.

## A renewal is two writes, and a reload may land between them

A renewal replaces two files. A reload that runs after the new chain is in place and before
the new key is finds a key that does not match its certificate, refuses it, and keeps serving
the old identity. The next reload, with both files in place, succeeds. Nothing needs to
coordinate the two; the failure in between is the mechanism working, and it is worth logging
at a level below an alarm.

## Triggers

There are two, and the package leaves the choice of when to the server.

``ReloadableServerTLS/reload()`` always rebuilds the context when the files are valid.

``ReloadableServerTLS/reloadIfChanged()`` validates the files and replaces the context only
if the certificate chain differs from the one being served. It is the one to call on a
schedule: an unchanged chain is ``ReloadOutcome/unchanged(serving:)`` and costs two small
file reads.

``ReloadableServerTLS/reloadOnEach(_:report:)`` runs `reloadIfChanged()` for every element of
an asynchronous sequence, which covers both of the usual arrangements.

### On SIGHUP

Signal handling belongs to the executable, not to a library, so this is a snippet to copy
rather than an API. `launchctl kill SIGHUP gui/501/com.example.service` then asks a running
service to take the new certificate.

```swift
import Dispatch
import Foundation
import SwiftTLSKit
import os

func reloadOnHangup(_ tls: ReloadableServerTLS, logger: Logger) async {
    // Without this the default disposition ends the process before the source sees it.
    signal(SIGHUP, SIG_IGN)
    let (hangups, continuation) = AsyncStream.makeStream(of: Void.self)
    let source = DispatchSource.makeSignalSource(signal: SIGHUP, queue: .global())
    source.setEventHandler { continuation.yield() }
    source.resume()

    await tls.reloadOnEach(hangups) { outcome in
        logger.notice("\(outcome.description, privacy: .public)")
    }
    source.cancel()
}
```

### On a timer

```swift
import Foundation
import SwiftTLSKit
import os

func reloadEvery(_ interval: Duration, _ tls: ReloadableServerTLS, logger: Logger) async {
    let ticks = AsyncStream<Void> {
        do {
            try await Task.sleep(for: interval)
            return ()
        } catch {
            return nil
        }
    }
    await tls.reloadOnEach(ticks) { outcome in
        if case .unchanged = outcome { return }
        logger.notice("\(outcome.description, privacy: .public)")
    }
}
```

## Why there is no file watcher

It was considered and left out. A watcher is neither cheap nor testable here:

- **The files are replaced, not edited.** `install` and certbot both put a new file in place
  of the old one, so a descriptor-based watch (`DispatchSource` on macOS, `inotify` on Linux)
  loses its target at the moment it matters and has to watch the directory instead — two
  platform-specific implementations.
- **Two files change, not one.** A watcher fires between them, which is the mismatch window
  described above. That is handled, but it makes "one renewal, one reload" untrue and every
  renewal log a failure first.
- **It cannot be tested without waiting.** The only honest test of a watcher is to change a
  file and wait for an event, and a test that waits is a test that is sometimes wrong.

A timer calling ``ReloadableServerTLS/reloadIfChanged()`` gets the same result with none of
that: it is a few lines in the consumer, it is the same on every platform, and the function
it calls is tested deterministically.

## Checking that it worked

``ReloadableServerTLS/current`` is the context new connections get. Its
``ServerTLSContext/leaf`` carries the fingerprint `openssl x509 -noout -fingerprint -sha256`
prints for the file, so "is this process serving the certificate on disk" can be answered by
the process itself.
