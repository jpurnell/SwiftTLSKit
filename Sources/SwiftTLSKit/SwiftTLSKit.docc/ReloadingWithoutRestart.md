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

``ReloadOutcome/suggestedLogLevel`` says so in a form code can use: a failed reload is a
``SuggestedLogLevel/warning``, a reload is a ``SuggestedLogLevel/notice``, and no change is
``SuggestedLogLevel/info``. The package has no logging dependency, so the level is a small
enum of its own whose raw values are swift-log's level names:

```swift
import SwiftTLSKit

func levelName(for outcome: ReloadOutcome) -> String {
    // With swift-log: Logger.Level(rawValue: outcome.suggestedLogLevel.rawValue)
    outcome.suggestedLogLevel.rawValue
}
```

## Triggers

There are two, and the package leaves the choice of when to the server.

``ReloadableServerTLS/reload()`` always rebuilds the context when the files are valid. It is
the one a signal, an admin endpoint or a renewal hook should run: somebody has said "read them
again", and the response to that is to read them again.

``ReloadableServerTLS/reloadIfChanged()`` validates the files and replaces the context only
if they differ from what is being served. It is the one to call on a schedule: unchanged files
are ``ReloadOutcome/unchanged(serving:)`` and cost two small file reads.

``ReloadableServerTLS/reloadOnEach(_:mode:report:)`` runs one or the other for every element
of an asynchronous sequence, which covers both of the usual arrangements. Its
``ReloadMode`` — ``ReloadMode/always`` or ``ReloadMode/ifChanged`` — has no default, because
the place that knows whether it is holding a signal or a timer is the call site.

### What "changed" means

Both files. The certificate chain is compared certificate by certificate, and the private key
file by a SHA-256 of its bytes that is kept in memory for that comparison alone. The digest
has no accessor and describes itself as redacted, so it cannot reach a log, a `dump` or a
debugger summary; nothing else derived from the key file is kept.

In 0.1.0 only the chain was compared. That could not serve a stale key — a key that is not the
leaf's is refused, so a new key that passes validation always comes with a new chain — but it
did mean "unchanged" was a statement about the public half only, and a key file rewritten
under the same chain was reported as nothing having happened. The wrong thing to build a
`SIGHUP` handler on, which is what this article used to show.

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
    // One undelivered hangup is enough: several that pile up behind a reload in progress all
    // ask for the same thing, and one more reload answers every one of them.
    let (hangups, continuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
    let source = DispatchSource.makeSignalSource(signal: SIGHUP, queue: .global())
    source.setEventHandler { continuation.yield() }
    source.setCancelHandler { continuation.finish() }
    source.resume()

    // `.always`: a hangup is an operator saying "read them again".
    await tls.reloadOnEach(hangups, mode: .always) { outcome in
        switch outcome.suggestedLogLevel {
        case .info: logger.info("\(outcome.description, privacy: .public)")
        case .notice: logger.notice("\(outcome.description, privacy: .public)")
        case .warning: logger.warning("\(outcome.description, privacy: .public)")
        }
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
    // `.ifChanged`: a tick is nobody saying anything, so unchanged files are left alone.
    await tls.reloadOnEach(ticks, mode: .ifChanged) { outcome in
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
