# Design Notes

The decisions behind the API, and the places where the code forced a different answer from
the one first intended.

## Overview

The package replaces TLS configuration that had been written separately in SwiftMCPServer's
HTTP transport, in VaultMCP's web view, and — for the client half — in SwiftMCPClient's
`ServerTrust`. Reading those was the design input. The defect they shared on the server side
is that a TLS context was built `if let certPath, let keyPath`, so one path without the other
fell through to plaintext.

## Decisions

### A server context can only be made from a loaded identity

``ServerTLSContext`` takes a ``LoadedServerIdentity``, and the only way to get one is
``ServerIdentity/load(now:)``. There is no initializer from two paths, so no route from
configuration to a listening TLS server skips the checks.

### Errors are typed, and carry paths, never contents

``ServerIdentityError`` and ``ClientTrustError`` are `Hashable` enums, so a caller can match a
case and a test can assert one exactly. The private key's parse error from the TLS library is
discarded rather than wrapped, because it is the one error that might describe the key.

### Time is a parameter

Nothing reads the clock. `load(now:)` takes a `Date`; ``ReloadableServerTLS`` takes a closure.
This is what lets expiry be tested at exact boundaries without waiting or mocking.

### No logging dependency

The package logs nothing. It returns values with descriptions — ``CertificateSummary``,
``ReloadOutcome``, ``BindExposure`` — and the consumer logs them with its own logger and its
own privacy annotations. A library that never holds a logger cannot log a key by accident.

### Minimum TLS 1.2, and no setting below it

``MinimumTLSVersion`` has two cases. TLS 1.0 and 1.1 are not expressible.

## Where the code forced a deviation

### The reloader is a class with a lock, not an actor

The brief allowed either. A NIO channel initializer is synchronous and runs on an event loop,
so it has to read the current context without suspending; an actor would force every new
connection through an `await`. ``ReloadableServerTLS`` is a `final class` whose mutable state
is one `NIOLockedValueBox`, which makes it `Sendable` without `@unchecked`.

### There is no file watcher

See <doc:ReloadingWithoutRestart>. A watcher would be two platform-specific implementations
that can only be tested by waiting. ``ReloadableServerTLS/reloadIfChanged()`` on a timer or a
signal gives the same result and is tested deterministically.

### A pin is checked after the handshake, not during it

NIOSSL's custom verification callback replaces chain validation. To keep NIOSSL's own chain
and hostname verification and add the pin on top, the pin is checked by a handler directly
after the handshake, which holds application writes until its verdict. See
<doc:ConnectingAsAClient>. Two things follow: a pinned trust cannot be flattened into a bare
`TLSConfiguration`, and ``ClientTLSContext`` deliberately does not expose its `NIOSSLContext`,
because a handler built from it directly would skip the pin.

### swift-crypto is a dependency

The intended dependency list was swift-nio and swift-nio-ssl. Pins and fingerprints need
SHA-256, NIOSSL exposes no digest, and a hand-written one has no place in a TLS package.
swift-crypto is Apple's, is CryptoKit on Apple platforms, and is already resolved by every
planned adopter.

### Subject names come from an underscored NIOSSL API

``CertificateSummary/subjectAlternativeNames`` is read with
`NIOSSLCertificate._subjectAlternativeNames()`, which NIOSSL marks as not yet stable. It is
the only way to read them without adding a certificate-parsing dependency to the library
target. The common name is not reported at all: NIOSSL keeps it internal, and hostname
verification ignores it whenever alternative names are present.

### Key mismatch is detected by building a context

NIOSSL does not expose a private key's public half, so "does this key belong to this
certificate" is answered by building a throwaway context: BoringSSL compares the two when the
key is installed. The specific error it raises is mapped to
``ServerIdentityError/privateKeyDoesNotMatchCertificate(certificateChainPath:privateKeyPath:)``;
anything else becomes ``ServerIdentityError/contextRejected(reason:)``.

### An address is verified against the connection, not the string

For an IP address NIOSSL sends no SNI and verifies the certificate against the address the
channel is actually connected to. ``ClientTLSContext/makeHandlers(serverHostname:)`` therefore
uses the string to decide *that* the peer is an address; the address checked is the socket's.

## Not in this version

- Client certificates (mutual TLS) on the server side.
- Encrypted private keys. An encrypted key is refused as
  ``ServerIdentityError/invalidPrivateKey(path:)``.
- Checking the private key's owner. The mode is checked; the uid is not.
- Linux has not been built or tested. The code avoids Darwin-only API and the manifest
  declares only what was verified.
