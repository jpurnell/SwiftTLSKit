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

``ServerIdentityError``, ``IncompleteServerIdentity`` and ``ClientTrustError`` are `Hashable`,
so a caller can match a case and a test can assert one exactly. The private key's parse error from the TLS library is
discarded rather than wrapped, because it is the one error that might describe the key.

### Time is a parameter

Nothing reads the clock. `load(now:)` takes a `Date`; ``ReloadableServerTLS`` takes a closure.
This is what lets expiry be tested at exact boundaries without waiting or mocking.

### No logging dependency

The package logs nothing. It returns values with descriptions — ``CertificateSummary``,
``ReloadOutcome``, ``BindExposure`` — and the consumer logs them with its own logger and its
own privacy annotations. A library that never holds a logger cannot log a key by accident.

What it can say without a logger is how much an outcome matters, and
``ReloadOutcome/suggestedLogLevel`` does: a ``SuggestedLogLevel`` of three cases whose raw
values happen to be swift-log's level names. That is a string coincidence a consumer can use,
not a dependency.

### Minimum TLS 1.2, and no setting below it

``MinimumTLSVersion`` has two cases. TLS 1.0 and 1.1 are not expressible.

## What the first adopters changed

0.1.0 was designed by reading the code it replaced. Two packages then adopted it, and each
worked round something by writing it again. Those workarounds were the second design input,
and a better one, because they were written by something trying to use the API.

### An error type is as wide as what throws it

``ServerIdentity/resolve(certificateChainPath:privateKeyPath:)`` can fail one way. In 0.1.0 it
threw ``ServerIdentityError``, twelve cases of which it could not produce, and a consumer
wrapping its error had to carry all of them. It now throws ``IncompleteServerIdentity``, and
``ServerIdentityError`` lost the one case that only `resolve` produced. The break in source
was taken deliberately: keeping the case for compatibility would have left an error type
with a case nothing throws, which is the same defect seen from the other side.

### A message says only what is true for every consumer

The half-pair message used to end "or neither to serve plaintext". For a server that refuses
plaintext on a public address, that sentence sends its operator to an option that does not
work. What a server does with no identity is its own decision, so the message stops before
it. It also takes the consumer's names for the two settings, because the operator typed
`--tls-cert`, not "a TLS certificate chain".

### "Unchanged" covers both files

``ReloadableServerTLS/reloadIfChanged()`` compared the chain. The adopters' report was that a
renewal keeping the chain and changing the key would be missed. Looked at closely that cannot
happen: a key that is not the leaf's is refused, so a new key that validates always comes
with a new chain. What was true is narrower and still wrong — a key file rewritten under the
same chain was reported as nothing having happened. The key file is now compared too.

It is compared by a SHA-256 of its bytes, which means something derived from the key is held
in memory, and the package's rule is that nothing derived from the key reaches a log. The
digest is therefore a type that can be compared and nothing else: no accessor, a description
that says "redacted", and an empty mirror. A test walks everything reflection can reach from
each public value and looks for it.

### What a trigger means is said where the trigger is

``ReloadableServerTLS/reloadOnEach(_:mode:report:)`` takes a ``ReloadMode`` and gives it no
default. The article's own `SIGHUP` snippet had used the if-changed loop for a signal; a
default would let the next snippet make the same mistake silently.

### One definition of loopback

Both adopters asked ``BindExposure`` whether a host was loopback, one of them about a host it
dials. ``isLoopback(host:)`` is that question on its own. Writing its table found three ways
the definition was too generous, each resolved towards "not loopback": an octet with a
leading zero, which `inet_pton` reads as decimal and `inet_aton` reads as octal; brackets
around something that is not an IPv6 literal; and a zone identifier.

The reason first given for the leading zero was wrong, and 0.2.0 shipped saying it. It said
`getaddrinfo` reads `0127.0.0.1` as octal, 87.0.0.1. An adopter measured it, and so did we,
on macOS 27.0.1:

| Text | `getaddrinfo` | `inet_pton` | `inet_aton` |
| --- | --- | --- | --- |
| `0127.0.0.1` | 127.0.0.1 | 127.0.0.1 | 87.0.0.1 |
| `0177.0.0.1` | 177.0.0.1 | 177.0.0.1 | 127.0.0.1 |

The octal reader is `inet_aton`. The rule stands, and for a better reason than the one it was
given: it never depended on which parser was the odd one, only on there being one. A caller
cannot know which of them the code between it and the socket will use, so a spelling they
read differently is refused. The suite pins the rule — an octet with a leading zero is not
loopback, in any position — and asserts nothing about any resolver, because that table is a
measurement of one platform and not a property of this package.

### Handshake failures are classified here, once

``ClientHandshakeFailure`` was a test helper. Both adopters rebuilt it, and one took a
dependency on swift-nio-ssl to do so. Publishing it moves the fragile part — NIOSSL keeps
BoringSSL's error code private, so it is read from the front of the error's description —
into the one package whose tests perform every kind of failed handshake. The code is compared
as a number, from an error that is structurally a BoringSSL one; an error whose text merely
contains `CERTIFICATE_VERIFY_FAILED` is not classified by it.

A peer that closes without sending anything is ``ClientHandshakeFailure/other(_:)``, not
``ClientHandshakeFailure/peerDoesNotSpeakTLS``. Nothing arrived, so there is nothing to say
it was not a TLS server that crashed.

### Test support is a product, and in-memory identities are not public

Both adopters copied this package's test certificates and added swift-certificates to their
own test targets. `SwiftTLSKitTestSupport` is that code as a second product, which makes
swift-certificates a dependency of that product and of nothing else.

It also builds a server context from memory, so a test need not write a private key to disk.
That needed an entry point in this module, and it is `package`, not `public`: the rule that a
server context comes only from a loaded identity, with its permission check, still holds for
everything a server can call.

The test-support product has no randomness of its own. Every key and serial number comes from
a generator the caller passes in.

It did not ship a generator at first, on the reasoning that a consumer brings its own. Three
consumers — both adopters, and this package's own suite — then each wrote the same thirty
lines of SplitMix64, because the quality gate refuses `SystemRandomNumberGenerator` in tests
and a seeded generator is therefore not optional for them. `SeededGenerator` is those thirty
lines, once, in `SwiftTLSKitTestSupport`. The rule above is unchanged: the caller still
constructs the generator and chooses the seed, and nothing in the package draws from one the
caller did not pass. It is in the test-support product only, and its documentation says in
as many words that nothing it produces is secret.

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

### Subject names are read from the DER, by this package

``CertificateSummary/subjectAlternativeNames`` was first read with
`NIOSSLCertificate._subjectAlternativeNames()`, which NIOSSL marks as not yet stable: a NIOSSL
release could remove it, and the failure would have landed as a compile error in every adopter's
build rather than here. The other ways to read them were to add swift-certificates to the
library target, which this package does not do (it would be built by every consumer, where today
it is only resolved), or to stop reporting the names.

Instead `NIOSSLCertificate.toDERBytes()`, which is stable, is walked by a small reader
(`DERSubjectAlternativeNames`) that finds the subject alternative names extension and returns
the DNS names and addresses. It has no recursion, checks every length against the bytes that
remain, and returns no names, never an error, for anything it cannot read: the certificate was
already accepted by BoringSSL, and the output is for a log line. Its tests compare it with
swift-certificates, which is neither this reader nor NIOSSL.

Two decisions came with it. A DNS name holding anything but printable ASCII — a control
character, a space, a byte above 0x7e — is left out, because the summary is logged and such a
name can forge or hide a line (an embedded NUL is the old way to make a certificate for
`good.test` read as `good.test\0evil.test`). And IPv6 addresses are written as RFC 5952 writes
them (`::1`), where the underscored-API version wrote eight groups (`0:0:0:0:0:0:0:1`); that is
the one visible change.

The common name is not reported at all: NIOSSL keeps it internal, and hostname verification
ignores it whenever alternative names are present.

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
  declares only what was verified. ``ClientHandshakeFailure/wrongHostname(under:)`` has a
  branch for it that states NIOSSL's documented behaviour and has not been run.
- A way to read the peer certificate's fingerprint after a client handshake. Tests that want
  it still reach for `NIOSSLClientHandler.peerCertificate`.
