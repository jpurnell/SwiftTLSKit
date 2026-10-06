# ``SwiftTLSKit``

TLS configuration for SwiftNIO servers and clients, written once.

## Overview

SwiftTLSKit holds the TLS decisions that were being re-made in every server and client: which
files are a server's identity, what makes them unfit to serve, how a running server takes a
renewed certificate, and what a client is prepared to trust.

It is configuration only. It opens no sockets, owns no event loops, and is not a listener
framework: it produces values and NIO channel handlers, and the consumer keeps its own
bootstrap.

Four properties are the point of it:

- **Half an identity is an error, never plaintext.** A certificate path without a key path, or
  the reverse, throws ``ServerIdentityError/incompletePair(present:path:)``. The code this
  replaces built a TLS context only when both were present, so one without the other served
  plaintext without a word.
- **An identity is judged before it is served.** ``ServerIdentity/load(now:)`` refuses a
  missing file, a private key other users can read, a key that does not match the
  certificate, and a certificate that has expired — each with a typed error that names the
  path and never the contents.
- **A renewed certificate does not need a restart.** ``ReloadableServerTLS`` replaces the
  context new connections are given, leaves live connections alone, and keeps the old
  context if the new files are bad.
- **Verification cannot be switched off.** ``ClientTrust`` chooses who may have signed a
  server's certificate. It has no case that skips the check, and the server's hostname is a
  required argument.

Start with <doc:ServingTLS> for a server and <doc:ConnectingAsAClient> for a client.

## Topics

### Articles

- <doc:ServingTLS>
- <doc:ReloadingWithoutRestart>
- <doc:ConnectingAsAClient>
- <doc:DesignNotes>

### Naming and loading a server identity

- ``ServerIdentity``
- ``LoadedServerIdentity``
- ``CertificateSummary``
- ``ServerIdentityError``

### Serving TLS

- ``ServerTLSContext``
- ``ServerTLSOptions``
- ``MinimumTLSVersion``

### Reloading without restarting

- ``ReloadableServerTLS``
- ``ReloadOutcome``

### Trusting a server

- ``ClientTrust``
- ``CertificateSource``
- ``CertificatePin``
- ``ClientTLSContext``
- ``ClientTrustError``

### Deciding what a listener exposes

- ``BindExposure``
- ``isLoopback(host:)``
