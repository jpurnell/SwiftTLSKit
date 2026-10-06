# Connecting as a Client

Choose who may have signed the server's certificate, and name the server you expect.

## Overview

``ClientTrust`` says which certificate authorities a client accepts. Every case validates the
server's chain and checks the certificate against the hostname; they differ only in whose
signature counts.

| Case | Trusts |
|---|---|
| ``ClientTrust/systemRoots`` | the platform's root store |
| ``ClientTrust/additionalRoots(_:)`` | the platform's root store and the certificates supplied |
| ``ClientTrust/onlyRoots(_:)`` | the certificates supplied, and nothing else |
| ``ClientTrust/pinned(_:additionalRoots:)`` | as `additionalRoots`, and the leaf must also match a pin |

There is no case for "trust anything". A development server with a self-signed or privately
issued certificate is trusted by supplying that certificate, which is what `onlyRoots` and
`additionalRoots` are for.

## Adopting it in a NIO client

Build a ``ClientTLSContext`` once. In the channel initializer, add its handlers ahead of the
application's — for a WebSocket client, ahead of the HTTP handlers that perform the upgrade:

```swift
import NIOCore
import SwiftTLSKit

/// Once, at start-up.
func makeClientTLS() throws -> ClientTLSContext {
    try ClientTLSContext(trust: .systemRoots)
}

/// In `ClientBootstrap.channelInitializer`, for a `wss://` URL whose host is `host`.
func addTLS(_ tls: ClientTLSContext, to channel: any Channel, host: String) -> EventLoopFuture<Void> {
    channel.eventLoop.makeCompletedFuture {
        try tls.addHandlers(to: channel.pipeline.syncOperations, serverHostname: host)
    }
}
```

`serverHostname` is a `String`, not an optional. A name is sent as SNI and checked against
the certificate. An IP address cannot be sent as SNI, so none is sent, and the certificate is
checked against the address the channel is connected to — which has to appear among the
certificate's IP subject alternative names. An empty string is refused.

## A library that takes a TLSConfiguration

Some libraries build their own handlers and accept only a `TLSConfiguration`.
``ClientTrust/makeTLSConfiguration(minimumVersion:applicationProtocols:)`` produces one, with
verification left exactly as NIOSSL's client default sets it — full:

```swift
import NIOSSL
import SwiftTLSKit

func configuration(trustingPEMFile path: String) throws -> TLSConfiguration {
    try ClientTrust.onlyRoots([.pemFile(path)]).makeTLSConfiguration()
}
```

It throws ``ClientTrustError/pinsNeedHandlers`` for a pinned trust. A configuration cannot
carry a pin, and returning one without it would be a connection that looks pinned and is not.

## Pinning

A pin is an extra condition on top of ordinary verification: after the chain and the hostname
have been checked, the server's own certificate must also have a particular SHA-256, either of
the whole certificate or of its public key.

```swift
import SwiftTLSKit

func pinnedTrust(publicKeySHA256: String) throws -> ClientTrust {
    .pinned([try CertificatePin.publicKey(sha256: publicKeySHA256)])
}
```

- Pin the **public key** to survive renewals that keep the key, and the **certificate** to
  require this exact issuance.
- Several pins are alternatives. Pin the current key and its successor to rotate without an
  outage.
- The digests are the ones ``CertificateSummary/certificateSHA256`` and
  ``CertificateSummary/publicKeySHA256`` report on the server, so the value to pin can be
  read from the server's own start-up log.

A pin never loosens anything. A certificate that matches a pin and chains to no trusted root
is refused, as is one presented for the wrong hostname.

### When the pin is checked

NIOSSL offers a verification callback, but it *replaces* chain validation rather than adding
to it. Enforcing a pin there would mean re-implementing validation, so the pin is checked by
a second handler immediately after the handshake completes. That handler holds every write
issued before its verdict, so no application byte is sent to a server that then fails the
pin; on a mismatch it fires ``ClientTrustError/pinMismatch(certificateSHA256:publicKeySHA256:)``
and closes the connection.

The consequence to know about is that the TLS handshake itself completes before the pin is
judged: a server that fails its pin sees a finished handshake followed by a close.

## Development certificates on Apple platforms

When the system root store is consulted — every case except ``ClientTrust/onlyRoots(_:)`` —
NIOSSL verifies through Security.framework on Apple platforms, and Apple's policy applies to
every server certificate, whoever signed it: one issued on or after 1 July 2019 must be valid
for 825 days or fewer, and must carry the server-authentication extended key usage and a
subject alternative name. A long-lived development certificate trusted through
`additionalRoots` fails there with a verification error that does not say why. Either issue
it for 825 days or fewer, or trust it with `onlyRoots`, which verifies with BoringSSL.

On the same path a wrong hostname is reported as a certificate verification failure rather
than as NIOSSL's hostname error, because Security.framework judges chain and name together.
The connection is refused either way.
