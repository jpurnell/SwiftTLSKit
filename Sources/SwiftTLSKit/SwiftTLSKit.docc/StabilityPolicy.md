# What 1.x promises

What will not change in a 1.x release, what may, and what the package does not do.

## Overview

SwiftTLSKit follows semantic versioning. A 1.x release does not change source that compiled against
an earlier 1.x release, with the exceptions below, each of which is a decision recorded in the
design notes and not an oversight.

## What is promised

- **Every public type, function, property and case keeps its name, its signature and its meaning.**
  A new one may be added; one is never removed or reshaped in a 1.x release.
- **The platforms.** macOS 14, iOS 17, tvOS 17 and visionOS 1, and Linux on x86_64 and arm64. The
  floor does not rise in 1.x. Linux is built and tested in CI with Swift 6.2 and the newest stable
  toolchain.
- **The safety rules.** Half an identity is an error and never plaintext. No case, flag or parameter
  disables certificate or hostname verification. Nothing read from a key file reaches an error, a
  description or a log. A host that is in any doubt is not loopback. A release that weakened one of
  these would be a security fix in the other direction, and would not be called minor.

## Enumerations are closed

``ServerIdentityError``, ``ClientTrustError``, ``ClientHandshakeFailure``, ``ReloadOutcome``,
``ClientTrust``, ``CertificateSource``, ``BindExposure`` and the package's other enumerations are
exhaustive, and **adding a case is a major version.** A `switch` over one that has no `default` keeps
compiling for the whole of 1.x.

What this costs, and why it was chosen: a capability that needs a new refusal (client certificates,
encrypted keys) cannot arrive as a new case on an existing error in 1.x. It arrives as a new type or a
new initialiser with its own error. The set of cases was settled before 1.0, with the cases the 1.0
review turned up already in it.

## What is not API

- **The text of a `description`.** The message a person reads is for a person, and may be reworded to
  say it better. Where a message tells an operator what to run, as the `chmod` hint does, the
  command is kept correct, but the sentence around it is not a contract. Match on the case, never on
  its text.
- **The text inside ``ClientHandshakeFailure/other(_:)``.** It is the TLS library's own wording.
- **How a certificate's names are written**, beyond this: an IPv6 address is written as RFC 5952
  writes it (`::1`), and a DNS name that is not printable ASCII is left out.

## The libraries it is built on

SwiftTLSKit's public interface names types from SwiftNIO: `ChannelPipeline.SynchronousOperations`
and `any ChannelHandler` in the functions that put TLS into a pipeline, and NIOSSL's
`TLSConfiguration` in ``ClientTrust/makeTLSConfiguration(minimumVersion:applicationProtocols:)``, the
one function that exists to hand a configuration to a library that builds its own handlers.

That ties 1.x to NIO 2 and NIOSSL 2. **A move of the package to NIO 3 or NIOSSL 3 would be package
2.0.** The package's dependency ranges are set so that a 1.x consumer is never resolved onto either.
Everything else that is NIOSSL's — the context, the parsed certificates — is not in the public
interface: it is `package`-level, visible to this package's own tests and to nothing else.

## Behaviour that was made stricter before 1.0

A refusal added after 1.0 would be a behaviour change that stops a server starting, so what a server
is refused for was settled first. ``ServerIdentity/load(now:)`` refuses a private key that:

- its group or others can read or write;
- is owned by a user other than the one running the process and root;
- has an access control list (macOS);
- is in, or below, a directory that its group or others can write, unless that directory has the
  sticky bit.

## Limits that are not defects

The package does not claim these, and says so:

- **Only the key's own directory chain is checked, and only its mode.** The owners of those
  directories are not examined, so a directory owned by another user and not writable by anyone else
  still lets its owner replace the key.
- **The certificate chain is public and is not checked at all**: not its mode, its owner or its
  directory.
- **A chain that is being rewritten can be read half-written.** A leaf with none of its intermediates
  validates, and is served until the next reload replaces it. The remedy is to write files the way
  certbot does, by renaming a finished file over the old one.
- **A path in an error is escaped; it is not made safe to paste** other than in the one command the
  message suggests, which is quoted.
- **Host names are not resolved.** ``isLoopback(host:)`` and ``BindExposure`` read text. A name that
  resolves to this machine is not loopback unless it is `localhost`.
- **No mutual TLS, and no encrypted private keys.** Both would arrive as new types in a 1.x release,
  not as changes to these.
