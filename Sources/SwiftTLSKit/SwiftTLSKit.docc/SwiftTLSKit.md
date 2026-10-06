# ``SwiftTLSKit``

TLS configuration for SwiftNIO servers and clients, written once.

## Overview

SwiftTLSKit holds the TLS decisions that were being re-made in every server: which files are
an identity, what makes them unfit to serve, and what a plaintext listener exposes. It is
configuration only. It opens no sockets and owns no event loops.

## Topics

### Deciding what a listener exposes

- ``BindExposure``
