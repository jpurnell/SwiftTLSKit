# Security review for 1.0

**Date:** 2026-11-13. **Tree reviewed:** `main` at `f81dc43` plus PR #6 (`ClientHandshakeFailure`).
**Method:** three independent reviewers, read-only, each given the package rules and one area and
*none* of the author's conclusions: (1) key files and reload, (2) loopback and exposure
classification, (3) client trust and pinning. Their reports are leads. Each finding below says
what was **reproduced here by a failing test** and what is **reasoned only**.

## Fixed (each with a test that failed first)

| # | Finding | Sev. | Evidence |
|---|---|---|---|
| 1 | `isLoopback("127.0.0.1\0.evil.com")` is `true`, and `BindExposure.classify` returns `.loopbackPlaintext` for it. Swift passes a `String` to `inet_pton` as a C string, which ends at the NUL. Fail-open against the package's own rule. Also made `IPAddressLiteral.isAddress` and both parsers accept such text. | **High** | Reproduced: 16 failing expectations. Fixed at the root, in `IPAddressLiteral`. |
| 2 | A key or chain **path** with a NUL (`…/privkey.pem\0.junk`) opened `privkey.pem`, so the path in errors and logs was not the path read. Same cause as 1. | Medium | Reproduced: `load` succeeded. Now `.unreadable`. |
| 3 | The `chmod 600 PATH` hint put a path into a command an operator pastes, unquoted: `/etc/ssl/a; rm -rf ~` was a command. Now shell-quoted when needed (ordinary paths unchanged) and `--` before a path that begins with `-`. | Low | Reproduced. |
| 4 | A pin accepted a colon anywhere (`::` + 64 hex, `0:…:2`). Now colons only between bytes, as `openssl` prints them. Not a security bypass (still exactly 64 hex digits); stricter than documented before. | Low | Reproduced. |
| 5 | `open` lacked `O_NOCTTY`. Added; harmless. | Low | **No test**: not practically testable. |

## Confirmed fine, now pinned by tests

- Pin digests equal OpenSSL 4.1.0's for a fixed certificate (certificate SHA-256 and SPKI SHA-256), where every earlier test hashed with this package on both sides. Review lead; the digests were already correct. (`DigestReferenceTests`)
- An unopenable key (a symlink that loops) is `.unreadable` for every user. This replaces, for root, the coverage that `ServerIdentityLoadingTests.swift:71` loses when the CI container runs as root: that test is skipped for root and only ever covered EACCES. The mode checks themselves ran, and passed, as root on Linux.
- `foo.localhost`, `localhost.`, `.localhost` are not loopback (over-strict against RFC 6761, fail-closed). Pinned so that widening the rule is a decision.
- Control characters, fullwidth digits and non-ASCII are not loopback.
- Not changed, with the reviewer's evidence: symlinks are judged on the opened descriptor; FIFOs/devices refused; size and growth bounded; reload never pairs an old key with a new certificate (`requireMatch`), keeps the old context on failure, and uses content fingerprints, not mtime; no bytes before the pin check (reviewer read the handler); `.pinned([])`, `.onlyRoots([])` and `.additionalRoots([])` are errors, not "trust everything"; the leaf is what is hashed; nothing below TLS 1.2 is expressible; no `withUnsafe*`, `try!`, force unwrap, or clock read in `Sources/`.

## Rejected

- **Use NIOSSL's `additionalPeerCertificateVerificationCallback` for the pin** (reviewer 3, to close the post-handshake window). The callback is `_NIOAdditionalPeerCertificateVerificationCallback`: underscored, the same fragility removed from `CertificateSummary` in step 2. And the window leaks nothing: the pin handler acts on `handshakeCompleted` before NIOSSL releases any read, and holds writes. Keep post-handshake pinning. (Candidate for 1.x if NIOSSL stabilises it.)
- Zeroing key bytes in memory (reviewer 1, info): the rule is about errors, descriptions and logs.

## Needs a decision (changes the public API or a stated limit)

1. **Key owner.** Only the mode is checked (documented limit). Reviewer 1: a root process accepts a `0600` key owned by an unprivileged user, who can then read and *replace* it. Proposed: require `st_uid` to be the effective user or root, a new `ServerIdentityError` case (`privateKeyOwnedByAnotherUser`). Testable on Linux CI, which runs as root (`chown`). **Recommend yes.**
2. **`ClientTLSContext.makeHandlers` is public and returns `[any ChannelHandler]`.** A caller can add only `handlers[0]` and silently lose the pin. Reasoned only. Options: make it internal, return one composite handler, or have the pin handler fail closed if not installed. Belongs to the API audit (step 6). **Recommend a composite or internal.**
3. **No peer certificate is reported as `pinMismatch("", "")`**, whose message reads "a certificate with SHA-256 ." Fail-closed, but misleading. Proposed: a distinct `ClientTrustError.noPeerCertificate`. A new case in an exhaustive enum: pre-freeze, so now or never. **Recommend yes.**
4. **Parent directory.** A key in a world-writable directory can be replaced by another user, since the owner is not checked either. Proposed: document as a limit (checking directory modes means sticky-bit and ownership rules that differ by platform). **Recommend document.**
5. **ACLs and xattrs** (macOS `chmod +a`, Linux POSIX ACL) are ignored: a `0600` key with an "everyone: read" ACL loads. Reviewer 1 reproduced it on macOS. Proposed: document as a limit, not fix. **Recommend document.**
6. **A truncated chain** (leaf only, intermediates not yet written) validates and is served; the next reload fixes it. Design question, not a defect. **Recommend document.**
7. **Log forging via a path** with a newline in an error message. Paths come from operator configuration. **Recommend document.**
