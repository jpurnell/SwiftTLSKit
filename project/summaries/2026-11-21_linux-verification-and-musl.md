# Session summary, 2026-11-21: Linux verified locally, Musl fixed (1.0.1)

## What was done
- Read and corrected `project/plans/proposals/LinuxSupport.md`. Premise confirmed from the source: no
  Network, Security or CryptoKit use; Linux already worked on Glibc. Real gaps were verification
  (GitHub only), Musl, and the bare-box CA behaviour.
- Runner is `starscream.local` (Ubuntu 26.04.1, x86_64, uid 1000, swiftly with 6.4.2 and 6.2.4,
  passwordless ssh), not a container. `scripts/linux-test.sh` syncs, builds and tests there;
  `--no-ca-store` hides `/etc/ssl` with bubblewrap (no sudo; plain `unshare` is blocked by AppArmor);
  `--musl` builds against the static Linux SDK.
- **Musl:** red reproduced (`in6_addr` has no member `__in6_u`); `ipv6Bytes` now fills a 16-byte array
  through `inet_pton`'s `void *`. Builds for x86_64 and aarch64 Musl. Build-only: the static SDK has
  no `Testing` module.
- **Zone suffix:** Darwin's `inet_pton` accepts `fe80::1%eth0`, Glibc's does not, and Glibc's NIOSSL
  sent it as SNI. Now not an address anywhere, and `makeHandlers` refuses it as a server name.
- **Bare box:** NIOSSL ignores `SSL_CERT_FILE`; with no CA file or directory, `.systemRoots` and
  `.additionalRoots` throw `contextRejected` at construction (reason empty), `.onlyRoots` works.
  The proposal had predicted `certificateNotTrusted` per probe; that was wrong.

## Verified
Linux Glibc 203 tests (Swift 6.4.2; 6.2.4 ran 193 before the last vectors), macOS 205, bare-box 3
(negative control fails as it should), Musl x86_64 and aarch64 build clean. Quality gate 51/51.

## Not verified / open
- 6.2.4 not rerun after the final test additions; arm64 Linux not run at all (CI only).
- Static SDK bundle installed from a download over HTTPS without a published checksum (swift.org
  lists 6.4.3 only); SHA-256 `3786b179936d9cc9e266dd506bd1654176358d7b25288e243359f4d17cc4dc5a`.
- Bare-box variant "empty bundle file" not re-run with a real file (first attempt used /dev/null).
- Empty `contextRejected` reason text could be made clearer (no API change); not done.
- SwiftPenTest on Linux: separate proposal (argument-parser, `.copy("PenTestCore.docc")` resource
  bundle on a one-file deploy, `import os` guards). Other adopters' Linux builds not checked.

## Next
Merge, tag 1.0.1, then move the two beta-pinned adopters when SwiftHTTPService leaves its soak.
