# Design Proposal: Linux support, verified locally (no GitHub dependency)

**Status:** Proposed, 2026-11-21. Not implemented. This file is the only artefact; no code was changed.
**Template:** `development-guidelines/rules/design_proposal.md` (16 sections) was present in the vendored
directory and is followed below, with the layout of `project/plans/upcoming/SwiftTLSKit-1.0-readiness.md`
(Decisions / Objective / ... / Adversarial Review / Open Questions). The `devguidelines` MCP was not consulted;
the vendored file sufficed. `project/plans/proposals/` held only `.gitkeep`, so there was no earlier proposal to copy.

---

## 0. Verified first: no Apple TLS API is in use, and Linux support already exists

A port from Network.framework, Security.framework, Keychain or CryptoKit might be assumed to be needed.
**None is used, and Linux support already exists.** Read from the source, not from memory:

- `grep` for `Network`, `Security`, `SecIdentity`, `SecCertificate`, `Keychain`, `NIOTransportServices`,
  `CryptoKit` over `Sources/` finds no import or use. The only mentions of Security.framework are in doc comments
  (`ClientHandshakeFailure.swift:43,53`, `TestInstant.swift:11`) that describe how Apple's verifier behaves when
  NIOSSL consults the system roots.
- The package already contains Linux branches (`#if canImport(Darwin) / Glibc / Musl`) in `PEMFile.swift:3-9`,
  `IPAddressLiteral.swift:1-7,37`, `ClientHandshakeFailure.swift:120`, and the test `KeyFileHardeningTests.swift:7`.
- `project/master_plan.md:49,249,297` and `CHANGELOG.md:118-121` record that Linux (x86_64 and arm64; Swift 6.2
  and latest) has been built and tested in GitHub CI since 2026-11-11 (PR #4): "all eight jobs green, 135 tests on
  each Linux job", "Linux needed no source change". `StabilityPolicy.md:15` declares Linux in the 1.x platform floor.
  (I did not re-run that; it is the repository's own claim.)

So the real problem is not "make it build on Linux". It is:

1. **Linux is verified only on GitHub Actions** (`.github/workflows/ci.yml`, `upstream.yml`), which the owner does
   not want to depend on. There is no local Linux path today.
2. **Local tooling has nothing to run Linux with** (section 3.6).
3. **A few Linux paths are unverified or probably broken** (Musl; running as non-root; system CA store on a bare
   box) and none is exercised locally.
4. **The motivating consumer, SwiftPenTest, has never been built on Linux**, and its gaps are outside this repo
   (section 7).

This proposal therefore asks for a small amount of code (one probable portability fix and tests) and mostly a
local verification harness. If the owner wanted a larger rewrite, section 12 argues that nothing requires one.

## Decisions (proposed, for the owner to confirm; see Open Questions)

1. Keep the single code path on swift-nio-ssl everywhere. Do not introduce NIOTransportServices.
2. Establish a local Linux runner (Apple `container`, else Colima+Docker, else a UTM VM) with a checked-in script.
3. Leave GitHub Actions in place as a secondary, non-required signal.
4. No public API change. No adopter change.

---

## 1. Objective

Make "builds, tests and runs on Linux" a claim the owner can verify from a laptop in under ten minutes, with no
GitHub round-trip, on the toolchains that matter (Swift 6.2 floor, 6.4.2 current), as non-root and root, on x86_64
and arm64 where possible; and make sure a SwiftPenTest binary deployed to a cheap Linux box can use this package.

Non-goals: Windows, Android, a new public API, Network.framework or Security.framework support (neither is used).

## 2. Motivation

SwiftPenTest must run on a cheap Linux box outside the owner's LAN, because a probe from inside the LAN says
little about what the internet sees. SwiftPenTest depends on SwiftTLSKit 1.0.0 (`ALPNChecker.swift:4`, uses
`ClientTrust` and `ClientTLSContext`; its tests use `SwiftTLSKitTestSupport`'s `TestAuthority` and
`InMemoryServerIdentity`). That path is the client half only: **no key file, no PEM permission check and no
reload is involved**, so the Linux-sensitive parts of `PEMFile` are not on SwiftPenTest's critical path.

## 3. Findings (ground truth)

### 3.1 Apple-only API usage in SwiftTLSKit today (item 1)

| API | Where | Apple-only? | Linux status |
|-----|-------|-------------|--------------|
| `Foundation` (`FileHandle`, `Data`, `Date`) | `PEMFile`, `ReloadableServerTLS`, `ServerIdentity`, `ServerTLSContext`, `CertificateSummary`, `CertificatePin`, `ServerIdentityError`; TestSupport | No | swift-corelibs-foundation |
| `Darwin`/`Glibc`/`Musl` (`open`, `fstat`, `stat`, `realpath`, `inet_pton`, `strerror`, `geteuid`) | `PEMFile.swift`, `IPAddressLiteral.swift` | Guarded | Glibc branch built in CI; Musl branch never built (3.7) |
| `acl_get_fd_np`, `ACL_TYPE_EXTENDED`, `acl_free` | `PEMFile.swift:127-133` | Yes, `#if os(macOS)` | Excluded on Linux by design; a POSIX ACL shows in the group bits, which the mode check already refuses |
| `in6_addr.__u6_addr` (Darwin) vs `__in6_u` (Glibc) | `IPAddressLiteral.swift:37-41` | Layout-specific | `#else` assumes Glibc's field name; see 3.7 |
| `wrongHostname(under:)` | `ClientHandshakeFailure.swift:118-125` | Behaviour differs on Darwin | Linux returns `.hostnameMismatch`; CI-tested |
| Security.framework | none in code | n/a | n/a |
| Network.framework, `NIOTransportServices`, Keychain, `SecIdentity`, `SecCertificate`, CryptoKit | **none** | n/a | n/a |
| `os` / `Logger` | none in this package (it has no logger by rule) | n/a | n/a |

The one behavioural platform difference is *who verifies the chain when `ClientTrust` consults the system roots*:
Security.framework on Apple (825-day rule, one combined verdict), BoringSSL against a CA file on Linux. That is
why `TestInstant` dates fixtures from 2019-01-01 (harmless on Linux).

### 3.2 Manifest and dependencies (item 2)

`Package.swift` (tools-version 6.2): `platforms: [.macOS(.v14), .iOS(.v17), .tvOS(.v17), .visionOS(.v1)]`.
SwiftPM has no `.linux` entry and does not need one: an absent platform list entry means "no minimum", so Linux
is not excluded. Nothing in the manifest has to change.

| Dependency | Declared | Resolved (Package.resolved, 2026-11-13) | Linux |
|------------|----------|-----------------------------------------|-------|
| swift-nio (`NIOCore`, `NIOConcurrencyHelpers`, `NIOTLS`; tests add `NIOPosix`, `NIOEmbedded`) | `from: 2.105.0` | recorded in lockfile | Yes (primary platform) |
| swift-nio-ssl (`NIOSSL`) | `from: 2.37.6` | 2.37.6 | Yes, bundles BoringSSL |
| swift-crypto (`Crypto`) | `3.0.0..<5.0.0` | 4.5.2 | Yes (BoringSSL-backed; CryptoKit on Apple) |
| swift-certificates (`X509`), swift-asn1 | `from: 1.5.0` / `1.1.0` | 1.21.0 / 1.7.3 | Yes; linked by `SwiftTLSKitTestSupport` and tests only |
| swift-docc-plugin | `from: 1.4.3` | n/a | Plugin; not built by `swift build` |
| swift-nio-transport-services | **not a dependency** | n/a | Apple-only; stays out |

"Yes" for Linux is the upstream packages' published support plus this repo's CI record; I did not build them
locally on Linux.

### 3.3 Public API and what would need to change (item 3)

Nothing needs to change shape. The public surface (`ServerIdentity`, `LoadedServerIdentity`, `ServerTLSContext`,
`ReloadableServerTLS`, `ClientTrust`, `ClientTLSContext`, `CertificatePin`, `ClientHandshakeFailure`,
`BindExposure`, ...) is expressed in Foundation, NIOCore and NIOSSL types (`master_plan.md:50-55`). There is no
Apple type in any signature. `PEMFile` is `internal`.

Dependents (found by scanning every `Package.swift` under `Swift/` for `SwiftTLSKit`; the 11-package count in
`master_plan.md` matches, plus one stale worktree copy of SwiftHTTPService):

| Dependent | Requirement | Platforms declared | Source impact of this proposal |
|-----------|-------------|--------------------|--------------------------------|
| SwiftPenTest | `from: "1.0.0"` | macOS 15 | None |
| SwiftHTTPService | `exact: "1.0.0-beta.1"` (main: up-to-next-minor 1.0.0 per master plan; the manifest I read still shows the beta pin) | macOS 14 | None |
| SwiftPushHub | `.upToNextMinor(from: "1.0.0")` | macOS 15 | None |
| SwiftDiagnosticsHub | `.upToNextMinor(from: "1.0.0")` | macOS 15, iOS 17, watchOS 10, tvOS 17, visionOS 1 | None |
| FleetWatch | `.upToNextMinor(from: "1.0.0")` | macOS 15 | None |
| ijs-dashboard-server | `.upToNextMinor(from: "1.0.0")` | macOS 14 | None |
| swiftMoE | `exact: "1.0.0-beta.1"` | macOS 14 | None |
| IconquerServer / IconquerTournament / IconquerClient / IconquerCLI | `from: "1.0.0"` (Server verified; others per master plan) | macOS 14 (Server) | None |
| VaultMCP, SwiftMCPServer, SwiftMCPClient | **not dependents** | n/a | None |

Source compatibility: no source break, no version bump required for the API. Only a patch release (1.0.1) if the
Musl fix in 3.7 ships. Whether any dependent builds on Linux is its own question (section 7); this repo can only
say that SwiftTLSKit does not stop it.

### 3.4 Test fixtures (item 4)

`SwiftTLSKitTestSupport` (`TestAuthority`, `TestLeaf`, `InMemoryServerIdentity`, `SeededGenerator`,
`TestInstant`, `TestKeyMaterial`) imports only `Crypto`, `Foundation`, `X509`, `SwiftASN1`, `NIOConcurrencyHelpers`
and `SwiftTLSKit`. **No Apple-only API.** Keys are generated in memory from an injected generator; nothing touches
disk. `InMemoryServerIdentity` and `TestLeaf.serverContext(now:)` build contexts from memory, which is what
SwiftPenTest's `ALPNCheckerTests` use (`ALPNCheckerTests.swift:18-19,48-55`). The fixtures therefore work on Linux
as shipped; the package's own 135-test suite is reported green on Linux in CI. Only the suites that test file
handling (`KeyFileHardeningTests`, `ServerIdentityLoadingTests`, `KeyFileHandlingTests`, `ReloadTests`) write to a
temporary directory.

### 3.5 Certificate and key material (item 5)

Loaded from two PEM files (`ServerIdentity`, `PEMFile.read`): `open(O_RDONLY|O_NONBLOCK|O_NOCTTY|O_CLOEXEC)`,
`fstat` on the descriptor, regular files only, <= 1 MiB, then for the key: no group/other bits (0600), owner is
euid or root, no group/other-writable ancestor directory unless sticky (`requireUnwritableAncestors`), macOS ACL
check. Reload is polling (`reloadIfChanged`, `reloadOnEach`); no inotify (`ReloadingWithoutRestart.md:154`). There
is no Keychain path at all, so there is nothing to translate. Linux equivalent is what already runs: PEM files.

Linux-specific consequences worth stating for operators, not code changes:

- Distro-default key locations (`/etc/ssl/private/*.key`, root:ssl-cert 0640) are **refused** (group-readable).
  Certbot's `live/` keys are symlinks to 0600 root files in 0700 directories and pass only for a process running as
  root. A non-root service needs a deploy-hook copy to a service-owned 0600 file. Documented as an operator
  procedure, not a loosening of the check (see section 12 on why the check stays).
- POSIX ACLs fold into the group bits (documented, `DesignNotes.md:234`).
- Inside a container running as root, the owner check is satisfied trivially, so `ServerIdentityLoadingTests.swift:71`
  and similar lose coverage (`security_review_1.0.md:22`). Running the harness non-root restores it (section 5, step 2).

### 3.6 What is available locally (read-only checks, 2026-11-21)

| Check | Result |
|-------|--------|
| `which docker podman colima lima limactl orbstack container multipass qemu-system-aarch64 tart` | **none installed** |
| `/Applications` | `UTM.app` present (installed Nov 15). No Docker Desktop, OrbStack, Parallels |
| UTM VM library | one VM, "Mr. Bigglesworth", **architecture `ppc`** (QEMU). Not usable for Swift |
| `ssh pi-vim` (192.168.64.4, a UTM-style NAT address) | **timed out**; VM presumably off; OS/toolchain unverified |
| `ssh chromedome`, `ssh teletran-2` | both `Darwin 24.6.0 x86_64`, Swift 6.4.2 (swift-6.4.2-RELEASE), no docker/podman. macOS, so they do not help |
| Local toolchains | Xcode toolchain Swift 6.4.2 (swiftly also lists 6.3.3, 6.4.1); host macOS 27.2.1 arm64, 10 cores, 32 GB RAM, ~162 GB free |
| `swift sdk list` | "No Swift SDKs are currently installed" |
| Homebrew | present; `brew info` shows formulae `container` 1.7.1, `colima` 0.10.3, `lima` 2.3.0, `docker` 29.10.0, `podman` 6.2.0 (metadata only; nothing installed or tried) |
| Docker Hub `library/swift` (registry API) | tags `6.4`, `6.4.2`, `6.4.2-noble`, `6.4-noble-slim`, `6.2`, `latest` exist (HTTP 200); `6.4` manifest list has `amd64` and `arm64`. Newer `6.4.3` tags also exist |
| Static Linux SDK | `download.swift.org/.../swift-6.4.2-RELEASE_static-linux-0.1.0.artifactbundle.tar.gz` returns HTTP 200 |

Note on versions: the Docker `swift:6.4.2` image existing is verified; that it builds this package is not.

### 3.7 Probable defects / unverified paths found in reading

1. **Musl IPv6 field (probable build break).** `IPAddressLiteral.ipv6Bytes` reads `address.__in6_u.__u6_addr8` in
   the `#else` of `#if canImport(Darwin)`. That is the Glibc field name. The file also imports `Musl`, whose
   `in6_addr` uses a differently named member (from my memory of musl headers; **unverified**). So a Musl or
   Alpine or static-SDK build probably fails to compile, even though the code claims Musl support. CI has no
   Musl job (readiness doc listed one as optional, Open Question 3).
2. **Root-only coverage** (3.5).
3. **System CA bundle on a bare box.** `ClientTrust.systemRoots` leaves NIOSSL's default trust store in place
   (`ClientTrust.swift:92`, `ContextConfigurationTests` "System roots leave the trust store at the platform
   default"). On Linux NIOSSL loads a CA file from well-known paths such as `/etc/ssl/certs/ca-certificates.crt`
   (from memory, **unverified**; no `swift-nio-ssl` checkout exists locally to read). A minimal image or VPS
   without the `ca-certificates` package would find no roots, and every probe would report
   `certificateNotTrusted`. SwiftPenTest on a cheap box hits this on day one. The fix is operational (install
   `ca-certificates`), plus a test and doc, not a new API.
4. **Timing assumptions in tests** (e.g. reload mtime resolution on ext4/overlayfs versus APFS) are not known to be
   a problem; they passed on GitHub's Linux. Unverified for a local overlay filesystem.

## 4. Proposed architecture

**Recommendation: keep one code path on swift-nio-ssl on every platform; add no platform abstraction seam and no
NIOTransportServices.** The existing `#if canImport(...)` blocks are the right size: they exist only where the C
library differs (`stat`, `inet_pton`, ACLs). Rationale:

- The package's core value (typed refusals, no way to disable verification, pinning judged after the handshake)
  is implemented on NIOSSL handlers. Introducing a second TLS backend on Apple would mean two verifiers with
  different answers (the 825-day rule shows how far they diverge) and a test matrix that doubles.
- There is nothing to abstract: no Apple TLS API is in use now.
- NIOTransportServices belongs to the *transport* (listeners/connections), which this package deliberately does
  not own ("Configuration only. No sockets, no event loops" in `CLAUDE.md`). A consumer that chose it would still
  need NIOSSL-style handlers; that is a consumer decision, not a Linux requirement.

Changes in the library, in priority order:

1. Make `IPAddressLiteral.ipv6Bytes` platform-neutral: `var bytes = [UInt8](repeating: 0, count: 16)` and
   `inet_pton(AF_INET6, literal, &bytes)`. `dst` is `void *`, so the implicit array-to-pointer conversion applies
   on every libc. This removes `in6_addr`, the 16-element tuple unpacking, and the `__u6_addr`/`__in6_u` split and its `#if`.
   Respects the repo's no-`withUnsafe*` rule (the existing file comment points at this technique). **Unverified**
   that implicit conversion applies to `inet_pton`'s imported parameter type on all three libcs; the first thing
   the red step must establish.
2. No other source change is proposed. Everything else is harness, tests and documentation.

## 5. Ordered implementation plan (TDD)

Each step ends green locally on Linux, then macOS; gate 0 errors / 0 warnings, no suppressions, one commit per
green state.

**Step 0. Prerequisite: a local Linux runner (no code).**
Pick the first that works (section 6): Apple `container`, else Colima+Docker, else a UTM Ubuntu arm64 VM. Record the
choice in `project/decisions/`.

**Step 1. RED: the harness, run before changing anything.** Add `scripts/linux-test.sh` (a script, not Swift):

```
# usage: scripts/linux-test.sh [image-tag] [user]   defaults: 6.4.2-noble, non-root
#   copies the tree WITHOUT .build and .git to a throwaway dir inside the container,
#   builds with --scratch-path outside the mount so macOS .build is never touched,
#   runs: swift --version; uname -m; swift package resolve; swift build --build-tests; swift test
```

Matrix to run once by hand: `{6.2-noble, 6.4.2-noble}` x `{root, uid 1000}` x `{arm64 native}` (x86_64 only if
emulation is available, see section 6). Expected: 135 tests green as root (matches CI). Any failure as uid 1000 is a
real finding and gets a failing test first (for example a suite that assumes it may write to `/tmp` or owns
`/` ancestors). **Unverified whether any fails**; the plan treats it as a finding, not a given.

**Step 2. RED: a Musl build.** Install the static SDK (`swift sdk install <url>` with its checksum, taken from
swift.org; the 6.4.2 static-linux bundle URL answered 200) and run
`swift build --swift-sdk aarch64-swift-linux-musl` (and `x86_64-swift-linux-musl`). Expect the `__in6_u`
failure (3.7.1). Build-only: macOS cannot run those products. This is the red test for change 4.1 because the
"test" is a compile. Pair it with the existing `IPAddressLiteralTests`, which stay green on Linux Glibc.
Alternative if the SDK does not install: `swift:6.4.2` Alpine-based image is not offered in the tag list I
saw (only noble, jammy, bookworm, trixie, resolute, rhel, amazonlinux2023, slim), so the static SDK or a manual
Alpine toolchain is the route; **unverified**.

**Step 3. GREEN: the IPv6 fix.** Implement 4.1; `IPAddressLiteralTests` and `SubjectAlternativeNameTests` (IPv6
SANs) stay green on macOS, Glibc, Musl-build. Add test vectors that fail if byte order or zero-compression is wrong
on any libc (`::1`, `2001:db8::1`, `::ffff:192.0.2.1`, malformed inputs). Refactor: delete the now-dead branch.

**Step 4. RED/GREEN: system roots on a bare box.** Add a test, skipped when it cannot apply, that builds
`ClientTLSContext(trust: .systemRoots)` and handshakes with a loopback server whose chain is *not* publicly
trusted, expecting `.certificateNotTrusted`, and one with a server trusted only through `.additionalRoots`
expecting success. Run it in a container *with* and *without* `ca-certificates` (`apt-get purge` in a scratch
image) to learn what NIOSSL actually does when the store is absent. Outcome decides whether a doc sentence
suffices or `ClientTLSContext` should surface a typed error (that would be an API addition; see Q4).

**Step 5 (optional; low value, since `ALPNCheckerTests` already use only in-memory fixtures). Fixture portability evidence.** On Linux, build `SwiftTLSKitTestSupport` as a dependency of a scratch
package that mirrors SwiftPenTest's `ALPNCheckerTests` imports (a throwaway directory outside every repo; do
**not** touch SwiftPenTest here). Confirms the in-memory fixtures work from a consumer, not just from this repo.

**Step 6. Docs and doc housekeeping** (user's release rule): README platform line, `StabilityPolicy.md`
("verified locally with scripts/linux-test.sh; CI optional"), CHANGELOG 1.0.1 and its link definitions,
master_plan Current Status / Known limits / Last Updated (strike through, keep the earlier reasoning, and note
that "Linux needed no source change" turned out not to hold for Musl, if confirmed). Add an operator note on key
permissions and `ca-certificates` (3.5, 3.7.3).

**Step 7 (dropped unless the first runner proves flaky). Optional: the same script on a second environment** (fallback VM, or an x86_64 emulated run) so the
claim "x86_64 and arm64" is not carried by GitHub alone.

## 6. Verifying on Linux without GitHub

**Superseded 2026-11-21:** the owner's machine `starscream.local` (Ubuntu 26.04.1 LTS, x86_64, Swift 6.4.2 through swiftly, non-root uid 1000, passwordless ssh, ca-certificates installed) is a real Linux box and is the runner. `scripts/linux-test.sh` rsyncs the tree there and runs the suite; first run: 193 tests green. No container or VM is needed. The ranking below is kept as the reasoning recorded at the time. arm64 stays covered by GitHub CI only.

Primary, ranked (each unverified until tried; none is installed):

1. **Apple `container`** (`brew info container` -> 1.7.1; Apple-silicon, macOS 26+; host is macOS 27.2.1 arm64).
   Runs arm64 Linux images natively as lightweight VMs; no daemon, no Docker Desktop licence. Pull
   `swift:6.4.2-noble` and `swift:6.2-noble`. Whether `container` runs `linux/amd64` images (Rosetta) on this host is
   unverified; treat x86_64 as optional.
2. **Colima + Docker CLI** (`brew install colima docker`). Same images, mature, can use Rosetta for amd64.
3. **UTM Ubuntu arm64 VM** (UTM.app is already installed; the existing VM is PPC and useless). Install the Swift
   toolchain with swiftly, run the same script over ssh. Slowest to set up, no new tooling to trust, works if
   the container route is blocked. The `pi-vim` host (192.168.64.4) is unreachable now; if it is an arm64 Linux
   VM it may already be this (unverified; ask the owner).

Fallbacks and extras:

- **Static Linux SDK build-only check** on the Mac (Step 2): catches Linux/Musl compile errors in seconds, cannot
  run tests.
- **GitHub Actions**: stays as a weekly/PR signal; acceptable "in a pinch" and already working. Do not make it the
  gate. `quality-gate` is not on the runners either (`ci.yml` header), so the local gate remains authoritative.
- **Chromedome / Teletran 2**: macOS, no Linux, no container runtime. Not useful, as expected.

Swift version constraint: manifest tools-version 6.2 (must stay, siblings are 6.2); local 6.4.2; server toolchain
verified over ssh today at 6.4.2 (matches). Docker images `swift:6.2` and `swift:6.4.2` verified to exist.
Newest is 6.4.3; add it as a third optional tag, not the floor.

Cost: first container run downloads ~1-1.5 GB per image (**unverified size**) and a cold `swift build` of NIO,
NIOSSL (BoringSSL) and X509 is several minutes on 10 cores; warm runs reuse a named volume for `.build`.

## 7. SwiftPenTest on a cheap Linux box: what else must build

Read from `SwiftPenTest/Package.swift` and `Sources/`:

| Dependency | Needed Linux? | Covered by this proposal |
|------------|---------------|--------------------------|
| SwiftTLSKit 1.0.0 (client half) | yes | **Yes** |
| swift-nio, swift-nio-ssl (NIOCore, NIOPosix, NIOTLS, NIOSSL, NIOConcurrencyHelpers) | yes | Same upstreams as here, built by this harness; SwiftPenTest's own build is not |
| swift-crypto, swift-certificates, swift-asn1 (transitive) | resolved; certificates/asn1 only link into tests | Yes |
| swift-argument-parser (`swiftpentest` executable) | yes, Linux-supported upstream | **No** |
| swift-docc-plugin | resolved, not built | n/a |
| `PenTestCore` code | `import os` / `Logger` are guarded by `#if canImport(os)` (`PenTestRunner.swift:1,5,56`); `swiftpentest` imports Foundation | **No**; guards look correct but nobody has built it |
| `PenTestCore` resources: `resources: [.copy("PenTestCore.docc")]` | SwiftPM generates a `Bundle.module` resource bundle that must sit beside the binary; behaviour on Linux when deployed as one file is **unverified** | **No**; flag to the owner |
| `platforms: [.macOS(.v15)]` | harmless for Linux | n/a |
| CA bundle on the target box (`ca-certificates`) | yes for `.systemRoots` | Documented in Step 4/6; the SwiftPenTest CLI may want a `--ca-file` or `--trust` option: **its** design |
| SwiftPenTest has no `.github/workflows`, and no Linux run of any kind | n/a | Needs its own small proposal (est. 1 day): add the same `scripts/linux-test.sh`, build `swiftpentest` for Linux, decide dynamic vs static (Musl) deployment |

If a single static binary for a VPS is desired, the Musl fix (4.1) becomes a prerequisite for SwiftPenTest, not a
nicety; that is the main reason it is in scope here.

## 8. API Surface

No additions, removals or signature changes. (`ClientHandshakeFailure.wrongHostname(under:)` stays; it already
returns the right case per platform.) If Step 4 shows NIOSSL gives an unhelpful error when the CA store is missing,
the only candidate addition is a `ClientTrustError` case or an extra `ClientHandshakeFailure` hint; that would be a
minor release (1.1.0), is **not** proposed now, and is Open Question 4. No MCP schema (section 5 of the template):
not applicable, library only.

## 9. Constraints and Compliance

Swift 6 strict concurrency and no `@unchecked Sendable`/`nonisolated(unsafe)` (unchanged). No force unwraps. No
`withUnsafe*` (the fix in 4.1 uses implicit `&` instead). No suppressions to reach gate 0/0. The package keeps no
logger and no randomness of its own. No private key in the repository: the harness generates keys at run time via
`SwiftTLSKitTestSupport`. The script must not copy or mount host `.build` (macOS artefacts would poison the Linux
build) and must not write into any other repo.

## 10. Source and API Compatibility

None for the API (3.3). Version: the Musl fix is a patch (1.0.1). Adopters on `from: "1.0.0"` or
`.upToNextMinor(from: "1.0.0")` take it automatically; those still on `exact: "1.0.0-beta.1"` (SwiftHTTPService,
swiftMoE) do not, which is the ordering problem already recorded in `master_plan.md:285-296`.

## 11. Dependencies

No new package dependency. No change to floors. swift-nio-transport-services is deliberately not added.

## 12. Backend Abstraction

Not compute-intensive; not applicable. The only platform split is the existing libc `canImport` branch, which this
proposal shrinks by one `#if`.

## 13. Test Strategy

- Existing 135 tests run unchanged under the harness (Linux root and non-root, Swift 6.2 and 6.4.2).
- New: IPv6 literal vectors (3), system-roots-with-and-without-CA-store (Step 4), consumer-style fixture build
  (Step 5; a scratch package, not committed unless trivial).
- Real handshakes over loopback only; no network access beyond SwiftPM resolution. Dates stay fixed; no clock reads.
- Assertions must be correct-answer assertions (`correct_answers.md`): the IPv6 vectors are written from RFC 5952
  forms, not from the function's own output.
- Not run by the harness: the iOS/tvOS/visionOS builds (they need Xcode; `xcodebuild` stays a macOS step).

## 14. Architecture Decision Review

| Decision | Why | Revisit when |
|----------|-----|--------------|
| One NIOSSL path on all platforms | Already the design; one verifier for pinning and errors | NIOSSL 3 / NIO 3 (package 2.0) |
| No platform abstraction seam | Nothing Apple-only to abstract | An Apple-only TLS requirement appears (mutual TLS with Keychain identities, `SecIdentity` from MDM) |
| Local runner script, CI kept optional | Owner's stated preference; harness is also what CI runs | The owner abandons GitHub entirely |
| Key-permission check unchanged on Linux | It is a security property, and it matched Linux behaviour already | A real operator workflow cannot satisfy it (see Q5) |
| Fix Musl now | Cheap, removes an `#if`, unblocks a static binary | Owner says static binaries are out of scope |

## 15. Adversarial Review

**Strongest alternative: drop everything platform-specific and use swift-nio-ssl everywhere.** That is what the
package *already does*, and the review concludes it is correct. The remaining question is the inverse: should
Apple platforms get Network.framework (via NIOTransportServices) for the sake of the system keychain, system trust
UI and App Transport Security semantics? Arguments for it: Security.framework honours enterprise-managed roots and
revocation policy that a bundled BoringSSL does not; Apple's own guidance prefers it on device. Arguments against,
which win here: SwiftTLSKit's callers are the owner's servers and a pen-test tool, not App Store clients;
pinning and `ClientHandshakeFailure` are specified against NIOSSL's errors; two backends double the test matrix and
produce divergent verdicts (already visible in the 825-day rule); and the package has promised "no way to disable
verification", which is easiest to audit with one verifier. So the answer to "should we drop Network.framework"
is "it is already dropped".

**Other attacks, and replies**

- *"Linux is already green on GitHub, so this is wasted work."* Green on a service the owner will not rely on is
  not evidence the owner can reproduce; and two real gaps (Musl, non-root) exist. The harness is the point.
- *"Running tests in a container is not the box."* True. A container shares a kernel and mounts, and runs on the
  Mac's arm64 where the box may be x86_64. Mitigation: arm64 and (if emulation works) x86_64, plus a UTM VM; and
  the final claim is that of the harness, with the unverified list below.
- *"The static SDK build proves nothing at runtime."* Correct, it proves compilation only; hence "build-only".
- *"Why not relax the key-permission check on Linux so certbot and `ssl-cert` work?"* A group-readable private key
  is the condition the check exists to refuse; loosening it per platform would create the first platform-specific
  security behaviour. The operator procedure (copy with a deploy hook) costs one script.
- *"Containers as root hide the owner check."* Addressed by running non-root (Step 1).
- *"A local Linux runner is one more thing to maintain."* It is a ~20-line script and a tool the owner already
  needs for SwiftPenTest's box; the alternative is not knowing.

**What could make the recommendation wrong:** if `container` or Colima cannot run Swift 6.4.2 images reliably
(e.g. BoringSSL's build fails under emulation), the local path degrades to a UTM VM, which costs about a day more.

## 16. Alternatives Considered

1. Port to Network.framework / NIOTransportServices on Apple and NIOSSL on Linux: rejected (above).
2. `#if os(Linux)` forks of `PEMFile` and friends: unnecessary; one POSIX path already serves both.
3. Rely on GitHub Actions only: rejected by the owner.
4. Cross-compile on the Mac and run on Chromedome: Chromedome is macOS; cannot run Linux binaries.
5. Rent a throwaway Linux VPS for verification: possible fallback; costs money and needs an upload of the
   source (the repo is already public). Unverified pricing.

## 17. Documentation Strategy

DocC: add a short "Platforms and deployment" paragraph to `ServingTLS.md` and `ConnectingAsAClient.md` (system
roots on Linux need `ca-certificates`; key-file ownership and mode on Linux; certbot deploy-hook example).
`StabilityPolicy.md`, README, CHANGELOG, master_plan reconciled in Step 6. Session summary in `project/summaries/`.

## Time estimate (realistic, in working days)

| Item | Days |
|------|------|
| Step 0-1: pick/install runner, write script, first runs on two toolchains and two users | 0.75 (1.5 if `container` fails and a UTM VM is needed) |
| Step 2-3: static SDK install, Musl red, IPv6 fix, tests | 0.5 |
| Step 4: system-roots test and bare-box experiment | 0.5 |
| Step 5: consumer-fixture scratch build | 0.25 |
| Step 6: docs and doc housekeeping, gate 0/0, 1.0.1 release | 0.5 |
| **This repo, total** | **about 2.5 days (range 2-4); almost all of it is getting the runner working, since the code change is one function** |
| SwiftPenTest Linux (out of scope; separate proposal) | about 1 day |

## Open Questions for the owner

1. **Premise:** you may have been thinking of a different package; SwiftTLSKit uses no Network.framework or
   Security.framework. Confirm that "verify what exists, locally" is the job, not a rewrite.
2. Which runner: install Apple `container` (needs Homebrew and a macOS-26+ host; yours is 27.2.1), Colima+Docker,
   or revive a UTM Linux VM? Is `pi-vim` (192.168.64.4) a Linux VM, and is it supposed to be on?
3. Is the target box x86_64 or arm64 (cheap VPS is often either)? Dynamic glibc binary, or a static Musl binary?
   The second makes the Musl fix mandatory.
4. If NIOSSL gives a poor error when the CA store is missing, may SwiftTLSKit add a typed hint (a 1.1.0 API
   addition), or should it stay documentation only?
5. How will the box obtain server keys, if ever? SwiftPenTest as a client needs none. Is a certbot deploy hook
   acceptable, rather than relaxing the permission check?
6. Keep the GitHub workflows (as optional) or delete them? Proposed: keep, mark non-required.
7. May `scripts/linux-test.sh` pull images from Docker Hub, and is a ~1 GB per image download acceptable?

## Ledger of items I could not verify

- Whether any of Apple `container`, Colima, UTM Linux can run Swift 6.4.2 images successfully here: none installed.
- That the repo's CI claim (135 tests green on four Linux jobs) is current: taken from `ci.yml`, CHANGELOG and the
  master plan; I did not build or test anything on Linux.
- That Musl `in6_addr` differs from Glibc's field name (from memory of musl headers) and that the planned
  implicit-`&` `inet_pton` rewrite compiles on all three libcs.
- NIOSSL's Linux default CA search paths and its behaviour with no CA store (no `swift-nio-ssl` checkout locally).
- That the static-SDK artifact installs with the Xcode-bundled 6.4.2 toolchain and builds NIOSSL under Musl.
- Whether any test fails as non-root on Linux, or on a local overlay filesystem (mtime granularity).
- Image sizes and cold-build times.
- Whether `container`/Docker on this Mac can run linux/amd64 images, and the target box's architecture.
- SwiftPenTest on Linux: `swift-argument-parser`, resource bundle behaviour for `.copy("PenTestCore.docc")`,
  `import os` guards. Not built.
- Whether other dependents (SwiftPushHub, FleetWatch, SwiftDiagnosticsHub, which declares watchOS and iOS) build on
  Linux; only SwiftHTTPService's Linux CI is claimed in the master plan.
- That the SwiftHTTPService manifest I read (`exact: "1.0.0-beta.1"`) or `main` is the current one; the master
  plan says `main` is on `upToNextMinor(from: "1.0.0")`.
- That `pi-vim` is a Linux VM.
