# SwiftTLSKit — Development Guidelines

This project follows the Design-First TDD workflow defined in `development-guidelines/`.

## Session Start

Read documents in this order for full context recovery:
1. `project/master_plan.md` — Vision and priorities
2. `development-guidelines/rules/coding_rules.md` — Forbidden patterns, safety rules
3. `development-guidelines/rules/test_driven_development.md` — Testing contract
4. `development-guidelines/rules/correct_answers.md` — What an assertion must assert
5. `project/checklists/CURRENT_*.md` — Active tasks (if any)
6. Latest file in `project/summaries/` — Where we left off (if any)

For quick recovery (same-day, simple bug fixes), read only items 5-6.

## After Cloning

`.githooks/` is tracked, but `core.hooksPath` is per-clone git config and cannot
be committed — git will not let a repository enable its own hooks. So a fresh
clone has the hook files and does not run them, until:

```bash
./scripts/bootstrap.sh
```

That sets `core.hooksPath` and checks that `swift` and `quality-gate` are
present, since the hooks need both. It is idempotent. If you would rather not
run a script, `git config core.hooksPath .githooks` is the part that matters.

## Development Workflow

```
0. DESIGN   → Propose architecture (design_proposal.md)
1. RED      → Write failing tests first
2. GREEN    → Minimum code to pass
3. REFACTOR → Clean up, keep tests green
4. DOCUMENT → DocC comments and examples
5. VERIFY   → Run quality-gate (zero warnings/errors)
```

## Key Rules

- No force unwraps (`!`), no `try!`, no force casts (`as!`)
- Guard clauses for all validation; early returns over nested ifs
- Division safety: always check for zero before dividing
- Swift 6 strict concurrency compliance
- All public APIs require DocC documentation

## Quality Gate

Run `quality-gate` before every commit. All checks must pass.

## References

- Full guidelines: `development-guidelines/README.md`
- Coding rules: `development-guidelines/rules/coding_rules.md`
- TDD contract: `development-guidelines/rules/test_driven_development.md`
- Session workflow: `development-guidelines/rules/session_workflow.md`

---

# SwiftTLSKit — TLS configuration for SwiftNIO, written once

## What this package is

Configuration only: values and NIO channel handlers. No sockets, no event loops, no listener
framework. `Sources/SwiftTLSKit/SwiftTLSKit.docc/DesignNotes.md` records every decision and
every place the code forced a deviation; read it before changing the API.

## Rules specific to this package

- **Half an identity is an error, never plaintext.** Nothing may turn "one of two paths" into
  "no TLS".
- **No case, flag or parameter that disables certificate or hostname verification.**
  `certificateVerification` is never written.
- **Nothing read from a key file goes into an error, a description or a log.** The package has
  no logger; keep it that way.
- **Nothing reads the clock.** The current time is a parameter.
- **No `withUnsafe*` blocks.** The gate's pointer-escape auditor flags them here even when the
  result is copied; use typed values and implicit `&` instead (see `IPAddressLiteral`).
- **No private key files in the repository.** Tests generate certificates and keys when they
  run, with the `SwiftTLSKitTestSupport` product (`Sources/SwiftTLSKitTestSupport/`). The
  generator is injected and, in this suite, seeded (`SeededGenerator`, which the product
  ships; the seeds are in `Tests/SwiftTLSKitTests/Support/TestSeed.swift`), because the gate
  refuses unseeded randomness in tests. So the test keys are reproducible from the seed and are to be treated
  as public; nothing trusts a test authority except a client a test builds to trust it.
- **swift-certificates belongs to `SwiftTLSKitTestSupport` only.** The `SwiftTLSKit` target
  must not import X509 or SwiftASN1.
- **No randomness of the package's own.** `SwiftTLSKitTestSupport` takes the caller's
  generator; nothing in `Sources/` constructs `SystemRandomNumberGenerator`, and nothing in
  `Sources/` constructs a `SeededGenerator` either — it is shipped for a test to construct.
- **`SeededGenerator` stays in `SwiftTLSKitTestSupport`.** It is predictable by design. The
  `SwiftTLSKit` target must never see it.
- **No dependency on any other package of the owner's.**

## Tests

Real TLS handshakes over loopback on a kernel-chosen port. Test certificates are dated from
1 January 2019 on purpose: Security.framework refuses a server certificate issued from
1 July 2019 with more than 825 days of validity, and it verifies whenever the system root
store is consulted. (Measured on macOS 27.0.1, the line is 2019-06-30T23:00:00Z.)

A suite that is not about files serves its leaves from memory (`leaf.serverContext(now:)`);
only the suites that test file handling write a key to a temporary directory.
