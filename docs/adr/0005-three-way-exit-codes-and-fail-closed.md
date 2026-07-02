# 5. Three-way exit codes and fail-closed CI behavior

- Status: Accepted
- Date: 2026-06
- Supersedes: the original two-way (`0`/`1`) exit behavior

## Context

PolicyGuard's primary use is as a CI/CD gate: a pipeline runs it and decides
whether to fail the build. That makes the **exit code a contract**, and the
original contract was broken in a way that is dangerous specifically because it
fails *silently*.

Originally the binary exited `0` when clean (or whenever `--fail-on-error` was
off) and `1` otherwise — but `1` meant *both* "violations found" *and* "the scan
could not run" (bad input, unreadable/invalid policy, internal error). In a
pipeline those two outcomes demand opposite responses: violations are a finding
to gate on; a scan that *errored* means you have no signal at all and must not
treat a green-looking result as "clean".

Worse, the three reference CI integrations (GitHub Action, GitLab template,
Jenkins) captured the exit code from a scan invoked **without** `--fail-on-error`
— which always exits `0` — so `fail-on-error: true` never actually failed a
build. The gate was fail-*open*: a repo full of violations sailed through green.

## Options considered

1. **Keep `0`/`1`.** Minimal, but leaves "errored" indistinguishable from
   "violations" and cannot express fail-closed cleanly.
2. **Boolean + a separate `--strict` for errors.** More flags, same ambiguity in
   the common path.
3. **Three-way exit code as an explicit contract.** `0` clean, `1` violations
   under `--fail-on-error`, `2` the scan could not complete.

## Decision

Adopt a **three-way exit code**:

- `0` — clean (no violations, or violations without `--fail-on-error`).
- `1` — violations found while `--fail-on-error` is set (a gated failure).
- `2` — the scan could not complete: bad input, unreadable/invalid policy,
  internal error.

Implemented with an `errViolations` sentinel and Cobra `SilenceUsage`/
`SilenceErrors` so an error does not dump usage text over the report. All three
CI integrations now run the **gating** scan with `--fail-on-error` and treat exit
`2` as an unconditional build failure (you never trust a scan that errored),
distinct from exit `1` (gated on findings). Guarded by `TestCLIExitCodes`.

## Consequences

**Positive**

- A pipeline can now distinguish "infrastructure has a problem" from "the scanner
  has a problem" and fail closed on both — the behavior a security tool must have.
- The fail-open hole in every shipped CI integration is closed.
- The contract is testable and tested, so a refactor cannot silently regress it.

**Negative / accepted costs**

- It is a **behavior change**: a consumer that previously keyed only on
  `exit != 0` still works, but one that explicitly treated `1` as "violations"
  must learn that `2` now exists. Documented in `docs/SECURITY.md`,
  `TROUBLESHOOTING.md`, the README, and the CHANGELOG.
