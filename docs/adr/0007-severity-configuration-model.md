# 7. External JSON severity configuration over in-policy severities

- Status: Accepted
- Date: 2025-08 (recorded retroactively 2026-06)

## Context

Every policy assigns a severity to its findings (`critical`/`high`/`medium`/
`low`/`info`), and severity drives the CI gate and how a report is triaged. But
severity is partly an **organizational** judgment, not a universal fact: one team
treats "S3 access logging disabled" as `info`, another as `high` for compliance
reasons. The question is whether that judgment is baked into the policy or
configurable by the operator.

## Options considered

1. **Severity hardcoded in each policy's Rego.** Simple and self-contained, but
   to re-prioritize a check for your org you must edit (and thereby fork) the
   policy, which then drifts from upstream. Severity — an operational dial —
   becomes entangled with detection logic.
2. **Severity only via CLI flags.** A flag per override does not scale past a
   handful of policies and is unergonomic in CI.
3. **An external JSON severity configuration.** A `--severity-config` file maps
   `policy_id → severity`, with a `default_severity` fallback. The engine applies
   overrides after a policy fires, leaving the policy's detection logic untouched.

## Decision

Support an **external JSON severity configuration** (option 3), loaded via
`--severity-config` and applied in the engine (`WithSeverityConfig`). The file
carries an optional `description`, an optional `default_severity` (defaults to
`medium`), and a `severities` map of `policy_id → level`. A policy's built-in
severity is the default; the config overrides it without modifying the policy.

This keeps **detection** (what is a finding — in Rego, ADR-0001) separate from
**prioritization** (how much it matters — an operator dial), so an organization
can tune severities without forking the policy set and losing upstream updates.

## Consequences

**Positive**

- Organizations re-prioritize findings without editing Rego; the shipped policies
  stay pristine and updatable.
- Severity policy is a single reviewable artifact (one JSON file in the repo),
  which is itself auditable in version control.

**Negative / accepted costs**

- Two places now influence a finding's severity (the policy default and the
  config), so a surprising severity requires checking both. The config is the
  authoritative override and `default_severity` makes the fallback explicit, which
  bounds the confusion.
- The mapping is keyed by `policy_id`; renaming a policy ID silently drops its
  override back to the default. Policy IDs are therefore part of the tool's
  stable contract.
