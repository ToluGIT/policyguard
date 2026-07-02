# 2. HCL-native parsing with heuristic variable resolution

- Status: Accepted
- Date: 2025-05 (recorded retroactively 2026-06)

## Context

To evaluate Terraform/OpenTofu, PolicyGuard must turn `.tf`/`.tofu` source into a
resource model (`types.Resource`) the policy engine can reason over. There are
two fundamentally different places to get that model from, and the choice
determines what the tool can see, how fast it is, and what it depends on.

A Terraform configuration is not literally its final values: attributes can be
`var.x`, `${var.x}`, `var.enabled ? "a" : "b"`, module inputs, or `local`
expressions that are only resolved during `terraform plan` against real
providers and backend state.

## Options considered

1. **Plan/state-based.** Run `terraform plan -out` (or read a state file) and
   scan the fully-resolved JSON plan. This is what some scanners offer as a
   "plan mode". You get *exact* resolved values — no guessing. But it requires
   Terraform installed, provider plugins downloaded, valid credentials/backend
   access, and network egress; it is slow; and it cannot run on a pull request
   that only changed a `.tf` file without a full init. It also pulls a static
   scanner toward the live-cloud boundary the project deliberately stays behind.
2. **HCL-native, values only.** Parse the HCL directly, read literal attribute
   values, and treat anything non-literal as unknown. Fast, dependency-free, runs
   on a single file. But it goes blind exactly where security matters — a bucket
   whose `acl = var.acl` becomes invisible.
3. **HCL-native with heuristic variable resolution.** Parse HCL directly, and
   additionally resolve variable references, `${...}` interpolation, simple
   conditionals, and module inputs *heuristically* — propagating `default` values
   and security-relevant markers through the model so a policy can still see a
   likely-insecure value. Best-effort, not exact.

## Decision

Use **HCL-native parsing with heuristic variable resolution** (option 3). The
parser reads HCL directly and resolves `var.`/`${}`/conditional/module-input
forms on a best-effort basis, propagating defaults and security context through
module boundaries.

## Consequences

**Positive**

- Runs on a single changed file with no Terraform, no providers, no credentials,
  no network — which is what makes sub-second pre-commit and PR scanning possible.
- Stays firmly on the static-analysis side of the project's scope boundary (no
  live cloud, no state).
- Sees through the common indirection (`var.`, interpolation, module inputs) that
  a values-only parser would miss.

**Negative / accepted costs**

- **It is heuristic, therefore fallible.** Values that only resolve at plan time
  against real providers can be misread or unknown; this is a structural source
  of both false positives and false negatives, and it is why the benchmark
  measures precision/recall rather than asserting correctness.
- **Provider-schema drift.** Because we read attributes by name, a provider
  renaming an attribute (e.g. azurerm v3 `enable_https_traffic_only` → v4
  `https_traffic_only_enabled`) must be handled explicitly in policies. The
  parser cannot validate against a real provider schema.
- **The resolver is the riskiest part of the parser** and carries the most
  special-case logic (security-marker propagation through modules), which is a
  maintenance cost we accept in exchange for not requiring `terraform plan`.
