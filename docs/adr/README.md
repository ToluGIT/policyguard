# Architecture Decision Records

This directory records the **non-obvious** design decisions behind PolicyGuard —
the ones where a reasonable engineer would ask "why did you do it *that* way?"
and the answer involves a real trade-off rather than a default.

Each ADR follows a lightweight [MADR](https://adr.github.io/madr/)-style format:
context, the options considered, the decision, and its consequences (including
the downsides we accepted). They are immutable once `Accepted` — a decision that
changes gets a new ADR that supersedes the old one, so the history of *why*
stays legible.

| ADR | Decision | Status |
|-----|----------|--------|
| [0001](0001-opa-rego-over-hardcoded-go-checks.md) | OPA/Rego policies over hardcoded Go checks | Accepted |
| [0002](0002-hcl-native-parsing-with-heuristic-variable-resolution.md) | HCL-native parsing with heuristic variable resolution (not `terraform plan`) | Accepted |
| [0003](0003-single-resource-input-with-all-resources-context.md) | Single-resource evaluation input with an `input.all_resources` side channel | Accepted |
| [0004](0004-sibling-resource-types-performance-coupling.md) | Filtering `input.all_resources` to a `siblingResourceTypes` allow-list | Accepted |
| [0005](0005-three-way-exit-codes-and-fail-closed.md) | Three-way exit codes and fail-closed CI behavior | Accepted |
| [0006](0006-opa-capability-sandbox.md) | Restricting OPA capabilities to sandbox untrusted policies | Accepted |
| [0007](0007-severity-configuration-model.md) | External JSON severity configuration over in-policy severities | Accepted |

## Why these and not others

These ADRs cover decisions that (a) shaped the architecture, (b) have a credible
alternative we explicitly rejected, and (c) would otherwise look like accidents
to someone reading the code cold. Routine choices (using Cobra for the CLI,
table-driven tests, Go modules) are conventional and need no record.
