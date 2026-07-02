# 1. OPA/Rego policies over hardcoded Go checks

- Status: Accepted
- Date: 2025-05 (recorded retroactively 2026-06)

## Context

A misconfiguration scanner has to encode a growing body of security rules ("an
S3 bucket must not be public", "an EC2 instance should require IMDSv2"). The core
architectural question is *where those rules live*: compiled into the scanner's
own language, or expressed in a dedicated policy language the engine evaluates at
runtime.

The dominant tools split both ways. tfsec (original) and Trivy's built-in checks
are Go; Checkov is Python with a YAML/Rego escape hatch; Terrascan and Conftest
are OPA/Rego. So neither choice is obviously wrong — it is a genuine trade-off.

## Options considered

1. **Hardcoded Go checks.** Each policy is a Go function over the parsed
   resource model. Fastest to evaluate, fully type-checked, no second language.
   But every new or changed rule is a recompile-and-release, rules are only as
   auditable as the person willing to read Go, and a *user* cannot add an
   organization-specific rule without forking the tool.
2. **A bespoke rule DSL / YAML matcher.** Lower ceiling than a real policy
   language; you re-invent boolean logic, quantifiers, and helper composition
   badly. This is the path that tends to collapse into "and also an `eval`
   escape hatch" later.
3. **OPA/Rego.** Policies are data the engine loads at runtime. Rego is a mature,
   widely-known policy language with real semantics (quantification, comprehension,
   partial evaluation). Users can drop a `.rego` file in `policies/` and get a new
   check with no code change. The matching logic for every finding is openable and
   auditable as text.

## Decision

Use **OPA/Rego**, evaluated by the embedded OPA Go library, as the policy
substrate. Policies live as `.rego` files under `policies/<provider>/` and are
both shipped embedded in the binary (`//go:embed all:policies`) and overridable
via `--policy`.

This is the decision that defines PolicyGuard's competitive lane: it cannot
out-*count* Checkov, so it competes on **transparency** — every finding traces to
a human-readable policy you can open — and that is only credible if the policies
are genuinely external, inspectable artifacts rather than compiled control flow.

## Consequences

**Positive**

- Findings are explainable: the comparison table's "transparent per-finding Rego
  you can open" claim is structurally true, not marketing.
- Users extend the tool without forking it; `policy list` and `validate` operate
  on the same files the engine runs.
- Rego's quantifiers made the cross-resource sibling logic (ADR-0003) expressible
  without hand-rolled graph code.

**Negative / accepted costs**

- **Performance.** Evaluating Rego per resource is slower than a Go function
  call, and a naive implementation was quadratic (see ADR-0003/0004). We paid for
  this with a prepared-query + input-filtering optimization rather than by
  abandoning Rego.
- **A second language** in the codebase, with its own idioms and failure modes
  (e.g. provider-schema drift expressed as Rego attribute lookups).
- **Untrusted-code execution.** Loading user Rego means the engine executes
  untrusted code, which forced the capability sandbox in ADR-0006. A hardcoded-Go
  design would not have this attack surface.
