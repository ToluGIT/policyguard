# 4. Filtering `input.all_resources` to a `siblingResourceTypes` allow-list

- Status: Accepted
- Date: 2025-09 (recorded retroactively 2026-06)

## Context

ADR-0003 exposes other resources to each policy via `input.all_resources`. The
first implementation passed **every** parsed resource into **every** per-resource
evaluation. With *n* resources that is *n* evaluations each carrying *n*
resources — O(n²) work, dominated by serializing the resource set into the OPA
input over and over.

Measured on synthetic corpora, 500 resources took ~1.7s and ~26M allocations, and
scaling was clearly super-linear (5× the resources cost ~18× the time). A scanner
that gets quadratically slower is a scanner people disable on large repos.

Profiling located the cost in two places: (1) preparing a fresh OPA query per
resource, and (2) the `all_resources` payload size.

## Options considered

1. **Leave it.** Correct but quadratic; unacceptable on real monorepos.
2. **Prepare the query once, but still pass all resources.** Removes the
   per-resource compile cost (helped ~11%) but leaves the dominant O(n²) payload
   cost untouched — measurement showed this alone was not enough.
3. **Prepare once *and* pass only the resources a sibling-aware policy could
   actually need.** Only a small, known set of resource types participate in
   cross-resource matching (today: the two S3 split-resource configuration
   types). Passing only those into `input.all_resources` collapses the payload
   from *n* to a near-constant.

## Decision

Both halves of option 3:

1. Prepare the deny query **once** at compile time (`rego.PrepareForEval`) and
   reuse the prepared query for every resource.
2. Filter `input.all_resources` to a `siblingResourceTypes` allow-list — the
   resource types that sibling-aware policies actually look up — rather than the
   full resource set.

The allow-list is a deliberate **coupling between the engine and the policies**:
the engine "knows" which types matter. To keep that coupling from silently
rotting, `TestSiblingResourceTypes_CoversAllPolicyLookups` greps the policies for
`sibling.type == "..."` lookups and fails if any referenced type is not
registered in the allow-list. A new sibling-using policy that forgets to register
its type breaks the test, not production precision.

## Consequences

**Positive**

- 500 resources: ~1,697ms → ~131ms (~13×), allocations ~20× lower, scaling
  near-linear. Detection precision/recall unchanged (verified by the detection
  benchmark and correctness tests).
- The performance fix is guarded against regression by a test, not a comment.

**Negative / accepted costs**

- **Engine ↔ policy coupling.** The engine now encodes knowledge about specific
  policy behavior (which types are sibling types). This is the price of not
  paying O(n²); the guard test makes the coupling explicit and self-policing
  rather than hidden.
- A cross-resource policy over a resource type that is *not* in the allow-list
  would silently see an empty `all_resources`. The guard test catches the
  common form of this (a `sibling.type ==` lookup), but a policy that derived a
  type some other way could slip past it — a known limitation of the grep-based
  guard.
