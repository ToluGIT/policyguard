# 3. Single-resource evaluation input with an `input.all_resources` side channel

- Status: Accepted
- Date: 2025-08 (recorded retroactively 2026-06)

## Context

The OPA engine has to decide what shape of `input` each policy evaluation sees.
Two facts pull in opposite directions:

1. **Most policies are per-resource.** "Is *this* bucket public?" is a question
   about one resource. A per-resource input keeps policies simple and keeps a
   finding naturally attributable to one resource.
2. **Some correct configurations are expressed across resources.** Modern AWS
   provider (v4+) splits a bucket's encryption and logging out of
   `aws_s3_bucket` into separate `aws_s3_bucket_server_side_encryption_configuration`
   and `aws_s3_bucket_logging` resources that *reference* the bucket. A policy
   that only sees the bucket in isolation will report a false positive ("no
   encryption") on a bucket that is correctly encrypted via a sibling resource.

So a pure per-resource input is simple but wrong on split-resource patterns; a
pure whole-configuration input makes every policy reason about the entire graph
and makes finding attribution awkward.

## Options considered

1. **Per-resource input only.** Simple, but cannot express the split-resource
   case → unavoidable false positives on modern Terraform, which directly harms
   the precision number the project competes on.
2. **Whole-configuration input.** Pass the entire resource set as `input`. Every
   policy can see everything, but every policy now has to select "its" resource
   out of the set, attribution is manual, and it is the path that led to the
   quadratic blow-up (see ADR-0004).
3. **Per-resource input plus an `input.all_resources` side channel.** The policy
   is still evaluated once per resource with that resource as `input.resource`,
   but it can additionally reach into `input.all_resources` when — and only when —
   it needs sibling context.

## Decision

Evaluate **once per resource**, with the resource under `input.resource`, and
expose the (filtered — see ADR-0004) set of other resources as
`input.all_resources`. Cross-resource policies use `input.all_resources` to find
a sibling by name; per-resource policies ignore it entirely.

For correctness, sibling matching is **name- and module-scoped**: a sibling must
reference the resource by name, and matching is confined to the same module so
two modules that each name a bucket `this` cannot cross-suppress each other's
findings (that would be a false negative).

## Consequences

**Positive**

- Per-resource policies stay trivial; the complexity of cross-resource reasoning
  is opt-in and localized to the few policies that need it.
- Findings remain attributable to a single resource.
- The split-resource false positives were eliminated — benchmark precision rose
  from 0.88 to 1.00 with no recall loss.

**Negative / accepted costs**

- `input.all_resources` is a second, looser contract policy authors must learn,
  and a policy that uses it incorrectly can reintroduce a false positive or
  negative (hence the explicit same-module / name-match tests).
- Serializing other resources into every per-resource evaluation is what made the
  engine quadratic; this ADR created the problem that ADR-0004 solves.
