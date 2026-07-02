# Detection Benchmark

This directory measures PolicyGuard's detection **precision** and **recall**
against a small, hand-labeled corpus. The goal is to make accuracy a *measured,
reproducible number* rather than an assertion.

## Run it

```bash
go run ./benchmarks/cmd/benchrunner            # human-readable table
go run ./benchmarks/cmd/benchrunner -json      # machine-readable
make benchmark                                 # runs with the CI thresholds
```

## Current result

Reproduced with `go run ./benchmarks/cmd/benchrunner` against the committed
corpus (10 fixtures — AWS and Azure — scoped to 18 core-security policies):

| Metric | Value |
|--------|-------|
| True positives | 20 |
| False positives | 0 |
| False negatives | 1 |
| **Precision** | **1.00** |
| **Recall** | **0.95** |
| **F1** | **0.98** |

One false negative remains, **documented rather than hidden**:

- **False negative (recall)** — `ec2_bare_insecure.tf` is an instance with no
  `metadata_options` block. It defaults to IMDSv1 (insecure), which should be
  flagged, but the `ec2_instance_imdsv2` rule tests `http_tokens != "required"`
  and does not fire when the block is absent entirely. Closing this is tracked
  roadmap work; when the policy improves, recall will rise and the benchmark will
  prove it.

The earlier false positives on `s3_split_resource_secure.tf` (a bucket secured
via the modern split-resource pattern) **have been fixed**: the S3 encryption
and logging policies now recognize a sibling
`aws_s3_bucket_server_side_encryption_configuration` / `aws_s3_bucket_logging`
resource that references the bucket, so correctly-secured modern Terraform is no
longer flagged. The fixture is kept in the corpus as a true negative that guards
against regressing that fix. (Precision rose from 0.88 to 1.00 as a result.)

## How it works (and why the number is honest)

Ground truth is **independent of PolicyGuard's output**. Each fixture in
`corpus/` was read by a human, who decided — by AWS/security judgment — which
misconfigurations a knowledgeable reviewer would flag. Those decisions are
recorded in [`labels.json`](labels.json) as `(resource_id, policy_id)` pairs.
The runner then compares PolicyGuard's actual findings to those labels:

- **TP** — a labeled finding PolicyGuard reported.
- **FP** — a core-policy finding PolicyGuard reported that is *not* labeled.
- **FN** — a labeled finding PolicyGuard did *not* report.

If ground truth were derived from PolicyGuard's own output, precision and recall
would be a meaningless 1.0. They are not, because the labels were written first.

## Scope

The comparison is restricted to a **core set of 12 unambiguous security
policies** (S3 encryption/public-access/logging, EC2 public-IP/encryption/IMDSv2,
EBS encryption, security-group SSH/unrestricted, RDS encryption/public-access/
backup). Findings for policies outside this set (tagging, naming, documentation,
and other opinionated or style checks) are **ignored** — neither rewarded nor
penalized — because their "correctness" is a matter of organizational policy, not
a universal security fact. The scoped set is listed under `core_policies` in
`labels.json`. This keeps the number defensible: every labeled item is something
a security reviewer would agree is a real finding.

## Corpus composition

| Fixture | Purpose |
|---------|---------|
| `s3_insecure.tf` | Public + unencrypted + unlogged bucket; wide-open public-access block (true positives) |
| `ec2_sg_insecure.tf` | Public-IP / IMDSv1 / unencrypted instance; SSH-open and all-open security groups (true positives) |
| `rds_insecure.tf` | Unencrypted, publicly accessible, no-backup DB instance (true positives) |
| `secure_inline.tf` | Resources correctly secured with inline attributes (true negatives — must produce no findings) |
| `s3_partial_secure.tf` | Bucket encrypted + logged inline but with a public ACL (tests that secured dimensions are not over-reported; only the ACL is a finding) |
| `out_of_scope_clean.tf` | SNS/SQS/CloudWatch in reasonable configs (true negative for the core scope) |
| `s3_split_resource_secure.tf` | Correctly secured via split resources (true negative; guards the split-resource fix) |
| `ec2_bare_insecure.tf` | Instance defaulting to IMDSv1 (exposes a false negative) |
| `azure_insecure.tf` | Azure storage/NSG/SQL with explicit misconfigurations, incl. the azurerm v3 attribute name (true positives) |
| `azure_secure.tf` | Securely configured Azure (v4 attribute name, secure defaults, restricted multi-rule NSG) — true negative |

All values in the fixtures are synthetic.

## CI gate

CI runs the benchmark with `-min-precision 0.80 -min-recall 0.88`. A change that
drops detection below those floors fails the build. The floors sit a deliberate
margin *below* the current measured numbers (0.88 / 0.93) so that a single new
fixture or a minor regression does not break the build and pressure someone into
gaming the labels — but a real degradation still trips the gate. Raising or
lowering the thresholds is a conscious decision, recorded in the diff.

## Changing the labels (anti-gaming)

The benchmark is only meaningful while `labels.json` reflects independent
security judgment. A new policy that produces a false positive must be fixed in
the policy — **not** "fixed" by adding the false positive to `labels.json` as an
expected finding. Any PR that edits `labels.json` must explain in its description
why the label change reflects a real security fact about the fixture, and label
changes should normally accompany a corresponding fixture change. Editing labels
to match tool output defeats the entire purpose of the corpus.

## Throughput

Detection accuracy is the headline number, but a scanner also has to be fast
enough that nobody disables it. Engine throughput is measured with a Go
benchmark over synthetic corpora (10/100/500 resources), reproducible with:

```bash
go test ./pkg/policy/opa -bench BenchmarkEvaluate -benchmem -run '^$'
```

Reported on an Apple-silicon dev machine (your numbers will differ; the *shape*
is the point):

| Resources | Before | After | Speedup |
|-----------|--------|-------|---------|
| 10  | 5.2 ms   | 4.3 ms   | 1.2x |
| 100 | 116.3 ms | 29.1 ms  | 4.0x |
| 500 | 1,696.8 ms | 130.7 ms | 13.0x |

"Before" is the original engine, which created and prepared a fresh OPA query
**per resource** and passed every resource into every per-resource evaluation —
making evaluation roughly **quadratic** (5x the resources cost ~18x the time).
Two changes fixed it: (1) prepare the deny query once at compile time and reuse
it (`rego.PrepareForEval`); (2) pass only sibling-relevant resources (the S3
split-resource configuration types) into `input.all_resources` rather than the
entire resource set. After both, scaling is near-linear (5x resources ~4.5x
time) and allocations at 500 resources dropped ~20x. Detection precision/recall
are unchanged — the optimization changed only speed, verified by the detection
benchmark and the engine's correctness tests still passing.
