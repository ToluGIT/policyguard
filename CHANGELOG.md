# Changelog

All notable changes to PolicyGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Guide page in the web GUI** (`/guide`): a usage guide (what it scans, what it
  detects, severity model, safety model, CLI/CI, output formats) in the same
  terminal-mono style, linked from the top bar.
- **fly.io / container deploy for the GUI**: `Dockerfile.gui` (runs `serve
  --public` non-root on distroless) + `fly.toml` + [`docs/DEPLOY.md`](docs/DEPLOY.md)
  with custom-domain steps.
- **Brand identity**: the PolicyGuard logomark (a shield wrapping a `>_` prompt,
  lime accent) is now used across the GUI, static report, and favicons; README
  leads with the lockup and an architecture diagram (`docs/design/`).

### Changed
- **GUI copy**: upload/paste panels now say "Terraform / OpenTofu" (not just
  Terraform) and note AWS + Azure coverage; the live dashboard records the real
  build version instead of the dev placeholder.
- **GUI search/filter**: the filter/search/select handlers are now bound once and
  delegate from the document, so search works reliably and survives repeated
  scans (previously stale listeners could stack across scans).
- **README**: rewritten — concise, leads with the value proposition, dashboard,
  and architecture diagram; corrected the published precision/recall figure
  (1.00 / 0.95) and stale install pins; documents `serve` and the GUI.

### Security
- **GUI public-mode hardening** (from an adversarial review): uploaded Terraform
  can no longer escape the upload sandbox via a `module { source = "../../…" }`
  path — module resolution is confined to the scan root in the GUI
  (`Parser.WithConfinedRoot`); scan errors return a generic message to the client
  (server paths are logged server-side only); and the server sets
  `ReadTimeout`/`IdleTimeout` in addition to `ReadHeaderTimeout`. Guarded by new
  tests (`TestModuleSourceTraversalConfined`, `TestScanErrorIsGeneric`).

### Added (earlier in this cycle)
- **Interactive web GUI** (`policyguard serve`): a local web server that lets you
  import (drag-and-drop / file picker) or paste Terraform/OpenTofu in the browser
  and scan it live, rendering the same terminal-mono dashboard the static report
  uses (one shared template). It runs the **identical scan pipeline** in-process
  and loads **only the trusted embedded policy set** — a web request can never
  point the engine at an arbitrary policy directory. Hardened by design: binds to
  `127.0.0.1` by default; uploads go to a per-request temp dir (sanitized
  filenames, size/count/type limits) and are deleted after each scan; request
  body cap, scan timeout, and per-client rate limit; strict CSP and security
  headers; `html/template` auto-escaping makes crafted IaC inert (XSS-safe). A
  `--public` mode (upload/paste only, stricter limits, no filesystem path
  scanning) is intended for container hosting. See `pkg/web` and
  `docs/SECURITY.md` ("Hosting the GUI").
- **HTML dashboard reporter** (`--format html`): renders a single self-contained,
  interactive security dashboard (the GUI) from the real scan — severity stat
  cards, a stacked severity/pass distribution bar, a filterable + searchable
  findings table, and a finding-detail panel with the violation, its CWE
  mapping, the offending source line as evidence, and a diff-style remediation.
  Terminal-mono aesthetic (monospace, near-monochrome canvas, one lime accent,
  severity-only color, FAIL = diagonal hatch / PASS = solid). No external
  dependencies (renders offline; safe as a CI artifact) and no runtime server —
  it is a static file. Honest by construction: every count, finding, CWE,
  evidence line, and remediation comes from the scan; CIS/NIST tags appear only
  when a policy is actually mapped (never guessed); buttons implying a live
  action are inert in a static report. Built on `pkg/reporter/html` with template/
  CSS/JS embedded via `//go:embed`; all scan-derived strings are auto-escaped by
  `html/template` (HTML-injection safe against crafted IaC). Design reference and
  a committed sample live in `docs/design/`.
- **Non-root container image**: a multi-stage `Dockerfile` produces a static
  binary on a `distroless/static:nonroot` base — no shell, no package manager,
  runs as an unprivileged user. Because the default policies are embedded in the
  binary (`//go:embed all:policies`), the image needs no mounted policy volume;
  mount only the IaC to scan at `/work`. Published multi-arch (amd64/arm64) to
  GHCR by the release workflow. `.dockerignore` keeps the build context minimal.
- **Signed releases + SBOM (supply-chain integrity)**: the release workflow now
  signs `checksums.txt` with cosign **keyless** signing (GitHub OIDC, no stored
  private key) and attaches the signature/certificate, signs the GHCR image by
  immutable digest with provenance + SBOM attestations, and publishes an SPDX
  SBOM of the Go module graph. Verification instructions are in the README and
  `docs/SECURITY.md` (new "Supply-chain integrity" section).
- **Architecture Decision Records** (`docs/adr/`): seven ADRs documenting the
  non-obvious calls — OPA/Rego over hardcoded Go checks, HCL-native parsing with
  heuristic variable resolution, single-resource input + `input.all_resources`,
  the `siblingResourceTypes` performance coupling, three-way exit codes /
  fail-closed, the OPA capability sandbox, and the external severity-config model.
- **Reproducible demo + README asset**: `scripts/demo.sh` runs a real scan of
  `examples/demo/main.tf`; the terminal capture embedded at the top of the README
  (`docs/assets/demo.svg`) is generated from that actual output (deterministic,
  no hand-editing) via `scripts/gen_demo_svg.py`.

### Fixed
- **CI integrations were fail-open** (security): the GitHub Action, GitLab CI
  template, and Jenkins pipeline captured the scan exit code from a run *without*
  `--fail-on-error`, which always exits 0 — so `fail-on-error: true` never
  actually failed the build on violations. All three now run the gating scan with
  `--fail-on-error` and distinguish exit 2 (scan could not run → always fail) from
  exit 1 (violations → gated). The documented pre-commit example had the same bug
  and is corrected.
- **S3 provider-schema-drift false positives eliminated**: the `s3_bucket_encryption`
  and `s3_bucket_logging` policies no longer flag a bucket that is correctly
  secured using the modern split-resource pattern (a separate
  `aws_s3_bucket_server_side_encryption_configuration` / `aws_s3_bucket_logging`
  resource referencing the bucket, AWS provider v4+). The OPA engine now exposes
  all parsed resources to policies as `input.all_resources`, and the parser
  preserves cross-resource references (e.g. `aws_s3_bucket.modern.id`) instead of
  discarding them, so policies can match a sibling to its bucket by name.
  Sibling matching is name-specific — an unencrypted bucket is still flagged even
  when an unrelated bucket has an encryption config, and a literal bucket-name
  string (not a resource reference) does not suppress a finding. Cross-resource
  references are normalized so HCL (`.tf`) and JSON (`.tf.json`) Terraform produce
  the same reference string, so the fix works for both formats. Sibling matching
  is scoped to the same module, so two modules that each name a bucket `this` do
  not cross-suppress (an encryption config in one module cannot silence an
  unencrypted bucket of the same name in another — that would be a false
  negative). Benchmark precision rose from 0.88 to 1.00 (F1 0.90 → 0.97) with no
  recall loss.

### Added
- **Initial Azure coverage**: 6 policies across storage accounts
  (`azure_storage_https_only`, `azure_storage_min_tls`, `azure_storage_public_access`),
  network security groups (`azure_nsg_admin_ports` — handles both inline
  `security_rule` blocks and standalone `azurerm_network_security_rule`, and the
  single-object vs list parser shape), and SQL servers (`azure_sql_public_access`,
  `azure_sql_min_tls`). Policies are version-aware (both `https_traffic_only_enabled`
  and the older `enable_https_traffic_only`) and default-aware (flag explicit
  insecure values, not absence, since Azure resources are largely secure by
  default). Each has true-positive + true-negative fixtures in the benchmark
  corpus, CWE mappings, and Go tests. Benchmark precision/recall: 1.00 / 0.95
  (F1 0.98) across 18 core policies.
- **`scan` accepts multiple paths**: `policyguard scan a.tf b.tf dir/` now scans
  all paths in a single run/report (was: exactly one path). Paths are pooled
  before evaluation, so cross-resource policies can see related resources defined
  in different files. This is what lets the pre-commit hook pass all changed files
  at once.
- **Pre-commit hook definition** (`.pre-commit-hooks.yaml`): other repos can
  consume PolicyGuard via `repo: https://github.com/ToluGIT/policyguard`. Fails
  closed (`--fail-on-error`) on `.tf`/`.tofu` changes.
- **Suppressions / exemptions** (`--suppress`): acknowledge specific findings via
  a JSON config of rules (`policy_id`, optional `resource`, required `reason`,
  optional `expires` date) instead of deleting the policy. Suppressed findings are
  removed from the violations list and the `--fail-on-error` exit code, but
  counted and ranked by policy in the report so they stay visible and a noisy
  policy is easy to spot. Rules without a reason are rejected; expired rules lapse
  so a finding resurfaces for review. See `examples/suppression_config.json`.
- **Remediation HCL snippets**: findings now carry a corrected-Terraform example
  (`remediation_snippet` in JSON; a "Suggested HCL" block in human output) where a
  template exists, in addition to the existing prose remediation. This wires up
  the previously-dead `pkg/remediation` suggester — which had a key-matching bug
  (templates were keyed by a hyphenated form that never matched the real
  underscore policy IDs, so every lookup silently fell through to generic) — fixes
  the keys to actual policy IDs, expands coverage to the core security policies
  (S3, EC2/EBS, security groups, RDS), and aligns the S3 snippets with the
  split-resource pattern. Snippets are attached best-effort in the analyzer and
  never block reporting.
- **Compliance report format** (`--format compliance`): a CSV that maps each
  finding to its CWE control(s), severity, message, and remediation, for
  audit/GRC workflows. Built on `pkg/compliance`; unmapped policies are reported
  as `unmapped` rather than assigned a guessed control.
- **Honest comparison table in the README**: positions PolicyGuard against
  Checkov, Trivy/tfsec, and Terrascan, conceding coverage breadth, multi-cloud
  support, and raw speed to the incumbents while stating its own lane
  (transparent Rego, a published precision/recall number, correct SARIF/CWE). All
  ✓ cells are backed by verifiable capabilities.
- **SARIF 2.1.0 correctness**: results now carry stable `partialFingerprints`
  (so GitHub code scanning can dedupe and track a finding across runs even when
  line numbers shift) and a `ruleIndex` linking each result to its rule. Rules
  carry CWE identifiers (as a `cwe` property and `external/cwe/cwe-NNN` tags) for
  mapped policies, plus `helpUri`; the run records `informationUri`.
- **Compliance mapping** (`pkg/compliance`): a conservative `policy_id → CWE`
  table (CIS/NIST scaffolded). Unmapped policies emit no identifier rather than
  a guessed one. Feeds SARIF today and a compliance report later.
- **Detection benchmark with measured precision/recall**: a labeled corpus
  (`benchmarks/corpus/`) plus an independent ground-truth label set
  (`benchmarks/labels.json`) and a runner (`go run ./benchmarks/cmd/benchrunner`,
  `make benchmark`) that reports TP/FP/FN, precision, recall, and F1 scoped to a
  core set of 12 security policies. Current result: precision 0.88 / recall 0.93
  / F1 0.90 on 8 fixtures. Ground truth is authored independently of the tool's
  output, so the number is meaningful; the false positives (S3 split-resource
  pattern) and false negative (IMDSv1-by-default) are documented, not hidden. CI
  gates on `-min-precision 0.80 -min-recall 0.88` (a deliberate margin below the
  measured numbers).

### Changed
- **Engine throughput: near-linear scaling, up to ~13x faster on large corpora.**
  The OPA engine previously created and prepared a fresh query per resource and
  passed the full resource set into every per-resource evaluation, making a scan
  roughly quadratic in resource count (e.g. 500 resources took ~1.7s). The deny
  query is now prepared once at compile time and reused (`rego.PrepareForEval`),
  and only sibling-relevant resources are passed into `input.all_resources`.
  Measured: 500 resources 1,696.8 ms -> 130.7 ms (~13x), allocations ~20x lower,
  scaling now near-linear. Detection precision/recall are unchanged. Reproduce
  with `go test ./pkg/policy/opa -bench BenchmarkEvaluate -benchmem -run '^$'`.
- **Deterministic finding order across all output formats**: the analyzer now
  sorts violations by (file, line, resource, policy, id) before reporting, so
  re-running the same scan — including directory scans where file discovery order
  is filesystem-dependent — always emits findings in the same order. This keeps
  report diffs and CI baseline comparisons stable. Affects human/JSON/JUnit/SARIF/
  compliance output.
- **Startup banner moved to stderr**: the ASCII banner previously printed to
  stdout, corrupting `sarif`/`junit` output and any redirected report file unless
  `-f json` happened to be used. It now prints to stderr, so stdout always
  carries clean report data regardless of format.
- **SARIF tool version is the real build version**: the reporter previously
  hardcoded `1.0.0`; it now reports the actual binary version (and the Makefile
  `VERSION` was corrected from `0.3.0` to `0.3.1` to match).
- **Exit codes are now a 3-way CI contract**: `0` = clean, `1` = violations found
  under `--fail-on-error`, `2` = the scan could not complete (bad input,
  unreadable/invalid policy, internal error). Previously both violations and
  internal errors exited `1`, so a broken scan was indistinguishable from
  findings in a pipeline. Errors no longer print Cobra usage text. Guarded by an
  integration test (`TestCLIExitCodes`).

### Security
- **OPA policy sandbox**: The policy engine now compiles and evaluates Rego with a
  restricted capability set that removes all non-deterministic built-ins
  (`http.send`, `net.lookup_ip_addr`, `opa.runtime`, `io.jwt.*`, `rand.intn`,
  `time.now_ns`, `uuid.rfc4122`) and disallows outbound network access. A policy
  loaded from an untrusted `--policy` directory can no longer exfiltrate the
  parsed infrastructure; offending policies are rejected at load time. Documented
  in `docs/SECURITY.md` ("Securing PolicyGuard Itself").

## [0.3.1] - 2025-08-15

### Added
- **Enhanced Module Security Detection**: Improved security analysis for Terraform modules
  - Enhanced conditional variable resolution for module security attributes
  - Added special handling for security-critical boolean variables
  - Pre-processed security markers for module variables
  - Extended debug logging for module resolution
  
### Changed
- **Parser Enhancement**: Significantly improved security context propagation through modules
  - Multiple layers of security marker propagation for redundancy
  - Enhanced tracking of security-critical variables across module boundaries
  - Strengthened detection of insecure configurations in conditional expressions
  
### Fixed
- **RDS Module Detection**: Fixed security violation detection in RDS modules
  - Public accessibility detection in module variables
  - Unencrypted storage detection in modules
  - Backup configuration validation in modules
  - IAM authentication detection in modules
- **Debug Output Control**: Improved control over debug logging
  - Replaced direct printf statements with proper logger calls
  - Debug output now only shows when using verbose flag
  - Warnings still displayed at appropriate log level

## [0.3.0] - 2025-08-15

### Added
- **3 New AWS Service Security Policies**: Expanded coverage with policies for message and data services
  - SNS security policies (encryption, access control, FIFO configuration, delivery protocols)
  - SQS security policies (encryption, dead letter queues, access control, message retention)
  - DynamoDB security policies (encryption, recovery, TTL management, monitoring, autoscaling)
- **Terraform Module Support**: Parse and analyze resources within Terraform modules
  - Local module resolution for relative paths (./modules)
  - Module context tracking for better violation attribution
  - Resource ID prefixing with module information
- **Variable Interpolation**: Support for Terraform variable references and interpolation
  - Direct variable references (var.name)
  - String interpolation syntax (${var.name})
  - Conditional expressions using variables (var.enabled ? "yes" : "no")
  - Binary operations with variables (var.count + 1)
- **Policy Severity Customization**: Configure custom severities for policies
  - JSON configuration file format
  - Per-policy severity overrides
  - Default severity configuration
  - Command-line flag to specify configuration file

### Changed
- **Documentation**: Enhanced README with comprehensive coverage of new features
- **Reporting**: Improved violation messages with module context information
- **Command-line Interface**: Added `--severity-config` flag to scan command

### Fixed
- **Parser Robustness**: Fixed variable reference handling in complex expressions
- **DynamoDB Policy**: Resolved duplicate variable declaration issue
- **SNS Policy**: Fixed OR condition syntax using helper functions


## [0.2.0] - 2025-07-14

### Added
- **5 New AWS Service Security Policies**: Expanded coverage with comprehensive policies for high-impact services
  - API Gateway security policies (HTTPS enforcement, authentication, logging, throttling)
  - CloudTrail security policies (encryption, multi-region, log validation, global events)
  - ECR security policies (vulnerability scanning, immutable tags, KMS encryption)
  - Application Load Balancer security policies (HTTPS redirects, SSL policies, access logs)
  - KMS security policies (key rotation, deletion protection, policy validation)
- **Example Files**: Added `secure_complete.tf` demonstrating security best practices (78.6% pass rate)
- **Services Example**: New `extended_services.tf` showcasing all supported AWS services
- **Improved Policy Validation**: Better error reporting and syntax validation for Rego policies

### Changed
- **Expanded AWS Coverage**: Now supports 12 major AWS services (previously 7)
- **Better Security Detection**: 34+ new violation types across API Gateway, CloudTrail, ECR, ALB, and KMS
- **Policy Organization**: Cleaner separation of policies by AWS service

### Fixed
- **Pass Rate Calculation**: Resolved intermittent negative pass rate values in JSON output
- **Policy Syntax Issues**: Fixed Rego syntax errors in ALB security policies
- **Resource ID Matching**: Improved accuracy of pass rate calculations for complex infrastructures

### Security
- **Critical Security Checks**: Added detection for public ECR repositories, unencrypted CloudTrail logs
- **Authentication Enforcement**: New policies require API Gateway authentication and ALB HTTPS
- **Encryption Standards**: KMS and encryption-at-rest validation across services


## [0.1.0] - 2025-05-15

### Added
- Core architecture with modular design
- Parser interface for extensibility
- Policy engine with OPA integration
- Reporter interface with human and JSON implementations
- Analyzer component for orchestrating scans
- Basic CLI structure with Cobra
- Initial AWS security policies
- Project structure and build system

### Changed
- N/A (Initial release)

### Deprecated
- N/A (Initial release)

### Removed
- N/A (Initial release)

### Fixed
- N/A (Initial release)

### Security
- N/A (Initial release)

## Roadmap

### v0.3.0 (Planned)  
- [x] Additional AWS policies (~~ECS, EKS,~~ SNS, SQS, DynamoDB)
- [x] Support for Terraform modules
- [x] Variable interpolation in Terraform files
- [x] Policy severity customization
- [ ] YAML configuration file support

### v0.4.0 (Planned)
- [ ] Azure ARM template support
- [ ] Google Cloud Deployment Manager support  
- [ ] CloudFormation support
- [ ] Kubernetes YAML manifest support
- [ ] Policy exemptions and suppressions
- [ ] Web UI for policy management


[Unreleased]: https://github.com/ToluGIT/policyguard/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/ToluGIT/policyguard/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/ToluGIT/policyguard/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ToluGIT/policyguard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ToluGIT/policyguard/releases/tag/v0.1.0