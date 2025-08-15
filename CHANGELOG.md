# Changelog

All notable changes to PolicyGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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


[Unreleased]: https://github.com/ToluGIT/policyguard/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/ToluGIT/policyguard/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ToluGIT/policyguard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ToluGIT/policyguard/releases/tag/v0.1.0