# Changelog

All notable changes to PolicyGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of PolicyGuard
- Terraform HCL parser with support for .tf and .tf.json files
- Integration with Open Policy Agent (OPA) for policy evaluation
- CLI with scan, validate, and policy management commands
- Built-in AWS security policies for S3, EC2, and Security Groups
- Multiple output formats: human-readable, JSON, JUnit, and SARIF
- Remediation suggestions for security violations
- Comprehensive logging with multiple log levels
- Integration test suite
- Documentation including policy writing guide and troubleshooting

### Security
- Secure by default configurations
- No hardcoded credentials or secrets
- Input validation for all user inputs

## [0.1.0] - 2024-01-15

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

### v0.2.0 (Planned)
- [ ] Additional AWS policies (IAM, RDS, VPC, Lambda)
- [ ] Support for Terraform modules
- [ ] Variable interpolation in Terraform files
- [ ] Policy severity customization
- [ ] YAML configuration file support

### v0.3.0 (Planned)
- [ ] Azure ARM template support
- [ ] Google Cloud Deployment Manager support
- [ ] CloudFormation support
- [ ] Policy exemptions and suppressions
- [ ] Web UI for policy management

### v1.0.0 (Planned)
- [ ] Stable API
- [ ] Performance optimizations
- [ ] Enterprise features
- [ ] Compliance frameworks (CIS, HIPAA, PCI-DSS)
- [ ] IDE integrations

[Unreleased]: https://github.com/ToluGIT/policyguard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ToluGIT/policyguard/releases/tag/v0.1.0