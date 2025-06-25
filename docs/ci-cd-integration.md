# CI/CD Integration Guide

PolicyGuard can be easily integrated into your CI/CD pipelines to automatically scan Infrastructure as Code for security violations. This guide covers integration with popular CI/CD platforms.

## Table of Contents

- [GitHub Actions](#github-actions)
- [GitLab CI](#gitlab-ci)
- [Jenkins](#jenkins)
- [Generic Integration](#generic-integration)
- [Output Formats](#output-formats)
- [Best Practices](#best-practices)

## GitHub Actions

### Using the PolicyGuard Action

The easiest way to integrate PolicyGuard with GitHub Actions is to use our official action:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Run PolicyGuard
      uses: policyguard/policyguard-action@v1
      with:
        target: '.'
        fail-on-error: true
        upload-sarif: true
        comment-pr: true
```

### Using the Workflow Template

For more control, use our workflow template:

```yaml
name: PolicyGuard Security Scan

on:
  push:
    branches: [ main ]
  pull_request:

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.21'
    
    - name: Install PolicyGuard
      run: go install github.com/policyguard/policyguard/cmd/policyguard@latest
    
    - name: Run PolicyGuard Scan
      run: |
        policyguard scan . -f sarif -o results.sarif --fail-on-error
    
    - name: Upload SARIF
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: results.sarif
```

### GitHub Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `target` | Directory or file to scan | `.` |
| `policy-path` | Path to custom policies | `policies/` |
| `format` | Output format | `sarif` |
| `fail-on-error` | Fail if violations found | `true` |
| `severity-threshold` | Minimum severity | `low` |
| `upload-sarif` | Upload to Security tab | `true` |
| `comment-pr` | Comment on pull requests | `true` |

## GitLab CI

### Basic Integration

Add to your `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/policyguard/policyguard/main/ci/gitlab/.gitlab-ci.yml'

variables:
  POLICYGUARD_TARGET: "terraform/"
  POLICYGUARD_FAIL_ON_ERROR: "true"
```

### Custom Configuration

```yaml
stages:
  - security

policyguard:
  stage: security
  image: golang:1.21-alpine
  before_script:
    - go install github.com/policyguard/policyguard/cmd/policyguard@latest
  script:
    - policyguard scan . -f sarif -o gl-sast-report.json
    - policyguard scan . -f junit -o report.xml
  artifacts:
    reports:
      sast: gl-sast-report.json
      junit: report.xml
```

### GitLab Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `POLICYGUARD_VERSION` | Version to install | `latest` |
| `POLICYGUARD_TARGET` | Scan target | `.` |
| `POLICYGUARD_POLICY_PATH` | Policy directory | `policies/` |
| `POLICYGUARD_FAIL_ON_ERROR` | Fail pipeline on violations | `true` |

## Jenkins

### Declarative Pipeline

Use our Jenkinsfile template:

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    # Install PolicyGuard
                    go install github.com/policyguard/policyguard/cmd/policyguard@latest
                    
                    # Run scan
                    policyguard scan . -f junit -o policyguard-junit.xml
                '''
            }
        }
    }
    
    post {
        always {
            junit 'policyguard-junit.xml'
            archiveArtifacts artifacts: 'policyguard-*.xml'
        }
    }
}
```

### Scripted Pipeline

```groovy
node {
    stage('Checkout') {
        checkout scm
    }
    
    stage('PolicyGuard Scan') {
        try {
            sh 'policyguard scan . -f junit -o results.xml --fail-on-error'
        } catch (e) {
            currentBuild.result = 'FAILURE'
            throw e
        } finally {
            junit 'results.xml'
        }
    }
}
```

## Generic Integration

### Docker

```dockerfile
FROM golang:1.21-alpine AS scanner
RUN go install github.com/policyguard/policyguard/cmd/policyguard@latest
WORKDIR /scan
COPY . .
RUN policyguard scan . -f json -o results.json
```

### Shell Script

```bash
#!/bin/bash
set -e

# Install PolicyGuard
go install github.com/policyguard/policyguard/cmd/policyguard@latest

# Run scan
policyguard scan . \
  --format="${OUTPUT_FORMAT:-sarif}" \
  --output="${OUTPUT_FILE:-results.sarif}" \
  --fail-on-error="${FAIL_ON_ERROR:-true}"

# Check exit code
if [ $? -ne 0 ]; then
  echo "Security violations found!"
  exit 1
fi
```

## Output Formats

PolicyGuard supports multiple output formats for different CI/CD integrations:

### SARIF (Static Analysis Results Interchange Format)

Best for: GitHub, GitLab, Azure DevOps

```bash
policyguard scan . -f sarif -o results.sarif
```

Features:
- Integrates with GitHub Security tab
- Supports GitLab Security Dashboard
- Rich metadata and fix suggestions

### JUnit XML

Best for: Jenkins, CircleCI, Bamboo

```bash
policyguard scan . -f junit -o results.xml
```

Features:
- Test report visualization
- Failure tracking
- Trend analysis

### JSON

Best for: Custom integrations, APIs

```bash
policyguard scan . -f json -o results.json
```

Features:
- Machine-readable
- Complete scan data
- Easy to parse

### Human-Readable

Best for: Logs, debugging

```bash
policyguard scan . -f human
```

Features:
- Colored output
- Grouped by severity
- Detailed explanations

## Best Practices

### 1. Fail Fast

Configure your pipeline to fail on critical violations:

```yaml
- run: policyguard scan . --fail-on-error --severity-threshold=high
```

### 2. Progressive Enforcement

Start with warnings, then enforce:

```yaml
# Phase 1: Warning only
- run: policyguard scan . || echo "Violations found (warning)"

# Phase 2: Fail on high/critical
- run: policyguard scan . --fail-on-error --severity-threshold=high

# Phase 3: Fail on all violations
- run: policyguard scan . --fail-on-error
```

### 3. Custom Policies

Use custom policies for organization-specific rules:

```yaml
- run: policyguard scan . -p ./security-policies/
```

### 4. Caching

Cache PolicyGuard installation:

```yaml
# GitHub Actions
- uses: actions/cache@v3
  with:
    path: ~/go/bin
    key: ${{ runner.os }}-policyguard-${{ hashFiles('**/go.sum') }}
```

### 5. Notifications

Configure notifications for failures:

```yaml
# Email on failure
- name: Notify
  if: failure()
  run: |
    mail -s "PolicyGuard scan failed" team@example.com < results.txt
```

### 6. Baseline Management

Track security debt with baselines:

```bash
# Generate baseline
policyguard scan . -f json > baseline.json

# Compare against baseline
policyguard scan . --baseline=baseline.json
```

### 7. Pull Request Integration

Automatically scan pull requests:

```yaml
on:
  pull_request:
    types: [opened, synchronize, reopened]
```

### 8. Scheduled Scans

Run periodic security scans:

```yaml
on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday
```

## Troubleshooting

### Installation Issues

```yaml
# Use specific version
- run: go install github.com/policyguard/policyguard/cmd/policyguard@v1.0.0

# Or download binary
- run: |
    wget https://github.com/policyguard/policyguard/releases/download/v1.0.0/policyguard-linux-amd64
    chmod +x policyguard-linux-amd64
    sudo mv policyguard-linux-amd64 /usr/local/bin/policyguard
```

### Permission Issues

```yaml
# GitHub Actions
permissions:
  contents: read
  security-events: write
  pull-requests: write
```

### Performance

```yaml
# Parallel scanning
- run: |
    policyguard scan terraform/ &
    policyguard scan kubernetes/ &
    wait
```

## Examples

Complete examples are available in the `ci/` directory:
- [GitHub Actions](.github/workflows/policyguard.yml)
- [GitLab CI](ci/gitlab/.gitlab-ci.yml)
- [Jenkins](ci/jenkins/Jenkinsfile)

## Support

- GitHub Issues: https://github.com/policyguard/policyguard/issues
- Documentation: https://policyguard.io/docs
- Community: https://policyguard.io/community