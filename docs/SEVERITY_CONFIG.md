# Policy Severity Configuration

PolicyGuard allows customizing the severity levels of policy violations to align with your organization's security requirements and risk tolerance.

## Usage

To apply custom severity levels, create a JSON configuration file and use the `--severity-config` flag when running the scan:

```bash
policyguard scan path/to/iac/files --severity-config path/to/severity-config.json
```

## Configuration Format

The severity configuration file uses a simple JSON format:

```json
{
  "description": "Custom policy severity configuration",
  "default_severity": "medium",
  "severities": {
    "policy_id_1": "critical",
    "policy_id_2": "low",
    "policy_id_3": "high"
  }
}
```

### Configuration Fields

| Field | Description | Required |
|-------|-------------|----------|
| `description` | A description of the configuration | No |
| `default_severity` | The default severity level to use if a policy doesn't have a severity specified | No (defaults to "medium") |
| `severities` | A mapping of policy IDs to custom severity levels | Yes |

### Valid Severity Levels

- `critical`: Critical severity issues that must be addressed immediately
- `high`: High-priority security concerns
- `medium`: Moderate security issues
- `low`: Low-risk security concerns
- `info`: Informational findings with minimal security impact

## Example Configuration

```json
{
  "description": "Production environment severity configuration",
  "default_severity": "medium",
  "severities": {
    "s3_bucket_encryption": "critical",
    "s3_bucket_logging": "low",
    "dynamodb_encryption": "high",
    "dynamodb_recovery": "medium",
    "sns_encryption": "high",
    "sqs_encryption": "high"
  }
}
```

This configuration:
1. Sets `s3_bucket_encryption` to `critical` (elevated severity)
2. Lowers `s3_bucket_logging` to `low` (reduced severity)
3. Keeps other policies at their default or specified levels

## Benefits of Severity Customization

1. **Organizational Flexibility**: Different organizations have different risk tolerances and compliance requirements
2. **Prioritization**: Focus remediation efforts on the most critical issues first
3. **Environment-Specific Configurations**: Apply different severity levels for development vs. production environments
4. **Compliance Alignment**: Map policy violations to specific compliance framework requirements