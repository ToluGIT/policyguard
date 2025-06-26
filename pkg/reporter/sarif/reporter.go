package sarif

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ToluGIT/policyguard/pkg/types"
)

// Reporter implements the SARIF format reporter
type Reporter struct{}

// New creates a new SARIF reporter
func New() *Reporter {
	return &Reporter{}
}

// Generate creates a report from policy results
func (r *Reporter) Generate(ctx context.Context, result *types.PolicyResult, resources []types.Resource) (*types.Report, error) {
	report := &types.Report{
		ID:        fmt.Sprintf("report-%d", time.Now().Unix()),
		Timestamp: time.Now(),
		Resources: resources,
		Violations: result.Violations,
		Metadata:  result.Metadata,
	}

	// Calculate summary
	violationsBySeverity := make(map[string]int)
	for _, v := range result.Violations {
		violationsBySeverity[v.Severity]++
	}

	report.Summary = types.Summary{
		TotalResources:       len(resources),
		TotalViolations:      len(result.Violations),
		ViolationsBySeverity: violationsBySeverity,
		PassRate:             float64(len(resources)-len(result.Violations)) / float64(len(resources)) * 100,
	}

	return report, nil
}

// Write writes the report to the given writer in SARIF format
func (r *Reporter) Write(ctx context.Context, report *types.Report, writer io.Writer) error {
	sarifReport := r.toSARIF(report)
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(sarifReport)
}

// Format returns the format this reporter outputs
func (r *Reporter) Format() string {
	return "sarif"
}

// SARIF structures
type sarifReport struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []sarifRun  `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	SemanticVersion string      `json:"semanticVersion"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string                `json:"id"`
	Name             string                `json:"name"`
	ShortDescription sarifText             `json:"shortDescription"`
	FullDescription  sarifText             `json:"fullDescription"`
	Help             sarifText             `json:"help"`
	DefaultConfig    sarifRuleConfig       `json:"defaultConfiguration"`
	Properties       map[string]interface{} `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string              `json:"ruleId"`
	Level     string              `json:"level"`
	Message   sarifMessage        `json:"message"`
	Locations []sarifLocation     `json:"locations"`
	Fixes     []sarifFix          `json:"fixes,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

type sarifFix struct {
	Description sarifMessage         `json:"description"`
	Changes     []sarifChange        `json:"artifactChanges"`
}

type sarifChange struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Replacements     []sarifReplacement    `json:"replacements"`
}

type sarifReplacement struct {
	DeletedRegion sarifRegion `json:"deletedRegion"`
	InsertedContent sarifContent `json:"insertedContent"`
}

type sarifContent struct {
	Text string `json:"text"`
}

func (r *Reporter) toSARIF(report *types.Report) *sarifReport {
	// Collect unique rules and build generic descriptions
	rulesMap := make(map[string]*sarifRule)
	for _, violation := range report.Violations {
		if _, exists := rulesMap[violation.PolicyID]; !exists {
			// Create a generic rule description based on policy ID
			rule := sarifRule{
				ID:   violation.PolicyID,
				Name: violation.PolicyID,
				ShortDescription: sarifText{
					Text: getPolicyTitle(violation.PolicyID),
				},
				FullDescription: sarifText{
					Text: violation.Details,
				},
				Help: sarifText{
					Text: violation.Remediation,
				},
				DefaultConfig: sarifRuleConfig{
					Level: severityToSARIFLevel(violation.Severity),
				},
				Properties: map[string]interface{}{
					"severity": violation.Severity,
					"tags":     []string{"security", "infrastructure-as-code", "terraform"},
				},
			}
			rulesMap[violation.PolicyID] = &rule
		}
	}

	// Build rules array
	rules := make([]sarifRule, 0)
	for _, rule := range rulesMap {
		rules = append(rules, *rule)
	}

	// Build results
	results := make([]sarifResult, 0)
	for _, violation := range report.Violations {
		result := sarifResult{
			RuleID:  violation.PolicyID,
			Level:   severityToSARIFLevel(violation.Severity),
			Message: sarifMessage{
				Text: violation.Message,
			},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: violation.Location.File,
						},
						Region: sarifRegion{
							StartLine:   violation.Location.Line,
							StartColumn: violation.Location.Column,
						},
					},
				},
			},
		}

		// Note: We don't add fixes because SARIF requires artifactChanges with minItems: 1
		// Since we only have remediation text without actual code changes, we skip the fixes field
		// The remediation text is already included in the help text of the rule

		results = append(results, result)
	}

	return &sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:            "PolicyGuard",
						Version:         "1.0.0",
						SemanticVersion: "1.0.0",
						Rules:           rules,
					},
				},
				Results: results,
			},
		},
	}
}

func severityToSARIFLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "error"
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "warning"
	}
}

// getPolicyTitle returns a generic title for a given policy ID
func getPolicyTitle(policyID string) string {
	titles := map[string]string{
		// S3 policies
		"s3_bucket_encryption": "S3 Bucket Encryption",
		"s3_bucket_public_access": "S3 Bucket Public Access",
		"s3_bucket_logging": "S3 Bucket Logging",
		"s3_public_access_block_acls": "S3 Public Access Block - Block Public ACLs",
		"s3_public_access_block_policy": "S3 Public Access Block - Block Public Policy",
		"s3_public_access_ignore_acls": "S3 Public Access Block - Ignore Public ACLs",
		"s3_public_access_restrict_buckets": "S3 Public Access Block - Restrict Public Buckets",
		
		// EC2 policies
		"ec2_instance_encryption": "EC2 Instance Volume Encryption",
		"ec2_instance_public_ip": "EC2 Instance Public IP",
		"ec2_instance_imdsv2": "EC2 Instance IMDSv2",
		"ec2_instance_security": "EC2 Instance Security",
		"security_group_ssh_open": "Security Group SSH Access",
		"security_group_unrestricted": "Security Group Unrestricted Access",
		"ebs_volume_encryption": "EBS Volume Encryption",
		
		// IAM policies
		"iam_no_wildcard_actions": "IAM Wildcard Actions",
		"iam_no_wildcard_resources": "IAM Wildcard Resources",
		"iam_user_mfa_required": "IAM User MFA Required",
		"iam_role_require_mfa": "IAM Role MFA Required",
		"iam_role_trust_policy": "IAM Role Trust Policy",
		"iam_no_inline_policies": "IAM Inline Policies",
		"iam_password_policy_length": "IAM Password Policy Length",
		"iam_password_complexity": "IAM Password Complexity",
		"iam_password_rotation": "IAM Password Rotation",
		"iam_access_key_rotation": "IAM Access Key Rotation",
		
		// RDS policies
		"rds_encryption": "RDS Encryption at Rest",
		"rds_backup_retention": "RDS Backup Retention",
		"rds_multi_az": "RDS Multi-AZ Deployment",
		"rds_public_access": "RDS Public Access",
		"rds_deletion_protection": "RDS Deletion Protection",
		"rds_minor_version_upgrade": "RDS Auto Minor Version Upgrade",
		"rds_monitoring": "RDS Enhanced Monitoring",
		"rds_backup_window": "RDS Backup Window",
		"rds_storage_autoscaling": "RDS Storage Autoscaling",
		"rds_storage_type": "RDS Storage Type",
		"rds_engine_version": "RDS Engine Version",
		"rds_maintenance_window": "RDS Maintenance Window",
		
		// VPC policies
		"vpc_flow_logs": "VPC Flow Logs",
		"vpc_default_security_group": "VPC Default Security Group",
		"vpc_network_acl_unrestricted": "VPC Network ACL Unrestricted",
		"vpc_network_acl_ingress": "VPC Network ACL Ingress Rules",
		"vpc_network_acl_egress": "VPC Network ACL Egress Rules",
		"vpc_subnet_public_ip": "VPC Subnet Auto-assign Public IP",
		"vpc_subnet_availability_zone": "VPC Subnet Availability Zone",
		"vpc_endpoint_policy": "VPC Endpoint Policy",
		"vpc_endpoint_private_dns": "VPC Endpoint Private DNS",
		"vpc_security_group_description": "VPC Security Group Description",
		"vpc_cidr_block_size": "VPC CIDR Block Size",
		"vpc_dns_hostnames": "VPC DNS Hostnames",
		
		// Lambda policies
		"lambda_env_encryption": "Lambda Environment Variables Encryption",
		"lambda_env_secrets": "Lambda Environment Variables Secrets",
		"lambda_dlq": "Lambda Dead Letter Queue",
		"lambda_tracing": "Lambda X-Ray Tracing",
		"lambda_vpc_config": "Lambda VPC Configuration",
		"lambda_timeout": "Lambda Timeout Configuration",
		"lambda_memory": "Lambda Memory Configuration",
		"lambda_concurrent_executions": "Lambda Concurrent Executions",
		"lambda_runtime": "Lambda Runtime Version",
		"lambda_code_signing": "Lambda Code Signing",
		"lambda_cors": "Lambda CORS Configuration",
		"lambda_layers": "Lambda Layers Security",
	}
	
	if title, exists := titles[policyID]; exists {
		return title
	}
	
	// Fallback: convert policy_id to title case
	words := strings.Split(policyID, "_")
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + word[1:]
		}
	}
	return strings.Join(words, " ")
}