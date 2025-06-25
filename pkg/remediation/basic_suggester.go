package remediation

import (
	"context"
	"fmt"
	"strings"

	"github.com/ToluGIT/policyguard/pkg/types"
)

// BasicSuggester provides basic remediation suggestions
type BasicSuggester struct {
	suggestions map[string]suggestionTemplate
}

type suggestionTemplate struct {
	description string
	steps       []string
	codeFixFunc func(resource types.Resource) *CodeFix
	references  []string
}

// NewBasicSuggester creates a new basic suggester
func NewBasicSuggester() *BasicSuggester {
	return &BasicSuggester{
		suggestions: initSuggestionTemplates(),
	}
}

// Suggest generates remediation suggestion for a single violation
func (s *BasicSuggester) Suggest(ctx context.Context, violation types.PolicyViolation, resource types.Resource) (*Suggestion, error) {
	// Extract policy type from violation
	policyType := extractPolicyType(violation.PolicyID)
	
	template, exists := s.suggestions[policyType]
	if !exists {
		// Return generic suggestion if no specific template exists
		return s.genericSuggestion(violation, resource), nil
	}
	
	suggestion := &Suggestion{
		ViolationID: violation.ID,
		Type:        "remediation",
		Description: template.description,
		Steps:       template.steps,
		References:  template.references,
	}
	
	// Generate code fix if available
	if template.codeFixFunc != nil {
		suggestion.CodeFix = template.codeFixFunc(resource)
	}
	
	return suggestion, nil
}

// SuggestBatch generates suggestions for multiple violations
func (s *BasicSuggester) SuggestBatch(ctx context.Context, violations []types.PolicyViolation, resources []types.Resource) ([]*Suggestion, error) {
	// Create resource map for quick lookup
	resourceMap := make(map[string]types.Resource)
	for _, r := range resources {
		resourceMap[r.ID] = r
	}
	
	suggestions := make([]*Suggestion, 0, len(violations))
	for _, violation := range violations {
		resource, exists := resourceMap[violation.ResourceID]
		if !exists {
			continue
		}
		
		suggestion, err := s.Suggest(ctx, violation, resource)
		if err != nil {
			return nil, fmt.Errorf("failed to generate suggestion for violation %s: %w", violation.ID, err)
		}
		
		suggestions = append(suggestions, suggestion)
	}
	
	return suggestions, nil
}

// genericSuggestion creates a generic suggestion when no specific template exists
func (s *BasicSuggester) genericSuggestion(violation types.PolicyViolation, resource types.Resource) *Suggestion {
	return &Suggestion{
		ViolationID: violation.ID,
		Type:        "generic",
		Description: fmt.Sprintf("Review and fix the security issue: %s", violation.Message),
		Steps: []string{
			fmt.Sprintf("1. Review the resource '%s' in %s", resource.ID, resource.Location.File),
			fmt.Sprintf("2. Address the issue: %s", violation.Details),
			"3. Consult security best practices for your cloud provider",
			"4. Re-run the security scan to verify the fix",
		},
		References: []string{
			"https://docs.aws.amazon.com/security/",
			"https://cloud.google.com/security/best-practices",
			"https://docs.microsoft.com/azure/security/",
		},
	}
}

// extractPolicyType extracts the policy type from policy ID
func extractPolicyType(policyID string) string {
	// Policy IDs follow pattern: provider-resource-rule
	// e.g., "aws-s3-bucket-encryption", "aws-ec2-public-ip"
	parts := strings.Split(policyID, "-")
	if len(parts) >= 3 {
		return strings.Join(parts[1:], "-")
	}
	return policyID
}

// initSuggestionTemplates initializes remediation templates
func initSuggestionTemplates() map[string]suggestionTemplate {
	return map[string]suggestionTemplate{
		"s3-bucket-encryption": {
			description: "Enable encryption for S3 bucket",
			steps: []string{
				"1. Add server-side encryption configuration to the S3 bucket",
				"2. Choose appropriate encryption method (SSE-S3, SSE-KMS, or SSE-C)",
				"3. Apply the configuration using Terraform",
				"4. Verify encryption is enabled in AWS Console",
			},
			codeFixFunc: s3EncryptionFix,
			references: []string{
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration",
			},
		},
		"s3-bucket-public-access": {
			description: "Block public access to S3 bucket",
			steps: []string{
				"1. Remove public ACL from S3 bucket configuration",
				"2. Add S3 bucket public access block configuration",
				"3. Set all public access block settings to true",
				"4. Verify public access is blocked in AWS Console",
			},
			codeFixFunc: s3PublicAccessFix,
			references: []string{
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
			},
		},
		"s3-bucket-logging": {
			description: "Enable access logging for S3 bucket",
			steps: []string{
				"1. Create or identify a target bucket for logs",
				"2. Add logging configuration to the S3 bucket",
				"3. Set appropriate log file prefix",
				"4. Verify logging is enabled",
			},
			codeFixFunc: s3LoggingFix,
			references: []string{
				"https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html",
			},
		},
		"ec2-public-ip": {
			description: "Remove public IP from EC2 instance",
			steps: []string{
				"1. Set associate_public_ip_address to false",
				"2. Consider using NAT Gateway for outbound internet access",
				"3. Update security groups to restrict access",
				"4. Use VPN or bastion host for secure access",
			},
			codeFixFunc: ec2PublicIPFix,
			references: []string{
				"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html",
			},
		},
		"ec2-encryption": {
			description: "Enable encryption for EC2 volumes",
			steps: []string{
				"1. Set encrypted = true for root_block_device",
				"2. Set encrypted = true for all ebs_block_device blocks",
				"3. Optionally specify a KMS key for encryption",
				"4. Recreate instances to apply encryption",
			},
			codeFixFunc: ec2EncryptionFix,
			references: []string{
				"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
			},
		},
		"ec2-imdsv2": {
			description: "Enforce IMDSv2 for EC2 instance",
			steps: []string{
				"1. Set http_tokens = \"required\" in metadata_options",
				"2. Test applications to ensure IMDSv2 compatibility",
				"3. Update instance metadata options",
				"4. Verify IMDSv2 is enforced",
			},
			codeFixFunc: ec2IMDSv2Fix,
			references: []string{
				"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
			},
		},
		"security-group-open": {
			description: "Restrict security group rules",
			steps: []string{
				"1. Remove 0.0.0.0/0 from ingress rules",
				"2. Specify exact IP ranges or security groups",
				"3. Follow principle of least privilege",
				"4. Document legitimate access requirements",
			},
			codeFixFunc: securityGroupFix,
			references: []string{
				"https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html",
			},
		},
	}
}

// Code fix functions
func s3EncryptionFix(resource types.Resource) *CodeFix {
	return &CodeFix{
		FilePath:   resource.Location.File,
		LineNumber: resource.Location.Line,
		OldContent: fmt.Sprintf("resource \"%s\" \"%s\" {", resource.Type, resource.Name),
		NewContent: fmt.Sprintf(`resource "%s" "%s" {
  # ... existing configuration ...

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }`, resource.Type, resource.Name),
		Explanation: "Add server-side encryption configuration with AES256 algorithm",
	}
}

func s3PublicAccessFix(resource types.Resource) *CodeFix {
	return &CodeFix{
		FilePath:   resource.Location.File,
		LineNumber: resource.Location.Line,
		OldContent: `acl = "public-read-write"`,
		NewContent: `acl = "private"`,
		Explanation: "Change ACL from public-read-write to private",
	}
}

func s3LoggingFix(resource types.Resource) *CodeFix {
	return &CodeFix{
		FilePath:   resource.Location.File,
		LineNumber: resource.Location.Line,
		OldContent: fmt.Sprintf("resource \"%s\" \"%s\" {", resource.Type, resource.Name),
		NewContent: fmt.Sprintf(`resource "%s" "%s" {
  # ... existing configuration ...

  logging {
    target_bucket = aws_s3_bucket.log_bucket.id
    target_prefix = "logs/"
  }`, resource.Type, resource.Name),
		Explanation: "Add logging configuration to track access",
	}
}

func ec2PublicIPFix(resource types.Resource) *CodeFix {
	return &CodeFix{
		FilePath:   resource.Location.File,
		LineNumber: resource.Location.Line,
		OldContent: `associate_public_ip_address = true`,
		NewContent: `associate_public_ip_address = false`,
		Explanation: "Disable public IP assignment",
	}
}

func ec2EncryptionFix(resource types.Resource) *CodeFix {
	return &CodeFix{
		FilePath:   resource.Location.File,
		LineNumber: resource.Location.Line,
		OldContent: `encrypted = false`,
		NewContent: `encrypted = true`,
		Explanation: "Enable encryption for EBS volumes",
	}
}

func ec2IMDSv2Fix(resource types.Resource) *CodeFix {
	return &CodeFix{
		FilePath:   resource.Location.File,
		LineNumber: resource.Location.Line,
		OldContent: `http_tokens = "optional"`,
		NewContent: `http_tokens = "required"`,
		Explanation: "Enforce IMDSv2 by requiring tokens",
	}
}

func securityGroupFix(resource types.Resource) *CodeFix {
	return &CodeFix{
		FilePath:   resource.Location.File,
		LineNumber: resource.Location.Line,
		OldContent: `cidr_blocks = ["0.0.0.0/0"]`,
		NewContent: `cidr_blocks = ["10.0.0.0/8"] # Update with your specific IP range`,
		Explanation: "Restrict access to specific IP ranges instead of allowing all traffic",
	}
}