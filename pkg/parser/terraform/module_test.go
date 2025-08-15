package terraform

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParser_ModuleSupport(t *testing.T) {
	parser := New()
	ctx := context.Background()
	
	// Create temporary directory with test files
	tmpDir := t.TempDir()
	
	// Create root module that uses a child module
	rootModuleContent := `
module "security_module" {
  source = "./modules/security"
  
  name        = "test-sg"
  description = "Test Security Group"
  vpc_id      = "vpc-12345678"
  
  ingress_rules = [
    {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
      description = "HTTP"
    },
    {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
      description = "HTTPS"
    }
  ]
  
  egress_rules = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
}
`
	
	// Create child module files
	moduleDir := filepath.Join(tmpDir, "modules", "security")
	if err := os.MkdirAll(moduleDir, 0755); err != nil {
		t.Fatalf("Failed to create module directory: %v", err)
	}
	
	// Create main.tf in the child module
	childModuleContent := `
resource "aws_security_group" "this" {
  name        = var.name
  description = var.description
  vpc_id      = var.vpc_id
  
  tags = var.tags
}

resource "aws_security_group_rule" "ingress" {
  count = length(var.ingress_rules)
  
  security_group_id = aws_security_group.this.id
  type              = "ingress"
  from_port         = var.ingress_rules[count.index].from_port
  to_port           = var.ingress_rules[count.index].to_port
  protocol          = var.ingress_rules[count.index].protocol
  cidr_blocks       = var.ingress_rules[count.index].cidr_blocks
}
`
	
	// Create variables.tf in the child module
	variablesContent := `
variable "name" {
  type = string
}

variable "description" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "ingress_rules" {
  type = list(object({
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
    description = string
  }))
  default = []
}

variable "egress_rules" {
  type = list(object({
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
  }))
  default = []
}

variable "tags" {
  type    = map(string)
  default = {}
}
`
	
	// Write the files
	if err := os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte(rootModuleContent), 0644); err != nil {
		t.Fatalf("Failed to write root module file: %v", err)
	}
	
	if err := os.WriteFile(filepath.Join(moduleDir, "main.tf"), []byte(childModuleContent), 0644); err != nil {
		t.Fatalf("Failed to write child module main file: %v", err)
	}
	
	if err := os.WriteFile(filepath.Join(moduleDir, "variables.tf"), []byte(variablesContent), 0644); err != nil {
		t.Fatalf("Failed to write child module variables file: %v", err)
	}
	
	// Parse directory
	resources, err := parser.ParseDirectory(ctx, tmpDir)
	if err != nil {
		t.Fatalf("ParseDirectory() error = %v", err)
	}
	
	// Check that we found the module
	var foundModule bool
	var foundSecurityGroup bool
	var foundSecurityGroupRule bool
	var foundModulePrefix bool
	
	for _, resource := range resources {
		// Check if we found the module definition
		if resource.Type == "module" && resource.Name == "security_module" {
			foundModule = true
		}
		
		// Check if we found the security group from the module
		if strings.Contains(resource.ID, "module.security_module") && resource.Type == "aws_security_group" {
			foundSecurityGroup = true
			
			// Check if we have module information in attributes
			if moduleName, ok := resource.Attributes["_module_name"].(string); ok {
				if moduleName == "security_module" {
					foundModulePrefix = true
				}
			}
		}
		
		// Check if we found the security group rules from the module
		if strings.Contains(resource.ID, "module.security_module") && resource.Type == "aws_security_group_rule" {
			foundSecurityGroupRule = true
		}
	}
	
	if !foundModule {
		t.Errorf("Module resource not found")
	}
	
	if !foundSecurityGroup {
		t.Errorf("Security group from module not found")
	}
	
	if !foundSecurityGroupRule {
		t.Errorf("Security group rule from module not found")
	}
	
	if !foundModulePrefix {
		t.Errorf("Module information not added to resource attributes")
	}
}