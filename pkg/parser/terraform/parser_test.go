package terraform

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/policyguard/policyguard/pkg/types"
)

func TestParser_Parse(t *testing.T) {
	parser := New()
	ctx := context.Background()

	tests := []struct {
		name     string
		content  string
		filename string
		want     []types.Resource
		wantErr  bool
	}{
		{
			name:     "parse s3 bucket",
			filename: "test_s3.tf",
			content: `
resource "aws_s3_bucket" "test" {
  bucket = "my-test-bucket"
  acl    = "private"
  
  tags = {
    Name = "Test Bucket"
    Environment = "test"
  }
}`,
			want: []types.Resource{
				{
					ID:       "aws_s3_bucket.test",
					Type:     "aws_s3_bucket",
					Provider: "aws",
					Name:     "test",
					Attributes: map[string]interface{}{
						"bucket": "my-test-bucket",
						"acl":    "private",
						"tags": map[string]interface{}{
							"Name":        "Test Bucket",
							"Environment": "test",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:     "parse ec2 instance",
			filename: "test_ec2.tf",
			content: `
resource "aws_instance" "test" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  
  associate_public_ip_address = false
  
  root_block_device {
    encrypted = true
    volume_size = 20
  }
  
  tags = {
    Name = "Test Instance"
  }
}`,
			want: []types.Resource{
				{
					ID:       "aws_instance.test",
					Type:     "aws_instance",
					Provider: "aws",
					Name:     "test",
					Attributes: map[string]interface{}{
						"ami":                         "ami-12345678",
						"instance_type":               "t2.micro",
						"associate_public_ip_address": false,
						"root_block_device": map[string]interface{}{
							"encrypted":   true,
							"volume_size": float64(20),
						},
						"tags": map[string]interface{}{
							"Name": "Test Instance",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name:     "parse security group",
			filename: "test_sg.tf",
			content: `
resource "aws_security_group" "test" {
  name        = "test-sg"
  description = "Test security group"
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`,
			want: []types.Resource{
				{
					ID:       "aws_security_group.test",
					Type:     "aws_security_group",
					Provider: "aws",
					Name:     "test",
					Attributes: map[string]interface{}{
						"name":        "test-sg",
						"description": "Test security group",
					},
				},
			},
			wantErr: false,
		},
		{
			name:     "parse data source",
			filename: "test_data.tf",
			content: `
data "aws_ami" "ubuntu" {
  most_recent = true
  
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }
  
  owners = ["099720109477"]
}`,
			want: []types.Resource{
				{
					ID:       "data.aws_ami.ubuntu",
					Type:     "data.aws_ami",
					Provider: "aws",
					Name:     "ubuntu",
					Attributes: map[string]interface{}{
						"most_recent": true,
					},
				},
			},
			wantErr: false,
		},
		{
			name:     "parse invalid HCL",
			filename: "test_invalid.tf",
			content: `
resource "aws_s3_bucket" "test" {
  bucket = "test-bucket"
  invalid syntax here
}`,
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, tt.filename)
			
			err := os.WriteFile(tmpFile, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}
			
			// Parse the file
			got, err := parser.Parse(ctx, tmpFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("Parse() returned %d resources, want %d", len(got), len(tt.want))
					return
				}
				
				for i, resource := range got {
					if resource.ID != tt.want[i].ID {
						t.Errorf("Resource ID = %v, want %v", resource.ID, tt.want[i].ID)
					}
					if resource.Type != tt.want[i].Type {
						t.Errorf("Resource Type = %v, want %v", resource.Type, tt.want[i].Type)
					}
					if resource.Provider != tt.want[i].Provider {
						t.Errorf("Resource Provider = %v, want %v", resource.Provider, tt.want[i].Provider)
					}
					if resource.Name != tt.want[i].Name {
						t.Errorf("Resource Name = %v, want %v", resource.Name, tt.want[i].Name)
					}
				}
			}
		})
	}
}

func TestParser_ParseDirectory(t *testing.T) {
	parser := New()
	ctx := context.Background()
	
	// Create temporary directory with test files
	tmpDir := t.TempDir()
	
	// Create test files
	files := map[string]string{
		"s3.tf": `
resource "aws_s3_bucket" "test1" {
  bucket = "test-bucket-1"
}`,
		"ec2.tf": `
resource "aws_instance" "test2" {
  ami = "ami-12345678"
  instance_type = "t2.micro"
}`,
		// Skip JSON parsing for now as it requires different handling
		"not_terraform.txt": `This should be ignored`,
	}
	
	for filename, content := range files {
		err := os.WriteFile(filepath.Join(tmpDir, filename), []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}
	
	// Parse directory
	resources, err := parser.ParseDirectory(ctx, tmpDir)
	if err != nil {
		t.Fatalf("ParseDirectory() error = %v", err)
	}
	
	// Should find 2 resources from .tf files
	if len(resources) != 2 {
		t.Errorf("ParseDirectory() returned %d resources, want 2", len(resources))
	}
	
	// Check resource IDs
	expectedIDs := map[string]bool{
		"aws_s3_bucket.test1": false,
		"aws_instance.test2":  false,
	}
	
	for _, resource := range resources {
		if _, exists := expectedIDs[resource.ID]; exists {
			expectedIDs[resource.ID] = true
		}
	}
	
	for id, found := range expectedIDs {
		if !found {
			t.Errorf("Expected resource %s not found", id)
		}
	}
}

func TestParser_SupportedExtensions(t *testing.T) {
	parser := New()
	
	extensions := parser.SupportedExtensions()
	expected := []string{".tf", ".tf.json"}
	
	if len(extensions) != len(expected) {
		t.Errorf("SupportedExtensions() returned %d extensions, want %d", len(extensions), len(expected))
	}
	
	for i, ext := range extensions {
		if ext != expected[i] {
			t.Errorf("Extension[%d] = %v, want %v", i, ext, expected[i])
		}
	}
}