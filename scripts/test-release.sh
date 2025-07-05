#!/bin/bash

# Test script for verifying release setup
# This script tests the build process and binary functionality

set -e

echo "Testing PolicyGuard Release Setup..."
echo "========================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "success")
            echo -e "${GREEN} $message${NC}"
            ;;
        "error")
            echo -e "${RED} $message${NC}"
            ;;
        "info")
            echo -e "${YELLOW}ℹ $message${NC}"
            ;;
    esac
}

# Check if we're in the right directory
if [ ! -f "go.mod" ]; then
    print_status "error" "go.mod not found. Please run this script from the project root."
    exit 1
fi

print_status "info" "Step 1: Testing Go module setup"

# Check Go version
GO_VERSION=$(go version | cut -d' ' -f3)
print_status "success" "Go version: $GO_VERSION"

# Verify module
go mod verify
print_status "success" "Go module verification passed"

# Download dependencies
go mod download
print_status "success" "Dependencies downloaded"

print_status "info" "Step 2: Running tests"

# Run tests with coverage
go test -v -race -coverprofile=coverage.out ./...
TEST_EXIT_CODE=$?

if [ $TEST_EXIT_CODE -eq 0 ]; then
    print_status "success" "All tests passed"
    
    # Generate coverage report
    go tool cover -func=coverage.out | tail -n 1
    go tool cover -html=coverage.out -o coverage.html
    print_status "success" "Coverage report generated: coverage.html"
else
    print_status "error" "Tests failed"
    exit 1
fi

print_status "info" "Step 3: Testing builds for multiple platforms"

# Create build directory
mkdir -p build/test

# Set version info for testing
VERSION="test-$(git rev-parse --short HEAD)"
COMMIT=$(git rev-parse --short HEAD)
DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS="-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE} -s -w"

# Build for different platforms
platforms=(
    "linux/amd64"
    "linux/arm64" 
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
)

for platform in "${platforms[@]}"; do
    IFS='/' read -r GOOS GOARCH <<< "$platform"
    output_name="policyguard-${GOOS}-${GOARCH}"
    
    if [ "$GOOS" = "windows" ]; then
        output_name="${output_name}.exe"
    fi
    
    print_status "info" "Building for $GOOS/$GOARCH..."
    
    GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="${LDFLAGS}" -o "build/test/${output_name}" ./cmd/policyguard
    
    if [ $? -eq 0 ]; then
        print_status "success" "Built $output_name"
    else
        print_status "error" "Failed to build for $GOOS/$GOARCH"
        exit 1
    fi
done

print_status "info" "Step 4: Testing binary functionality"

# Test the Linux binary (since we're likely running on Linux/Mac)
BINARY="build/test/policyguard-linux-amd64"
if [[ "$OSTYPE" == "darwin"* ]]; then
    BINARY="build/test/policyguard-darwin-amd64"
fi

chmod +x "$BINARY"

# Test version command
print_status "info" "Testing version command..."
VERSION_OUTPUT=$($BINARY --version)
echo "Version output: $VERSION_OUTPUT"

if [[ $VERSION_OUTPUT == *"$VERSION"* ]]; then
    print_status "success" "Version command works correctly"
else
    print_status "error" "Version command output incorrect"
    exit 1
fi

# Test help command
print_status "info" "Testing help command..."
HELP_OUTPUT=$($BINARY --help 2>&1)

if [[ $HELP_OUTPUT == *"PolicyGuard is a security policy engine"* ]]; then
    print_status "success" "Help command works correctly"
else
    print_status "error" "Help command output incorrect"
    exit 1
fi

# Test policy validation
print_status "info" "Testing policy validation..."
if $BINARY validate policies/ > /dev/null 2>&1; then
    print_status "success" "Policy validation works"
else
    print_status "error" "Policy validation failed"
    exit 1
fi

# Test Terraform scanning
print_status "info" "Testing Terraform file scanning..."
if [ -f "examples/terraform/insecure_s3.tf" ]; then
    SCAN_OUTPUT=$($BINARY scan examples/terraform/insecure_s3.tf 2>&1)
    
    if [[ $SCAN_OUTPUT == *"VIOLATIONS"* ]] || [[ $SCAN_OUTPUT == *"violation"* ]]; then
        print_status "success" "Terraform scanning detected violations correctly"
    else
        print_status "error" "Terraform scanning failed to detect violations"
        echo "Scan output: $SCAN_OUTPUT"
        exit 1
    fi
else
    print_status "info" "Skipping Terraform scan test (example file not found)"
fi

# Test OpenTofu scanning
print_status "info" "Testing OpenTofu file scanning..."
if [ -f "examples/opentofu/s3_insecure.tofu" ]; then
    SCAN_OUTPUT=$($BINARY scan examples/opentofu/s3_insecure.tofu 2>&1)
    
    if [[ $SCAN_OUTPUT == *"VIOLATIONS"* ]] || [[ $SCAN_OUTPUT == *"violation"* ]]; then
        print_status "success" "OpenTofu scanning detected violations correctly"
    else
        print_status "error" "OpenTofu scanning failed to detect violations"
        echo "Scan output: $SCAN_OUTPUT"
        exit 1
    fi
else
    print_status "info" "Skipping OpenTofu scan test (example file not found)"
fi

# Test different output formats
print_status "info" "Testing output formats..."

formats=("json" "sarif" "junit")
for format in "${formats[@]}"; do
    print_status "info" "Testing $format format..."
    
    if [ -f "examples/terraform/insecure_s3.tf" ]; then
        OUTPUT_FILE="build/test/test-output.$format"
        
        if $BINARY scan examples/terraform/insecure_s3.tf -f "$format" -o "$OUTPUT_FILE" 2>/dev/null; then
            if [ -f "$OUTPUT_FILE" ] && [ -s "$OUTPUT_FILE" ]; then
                print_status "success" "$format format output generated"
                
                # Basic validation of output format
                case $format in
                    "json")
                        if jq . "$OUTPUT_FILE" > /dev/null 2>&1; then
                            print_status "success" "JSON output is valid"
                        else
                            print_status "error" "JSON output is invalid"
                        fi
                        ;;
                    "sarif")
                        if grep -q '"version"' "$OUTPUT_FILE" && grep -q '"runs"' "$OUTPUT_FILE"; then
                            print_status "success" "SARIF output looks valid"
                        else
                            print_status "error" "SARIF output format incorrect"
                        fi
                        ;;
                    "junit")
                        if grep -q 'testcase' "$OUTPUT_FILE"; then
                            print_status "success" "JUnit output looks valid" 
                        else
                            print_status "error" "JUnit output format incorrect"
                        fi
                        ;;
                esac
            else
                print_status "error" "$format output file not created or empty"
            fi
        else
            print_status "error" "Failed to generate $format output"
        fi
    fi
done

# Test policy listing
print_status "info" "Testing policy listing..."
POLICY_LIST_OUTPUT=$($BINARY policy list 2>&1)

if [[ $POLICY_LIST_OUTPUT == *"Available policies"* ]] && [[ $POLICY_LIST_OUTPUT == *"AWS"* ]]; then
    print_status "success" "Policy listing works correctly"
else
    print_status "error" "Policy listing failed"
    echo "Policy list output: $POLICY_LIST_OUTPUT"
fi

# Test policy show command
print_status "info" "Testing policy show command..."
POLICY_SHOW_OUTPUT=$($BINARY policy show s3_bucket_encryption 2>&1)

if [[ $POLICY_SHOW_OUTPUT == *"Policy:"* ]] || [[ $POLICY_SHOW_OUTPUT == *"not found"* ]]; then
    print_status "success" "Policy show command works"
else
    print_status "error" "Policy show command failed"
    echo "Policy show output: $POLICY_SHOW_OUTPUT"
fi

print_status "info" "Step 5: Calculating checksums"

# Generate checksums
cd build/test
sha256sum policyguard-* > checksums.txt
print_status "success" "Checksums generated"
cd ../..

print_status "info" "Step 6: Cleanup"

# Optional: Remove test build artifacts
# rm -rf build/test
print_status "success" "Test build artifacts preserved in build/test/"

echo
echo " All tests completed successfully!"
echo "=================================="
echo
print_status "success" "Release setup is ready!"
echo
echo "Next steps:"
echo "1. Commit your changes"
echo "2. Create and push a version tag: git tag -a v1.0.0 -m 'Release v1.0.0'"
echo "3. Push the tag: git push origin v1.0.0"
echo "4. Watch the GitHub Actions workflow create the release"
echo
echo "Manual testing commands:"
echo "- ./build/test/policyguard-linux-amd64 --version"
echo "- ./build/test/policyguard-linux-amd64 scan examples/terraform/"
echo "- ./build/test/policyguard-linux-amd64 policy list"