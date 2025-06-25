#!/bin/bash
set -e

echo "=== Testing PolicyGuard CI Integration ==="
echo

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Build PolicyGuard
echo "1. Building PolicyGuard..."
go build -o policyguard cmd/policyguard/main.go
echo -e "${GREEN}✓ Build successful${NC}"
echo

# Test different output formats
echo "2. Testing output formats..."

# Human format
echo "   Testing human format..."
./policyguard scan examples/terraform/1.tf > /dev/null 2>&1
echo -e "${GREEN}   ✓ Human format works${NC}"

# JSON format
echo "   Testing JSON format..."
./policyguard scan examples/terraform/1.tf -f json -o test-results.json
if [ -f "test-results.json" ] && jq -e . test-results.json > /dev/null 2>&1; then
    echo -e "${GREEN}   ✓ JSON format works${NC}"
else
    echo -e "${RED}   ✗ JSON format failed${NC}"
    exit 1
fi

# SARIF format
echo "   Testing SARIF format..."
./policyguard scan examples/terraform/1.tf -f sarif -o test-results.sarif
if [ -f "test-results.sarif" ] && jq -e '.version == "2.1.0"' test-results.sarif > /dev/null 2>&1; then
    echo -e "${GREEN}   ✓ SARIF format works${NC}"
else
    echo -e "${RED}   ✗ SARIF format failed${NC}"
    exit 1
fi

# JUnit format
echo "   Testing JUnit format..."
./policyguard scan examples/terraform/1.tf -f junit -o test-results.xml
if [ -f "test-results.xml" ] && grep -q "testsuites" test-results.xml; then
    echo -e "${GREEN}   ✓ JUnit format works${NC}"
else
    echo -e "${RED}   ✗ JUnit format failed${NC}"
    exit 1
fi

echo

# Test fail-on-error
echo "3. Testing fail-on-error..."
set +e
./policyguard scan examples/terraform/1.tf --fail-on-error > /dev/null 2>&1
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -ne 0 ]; then
    echo -e "${GREEN}   ✓ Fail-on-error works (exit code: $EXIT_CODE)${NC}"
else
    echo -e "${RED}   ✗ Fail-on-error did not fail as expected${NC}"
    exit 1
fi

echo

# Test directory scanning
echo "4. Testing directory scanning..."
./policyguard scan examples/terraform/ -f json -o test-dir-results.json
TOTAL_RESOURCES=$(jq '.summary.total_resources' test-dir-results.json)
if [ "$TOTAL_RESOURCES" -gt 0 ]; then
    echo -e "${GREEN}   ✓ Directory scanning works (found $TOTAL_RESOURCES resources)${NC}"
else
    echo -e "${RED}   ✗ Directory scanning failed${NC}"
    exit 1
fi

echo

# Display summary
echo "5. Summary of test results:"
echo "   - Human format: ✓"
echo "   - JSON format: ✓"
echo "   - SARIF format: ✓"
echo "   - JUnit format: ✓"
echo "   - Fail-on-error: ✓"
echo "   - Directory scan: ✓"

echo
echo -e "${GREEN}All CI integration tests passed!${NC}"
echo

# Cleanup
rm -f test-results.json test-results.sarif test-results.xml test-dir-results.json

echo "To test GitHub Actions locally, you can:"
echo "1. Push to a test branch: git push origin test"
echo "2. Use act (https://github.com/nektos/act): act -W .github/workflows/test-local.yml"
echo "3. Create a test repository and copy the workflow"