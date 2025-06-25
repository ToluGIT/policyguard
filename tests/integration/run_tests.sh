#!/bin/bash

# Run integration tests for PolicyGuard

set -e

echo "======================================"
echo "Running PolicyGuard Integration Tests"
echo "======================================"
echo

# Get the directory of this script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$SCRIPT_DIR/../.."

cd "$PROJECT_ROOT"

# Build the binary
echo "Building PolicyGuard..."
make build

# Run integration tests
echo
echo "Running integration tests..."
go test -v -tags=integration ./tests/integration/...

echo
echo "======================================"
echo "Integration Tests Complete!"
echo "======================================"