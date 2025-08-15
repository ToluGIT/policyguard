.PHONY: build test clean install lint integration-test test-all

# Variables
BINARY_NAME=policyguard
BINARY_PATH=./bin/$(BINARY_NAME)
MAIN_PATH=./cmd/policyguard
VERSION=0.3.0
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.date=$(BUILD_TIME)"

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p bin
	@go build $(LDFLAGS) -o $(BINARY_PATH) $(MAIN_PATH)
	@echo "Binary built at $(BINARY_PATH)"

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy

# Run tests
test:
	@echo "Running tests..."
	@go test -v -race -coverprofile=coverage.txt ./...

# Run linter
lint:
	@echo "Running linter..."
	@golangci-lint run

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf bin/ coverage.txt

# Install binary to $GOPATH/bin
install: build
	@echo "Installing $(BINARY_NAME)..."
	@cp $(BINARY_PATH) $(GOPATH)/bin/
	@echo "Installed to $(GOPATH)/bin/$(BINARY_NAME)"

# Development mode - rebuild on changes
dev:
	@echo "Running in development mode..."
	@air -c .air.toml

# Run the binary
run: build
	@$(BINARY_PATH) $(ARGS)

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Check for security vulnerabilities
security:
	@echo "Checking for vulnerabilities..."
	@gosec ./...

# Generate coverage report
coverage: test
	@echo "Generating coverage report..."
	@go tool cover -html=coverage.txt -o coverage.html
	@echo "Coverage report generated at coverage.html"

# Run integration tests
integration-test: build
	@echo "Running integration tests..."
	@go test -v -tags=integration ./tests/integration/...

# Run all tests (unit + integration)
test-all: test integration-test
	@echo "All tests completed!"