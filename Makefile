# MCP Security Scanner Makefile

.PHONY: all build test test-unit test-integration test-benchmarks test-coverage test-verbose clean deps fmt lint run-scanner run-proxy help

# Variables
BINARY_NAME=mcpscan
BUILD_DIR=./build
CMD_DIR=./cmd/mcpscan
GO_FILES=$(shell find . -type f -name '*.go')
TEST_TIMEOUT=30s
COVERAGE_OUTPUT=coverage.out

# Default target
all: deps fmt build test

# Build the application
build:
	@echo "Building MCP Security Scanner..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "Built $(BUILD_DIR)/$(BINARY_NAME)"

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod tidy
	go mod download

# Format Go code
fmt:
	@echo "Formatting Go code..."
	go fmt ./...

# Run linter
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found, skipping lint check"; \
		echo "Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Test targets
test: test-unit test-integration
	@echo "All tests completed"

test-unit:
	@echo "Running unit tests..."
	go test -timeout=$(TEST_TIMEOUT) ./test/unit/...

test-integration:
	@echo "Running integration tests..."
	go test -timeout=$(TEST_TIMEOUT) ./test/integration/...

test-benchmarks:
	@echo "Running benchmark tests..."
	@mkdir -p test_results
	go test -bench=. -benchmem -timeout=5m ./test/benchmarks/... | tee test_results/benchmark_results.txt

test-coverage:
	@echo "Running tests with coverage..."
	@mkdir -p test_results
	go test -coverprofile=test_results/coverage.out -covermode=atomic -timeout=$(TEST_TIMEOUT) ./...
	go tool cover -html=test_results/coverage.out -o test_results/coverage.html
	@echo "Coverage report generated: test_results/coverage.html"
	go tool cover -func=test_results/coverage.out | grep "total:"

test-verbose:
	@echo "Running tests with verbose output..."
	go test -v -timeout=$(TEST_TIMEOUT) ./test/...

test-all: test-unit test-integration test-benchmarks test-coverage
	@echo "All test suites completed"

# Advanced test targets using our test runner
test-runner:
	@echo "Running comprehensive test suite..."
	./test/run_tests.sh

test-runner-unit:
	@echo "Running unit tests only..."
	./test/run_tests.sh --unit-only

test-runner-integration:
	@echo "Running integration tests only..."
	./test/run_tests.sh --integration-only

test-runner-benchmarks:
	@echo "Running benchmark tests only..."
	./test/run_tests.sh --benchmarks-only

test-runner-full:
	@echo "Running full test suite with benchmarks..."
	./test/run_tests.sh --with-benchmarks --verbose

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -rf test_results
	go clean

# Run local scanner example
run-scanner:
	@echo "Running local scanner example..."
	$(BUILD_DIR)/$(BINARY_NAME) scan-local . critical-security

# Run proxy example
run-proxy:
	@echo "Running proxy example..."
	$(BUILD_DIR)/$(BINARY_NAME) proxy http://localhost:3000 8080

# List available policies
policies:
	@echo "Listing available policies..."
	$(BUILD_DIR)/$(BINARY_NAME) policies

# Install binary to system
install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "Installed successfully"

# Create release builds for multiple platforms
release:
	@echo "Building release binaries..."
	@mkdir -p $(BUILD_DIR)/release
	
	# Linux
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/release/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)
	
	# macOS
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/release/$(BINARY_NAME)-darwin-amd64 $(CMD_DIR)
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/release/$(BINARY_NAME)-darwin-arm64 $(CMD_DIR)
	
	# Windows
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/release/$(BINARY_NAME)-windows-amd64.exe $(CMD_DIR)
	
	@echo "Release binaries created in $(BUILD_DIR)/release/"

# Development server (build and run on file changes)
dev:
	@echo "Starting development mode..."
	@if command -v air >/dev/null 2>&1; then \
		air; \
	else \
		echo "air not found. Install with: go install github.com/cosmtrek/air@latest"; \
		echo "Falling back to simple build and run..."; \
		make build && $(BUILD_DIR)/$(BINARY_NAME) policies; \
	fi

# Generate documentation
docs:
	@echo "Generating documentation..."
	@mkdir -p docs/api
	@if command -v godoc >/dev/null 2>&1; then \
		echo "Documentation available at: http://localhost:6060/pkg/github.com/syphon1c/mcp-security-scanner/"; \
		godoc -http=:6060; \
	else \
		echo "godoc not found. Install with: go install golang.org/x/tools/cmd/godoc@latest"; \
	fi

# Security check
security:
	@echo "Running security checks..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not found. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi

# Performance benchmark
benchmark:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# Help target
help:
	@echo "MCP Security Scanner - Available Make targets:"
	@echo ""
	@echo "  build      - Build the application"
	@echo "  deps       - Install dependencies"
	@echo "  fmt        - Format Go code"
	@echo "  lint       - Run linter"
	@echo "  test       - Run tests"
	@echo "  clean      - Clean build artifacts"
	@echo "  install    - Install binary to system"
	@echo "  release    - Build release binaries for multiple platforms"
	@echo "  dev        - Development mode with auto-reload"
	@echo "  docs       - Generate and serve documentation"
	@echo "  security   - Run security checks"
	@echo "  benchmark  - Run performance benchmarks"
	@echo "  policies   - List available security policies"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make build && make run-scanner"
	@echo "  make build && make run-proxy"
