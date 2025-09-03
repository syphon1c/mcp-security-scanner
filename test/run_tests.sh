#!/bin/bash

# MCP Security Scanner Test Runner
# This script runs various types of tests for the MCP Security Scanner

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_TIMEOUT="30s"
COVERAGE_OUTPUT="coverage.out"
BENCH_OUTPUT="benchmark_results.txt"

# Test directories
UNIT_TEST_DIR="$PROJECT_ROOT/test/unit"
INTEGRATION_TEST_DIR="$PROJECT_ROOT/test/integration"
BENCHMARK_TEST_DIR="$PROJECT_ROOT/test/benchmarks"

# Default test types to run
RUN_UNIT=true
RUN_INTEGRATION=true
RUN_BENCHMARKS=false
RUN_COVERAGE=true
VERBOSE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --unit-only)
            RUN_UNIT=true
            RUN_INTEGRATION=false
            RUN_BENCHMARKS=false
            shift
            ;;
        --integration-only)
            RUN_UNIT=false
            RUN_INTEGRATION=true
            RUN_BENCHMARKS=false
            shift
            ;;
        --benchmarks-only)
            RUN_UNIT=false
            RUN_INTEGRATION=false
            RUN_BENCHMARKS=true
            shift
            ;;
        --with-benchmarks)
            RUN_BENCHMARKS=true
            shift
            ;;
        --no-coverage)
            RUN_COVERAGE=false
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --timeout)
            TEST_TIMEOUT="$2"
            shift 2
            ;;
        --help|-h)
            echo "MCP Security Scanner Test Runner"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --unit-only          Run only unit tests"
            echo "  --integration-only   Run only integration tests"
            echo "  --benchmarks-only    Run only benchmark tests"
            echo "  --with-benchmarks    Include benchmark tests (default: false)"
            echo "  --no-coverage        Skip coverage report generation"
            echo "  --verbose, -v        Enable verbose output"
            echo "  --timeout DURATION   Set test timeout (default: 30s)"
            echo "  --help, -h           Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                   # Run unit and integration tests with coverage"
            echo "  $0 --unit-only      # Run only unit tests"
            echo "  $0 --with-benchmarks # Run all tests including benchmarks"
            echo "  $0 --verbose         # Run with verbose output"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Change to project root
cd "$PROJECT_ROOT"

print_status "Starting MCP Security Scanner test suite..."
print_status "Project root: $PROJECT_ROOT"
print_status "Test timeout: $TEST_TIMEOUT"

# Check if Go is installed
if ! command -v go &> /dev/null; then
    print_error "Go is not installed or not in PATH"
    exit 1
fi

# Check Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
print_status "Using Go version: $GO_VERSION"

# Ensure dependencies are available
print_status "Downloading dependencies..."
go mod download

# Create test output directory
mkdir -p test_results

# Function to run tests with proper flags
run_tests() {
    local test_type="$1"
    local test_path="$2"
    local extra_flags="$3"
    
    print_status "Running $test_type tests..."
    
    local flags="-timeout=$TEST_TIMEOUT"
    if [ "$VERBOSE" = true ]; then
        flags="$flags -v"
    fi
    
    if [ "$RUN_COVERAGE" = true ] && [ "$test_type" != "benchmark" ]; then
        flags="$flags -coverprofile=test_results/${test_type}_coverage.out -covermode=atomic"
    fi
    
    # Add any extra flags
    if [ -n "$extra_flags" ]; then
        flags="$flags $extra_flags"
    fi
    
    # Run the tests
    if go test $flags "$test_path"; then
        print_success "$test_type tests passed"
        return 0
    else
        print_error "$test_type tests failed"
        return 1
    fi
}

# Track test results
FAILED_TESTS=0
TOTAL_TEST_SUITES=0

# Run unit tests
if [ "$RUN_UNIT" = true ]; then
    TOTAL_TEST_SUITES=$((TOTAL_TEST_SUITES + 1))
    if ! run_tests "unit" "./test/unit/..."; then
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
fi

# Run integration tests
if [ "$RUN_INTEGRATION" = true ]; then
    TOTAL_TEST_SUITES=$((TOTAL_TEST_SUITES + 1))
    print_status "Setting up integration test environment..."
    
    # Check if policies directory exists for integration tests
    if [ ! -d "policies" ]; then
        print_warning "Policies directory not found. Some integration tests may be skipped."
    fi
    
    if ! run_tests "integration" "./test/integration/..."; then
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
fi

# Run benchmark tests
if [ "$RUN_BENCHMARKS" = true ]; then
    TOTAL_TEST_SUITES=$((TOTAL_TEST_SUITES + 1))
    print_status "Running benchmark tests..."
    
    # Create benchmark output file
    BENCH_FILE="test_results/$BENCH_OUTPUT"
    
    # Run benchmarks with specific flags
    if go test -bench=. -benchmem -timeout=5m ./test/benchmarks/... > "$BENCH_FILE" 2>&1; then
        print_success "Benchmark tests completed"
        print_status "Benchmark results saved to: $BENCH_FILE"
        
        # Show summary of benchmark results
        if [ "$VERBOSE" = true ]; then
            echo ""
            print_status "Benchmark Summary:"
            grep -E "^Benchmark" "$BENCH_FILE" | head -10
        fi
    else
        print_error "Benchmark tests failed"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
fi

# Generate combined coverage report
if [ "$RUN_COVERAGE" = true ] && [ $FAILED_TESTS -eq 0 ]; then
    print_status "Generating coverage report..."
    
    # Combine coverage files if multiple exist
    COVERAGE_FILES=$(find test_results -name "*_coverage.out" 2>/dev/null)
    
    if [ -n "$COVERAGE_FILES" ]; then
        # Merge coverage files
        echo "mode: atomic" > "test_results/$COVERAGE_OUTPUT"
        for file in $COVERAGE_FILES; do
            grep -v "mode: atomic" "$file" >> "test_results/$COVERAGE_OUTPUT" 2>/dev/null || true
        done
        
        # Generate HTML coverage report
        go tool cover -html="test_results/$COVERAGE_OUTPUT" -o "test_results/coverage.html"
        
        # Calculate coverage percentage
        COVERAGE_PERCENT=$(go tool cover -func="test_results/$COVERAGE_OUTPUT" | grep "total:" | awk '{print $3}')
        print_success "Coverage report generated: test_results/coverage.html"
        print_status "Total coverage: $COVERAGE_PERCENT"
        
        # Show coverage by package if verbose
        if [ "$VERBOSE" = true ]; then
            echo ""
            print_status "Coverage by package:"
            go tool cover -func="test_results/$COVERAGE_OUTPUT" | grep -v "total:"
        fi
    else
        print_warning "No coverage files found"
    fi
fi

# Generate test report summary
print_status "Generating test summary..."
{
    echo "MCP Security Scanner Test Report"
    echo "================================"
    echo "Generated: $(date)"
    echo "Go Version: $GO_VERSION"
    echo "Test Timeout: $TEST_TIMEOUT"
    echo ""
    echo "Test Results:"
    echo "  Total Test Suites: $TOTAL_TEST_SUITES"
    echo "  Failed Test Suites: $FAILED_TESTS"
    echo "  Success Rate: $(( (TOTAL_TEST_SUITES - FAILED_TESTS) * 100 / TOTAL_TEST_SUITES ))%"
    echo ""
    
    if [ "$RUN_COVERAGE" = true ] && [ -f "test_results/$COVERAGE_OUTPUT" ]; then
        echo "Coverage Summary:"
        go tool cover -func="test_results/$COVERAGE_OUTPUT" | tail -1
        echo ""
    fi
    
    if [ "$RUN_BENCHMARKS" = true ] && [ -f "test_results/$BENCH_OUTPUT" ]; then
        echo "Benchmark Summary:"
        grep -E "^Benchmark" "test_results/$BENCH_OUTPUT" | head -5
        echo ""
    fi
} > test_results/test_summary.txt

print_status "Test summary saved to: test_results/test_summary.txt"

# Final status
echo ""
if [ $FAILED_TESTS -eq 0 ]; then
    print_success "All test suites passed! 🎉"
    
    # Show quick stats
    if [ "$RUN_COVERAGE" = true ] && [ -f "test_results/$COVERAGE_OUTPUT" ]; then
        COVERAGE_PERCENT=$(go tool cover -func="test_results/$COVERAGE_OUTPUT" | grep "total:" | awk '{print $3}')
        print_status "Final coverage: $COVERAGE_PERCENT"
    fi
    
    exit 0
else
    print_error "$FAILED_TESTS out of $TOTAL_TEST_SUITES test suites failed"
    print_status "Check test_results/ directory for detailed reports"
    exit 1
fi
