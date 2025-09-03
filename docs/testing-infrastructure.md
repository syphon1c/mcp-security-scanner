# Testing Infrastructure

The MCP Security Scanner includes a testing framework designed to ensure code quality, validate functionality, and provide performance metrics across all components.

## Overview

Our testing infrastructure covers five key areas:

1. **Unit Testing** - Isolated testing of core components
2. **Integration Testing** - End-to-end scenario validation 
3. **Mock Infrastructure** - Controlled testing environments
4. **Performance Benchmarking** - Performance and resource usage metrics
5. **Test Automation** - Automated test execution and reporting

## Quick Start

### Running All Tests

```bash
# Run complete test suite with coverage reporting
./test/run_tests.sh

# Expected output:
[INFO] Starting MCP Security Scanner test suite...
[INFO] Using Go version: 1.21.1
[SUCCESS] unit tests passed
[SUCCESS] integration tests passed
[SUCCESS] Coverage report generated: test_results/coverage.html
[SUCCESS] All test suites passed! 🎉
```

### Running Specific Test Types

```bash
# Unit tests only
make test-unit

# Integration tests only  
make test-integration

# Performance benchmarks
make test-benchmarks

# All tests with coverage
make test-coverage
```

## Test Structure

```
/test/
├── unit/                    # Unit tests for core functionality
│   └── scanner_test.go     # Scanner functionality tests
├── integration/             # End-to-end integration tests
│   └── mcp_protocol_test.go # MCP protocol integration tests
├── mocks/                   # Mock servers and test utilities
│   └── mock_mcp_server.go  # HTTP test servers simulating MCP protocol
├── testdata/               # Test data and fixtures
│   ├── vulnerable_samples.go # Known vulnerable code patterns
│   └── test_policies.go    # Pre-defined security policies
├── benchmarks/             # Performance benchmarking
│   └── performance_test.go # Scanner performance benchmarks
├── run_tests.sh           # Main test runner script
└── test_results/          # Generated coverage and reports
    ├── coverage.html      # Interactive HTML coverage report
    ├── test_summary.txt   # Test execution summary
    └── benchmark_results.txt # Performance metrics
```

## Unit Testing

Unit tests validate core scanner functionality with isolated test cases.

### Test Coverage

- **Scanner Initialization**: Configuration loading and setup
- **Vulnerability Detection**: Accuracy of threat identification
- **Policy Engine**: Security rule processing and evaluation
- **False Positive Validation**: Ensuring clean code doesn't trigger alerts

### Running Unit Tests

```bash
# Basic unit test execution
make test-unit

# With verbose output
go test -v ./test/unit/...

# Expected results:
# TestNewScanner ✓
# TestScanLocalMCPServer_WithVulnerabilities ✓
# TestScanLocalMCPServer_SafeSamples ✓
# TestScanLocalMCPServer_VulnerabilityMapping ✓
```

### Test Data

Unit tests use structured test data from `testdata/`:

**Vulnerable Samples** (12 categories):
- SQL Injection patterns
- Command Injection patterns
- Path Traversal patterns
- Script Injection patterns
- Authentication Bypass patterns

**Safe Samples**: Clean code examples that should not trigger alerts

**Test Policies**: Minimal security policies for controlled testing

## Integration Testing

Integration tests validate end-to-end functionality with real MCP server interactions.

### Test Scenarios

- **MCP Protocol Integration**: Full protocol handshake and communication
- **Vulnerability Detection**: End-to-end threat identification
- **Concurrent Scanning**: Multiple simultaneous connections
- **Error Handling**: Graceful failure scenarios

### Mock Server Integration

Integration tests use HTTP test servers that simulate MCP protocol:

```go
// Example integration test
func TestMCPProtocolIntegration(t *testing.T) {
    // Start mock vulnerable server
    server := mocks.NewVulnerableMCPServer()
    defer server.Close()
    
    // Test scanner against server
    scanner, _ := scanner.NewScanner(".")
    result, err := scanner.ScanRemoteMCPServer(server.URL, "test-policy")
    
    // Validate results
    assert.NoError(t, err)
    assert.Greater(t, len(result.Vulnerabilities), 0)
}
```

### Running Integration Tests

```bash
# Basic integration test execution
make test-integration

# With detailed output
go test -v ./test/integration/...

# Expected results:
# TestMCPProtocolIntegration ✓
# TestMCPVulnerabilityDetection ✓
# TestConcurrentMCPScanning ✓
```

## Mock Infrastructure

Mock servers provide controlled testing environments with known characteristics.

### Mock Server Types

**VulnerableMCPServer**: Contains intentional security vulnerabilities
- SQL injection endpoints
- Command injection capabilities
- Path traversal vulnerabilities
- Authentication bypass patterns

**SecureMCPServer**: Hardened server for negative testing
- Proper input validation
- Secure authentication
- No exploitable patterns

**CustomMCPServer**: Configurable server for specific test scenarios

### Mock Server Features

- **Full MCP Protocol Compliance**: `initialize`, `tools/list`, `tools/call`, etc.
- **HTTP and WebSocket Support**: Complete transport layer coverage
- **Configurable Responses**: Customizable vulnerability patterns
- **Real-time Interaction**: Supports dynamic testing scenarios

## Performance Benchmarking

Performance benchmarks measure scanner efficiency and resource usage.

### Benchmark Categories

**Local Scanning Performance**:
- Small projects (< 100 files)
- Medium projects (100-1000 files) 
- Large projects (1000+ files)

**Remote Scanning Performance**:
- Single remote server scanning
- Concurrent remote scanning
- Protocol communication overhead

**Pattern Matching Performance**:
- Security rule pattern matching
- Policy engine evaluation
- Vulnerability classification

### Running Benchmarks

```bash
# Execute performance benchmarks
make test-benchmarks

# View results
cat test_results/benchmark_results.txt

# Example output:
BenchmarkLocalScanSmallProject-8    100  12345678 ns/op  1234 B/op  56 allocs/op
BenchmarkRemoteMCPScan-8            50   23456789 ns/op  2345 B/op  67 allocs/op
BenchmarkConcurrentScans-8          20   34567890 ns/op  3456 B/op  78 allocs/op
```

### Performance Metrics

Benchmarks track:
- **Execution Time**: Nanoseconds per operation
- **Memory Allocation**: Bytes allocated per operation
- **Allocation Count**: Number of allocations per operation
- **Throughput**: Operations per second for load testing

## Test Automation

### Test Runner

The `run_tests.sh` script provides automated test execution:

```bash
#!/bin/bash
# Features:
# - Automated dependency management
# - Test timeout handling
# - Coverage report generation
# - Colored output formatting
# - Test result archiving
# - Performance benchmark execution
```

### Test Runner Options

```bash
# Standard execution
./test/run_tests.sh

# Unit tests only
./test/run_tests.sh --unit-only

# Integration tests only
./test/run_tests.sh --integration-only

# With benchmarks
./test/run_tests.sh --with-benchmarks

# Verbose output
./test/run_tests.sh --verbose

# Custom timeout
./test/run_tests.sh --timeout 60s
```

### Generated Reports

Test execution generates multiple reports in `test_results/`:

**Coverage Reports**:
- `coverage.html` - Interactive HTML coverage report
- `coverage.out` - Raw coverage data for tooling
- `unit_coverage.out` - Unit test specific coverage
- `integration_coverage.out` - Integration test specific coverage

**Test Results**:
- `test_summary.txt` - Detailed test execution summary
- `benchmark_results.txt` - Performance benchmark results

**Report Format Example**:
```
MCP Security Scanner Test Report
================================
Generated: Tue  2 Sep 2025 11:22:02 AEST
Go Version: 1.21.1
Test Timeout: 30s

Test Results:
  Total Test Suites: 2
  Failed Test Suites: 0
  Success Rate: 100%

Coverage Summary:
  Lines Covered: 0.0%
  Branches Covered: 0.0%
  Functions Covered: 0.0%
```

## Continuous Integration

### Makefile Integration

All test commands are integrated into the project Makefile:

```bash
# Basic test commands
make test              # Run unit and integration tests
make test-unit         # Unit tests only
make test-integration  # Integration tests only
make test-benchmarks   # Performance benchmarks
make test-coverage     # Tests with coverage reporting

# Advanced test commands
make test-runner       # Use custom test runner script
make test-all          # All test suites including benchmarks
make test-verbose      # Tests with detailed output
```

### CI/CD Pipeline Integration

Example GitHub Actions configuration:

```yaml
name: Test Suite
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v3
        with:
          go-version: '1.21'
          
      - name: Run Tests
        run: make test-all
        
      - name: Upload Coverage
        uses: actions/upload-artifact@v3
        with:
          name: coverage-report
          path: test_results/coverage.html
          
      - name: Upload Benchmarks
        uses: actions/upload-artifact@v3
        with:
          name: benchmark-results
          path: test_results/benchmark_results.txt
```

## Best Practices

### Writing Unit Tests

1. **Isolation**: Tests should not depend on external systems
2. **Deterministic**: Tests should produce consistent results
3. **Fast**: Unit tests should execute quickly (< 1 second each)
4. **Clear**: Test names should describe the scenario being tested

```go
func TestScanLocalMCPServer_WithSQLInjection_DetectsVulnerability(t *testing.T) {
    // Arrange
    scanner, err := scanner.NewScanner("../testdata")
    require.NoError(t, err)
    
    tmpDir := createTestFiles(t, map[string]string{
        "vulnerable.go": testdata.VulnerableSamples["sql_injection"],
    })
    defer os.RemoveAll(tmpDir)
    
    // Act
    result, err := scanner.ScanLocalMCPServer(tmpDir, "test-policy")
    
    // Assert
    assert.NoError(t, err)
    assert.Greater(t, result.RiskScore, 0)
    assert.Contains(t, result.Vulnerabilities[0].Category, "SQL_INJECTION")
}
```

### Writing Integration Tests

1. **Realistic**: Use real protocol interactions
2. **Comprehensive**: Cover happy path and error scenarios  
3. **Independent**: Tests should not affect each other
4. **Cleanup**: Always clean up resources

```go
func TestMCPProtocolIntegration_VulnerableServer_DetectsThreats(t *testing.T) {
    // Arrange
    server := mocks.NewVulnerableMCPServer()
    defer server.Close()
    
    scanner, err := scanner.NewScanner(".")
    require.NoError(t, err)
    
    // Act
    result, err := scanner.ScanRemoteMCPServer(server.URL, "test-policy")
    
    // Assert
    assert.NoError(t, err)
    assert.Greater(t, len(result.Vulnerabilities), 0)
    assert.Equal(t, "High", result.RiskLevel)
}
```

### Performance Testing Guidelines

1. **Baseline**: Establish performance baselines
2. **Realistic Data**: Use representative test data sizes
3. **Multiple Iterations**: Run benchmarks multiple times
4. **Resource Monitoring**: Track memory and CPU usage

```go
func BenchmarkLocalScanMediumProject(b *testing.B) {
    // Create test project with 500 files
    tmpDir := createMediumTestProject(b)
    defer os.RemoveAll(tmpDir)
    
    scanner, _ := scanner.NewScanner(".")
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := scanner.ScanLocalMCPServer(tmpDir, "test-policy")
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

## Troubleshooting

### Common Test Issues

**Tests Timing Out**:
```bash
# Increase timeout
make test-unit TIMEOUT=60s

# Check for infinite loops or blocking operations
go test -v -timeout 10s ./test/unit/...
```

**Coverage Not Generated**:
```bash
# Ensure test_results directory exists
mkdir -p test_results

# Run coverage manually
go test -coverprofile=test_results/coverage.out ./...
go tool cover -html=test_results/coverage.out -o test_results/coverage.html
```

**Mock Server Issues**:
```bash
# Check if ports are available
lsof -i :8080

# Verify mock server starts correctly
go test -v ./test/mocks/...
```

**Benchmark Inconsistencies**:
```bash
# Run benchmarks multiple times
go test -bench=. -count=5 ./test/benchmarks/...

# Check system load during benchmarks
top

# Use consistent hardware for CI/CD
```

### Debug Mode

Enable debug output for troubleshooting:

```bash
# Enable verbose test output
export TEST_VERBOSE=1

# Enable debug logging
export LOG_LEVEL=DEBUG

# Run tests with trace
go test -trace=trace.out ./test/...
```

## Contributing to Tests

### Adding New Tests

1. **Identify the test type** needed (unit/integration/benchmark)
2. **Follow naming conventions**: `Test*` for tests, `Benchmark*` for benchmarks
3. **Add test data** to `testdata/` if needed
4. **Update documentation** to reflect new test scenarios
5. **Ensure tests pass** in CI/CD pipeline

### Test Data Management

**Adding Vulnerable Samples**:
```go
// In testdata/vulnerable_samples.go
VulnerableSamples["new_vulnerability"] = `
    // Vulnerable code pattern
    db.Exec("SELECT * FROM users WHERE id = " + userInput)
`
```

**Adding Test Policies**:
```go
// In testdata/test_policies.go
TestPolicies["new-test-policy"] = SecurityPolicy{
    PolicyName: "new-test-policy",
    Rules: []SecurityRule{
        {
            ID: "TEST_001",
            Name: "Test Rule",
            Patterns: []string{"vulnerable_pattern"},
            Severity: "High",
        },
    },
}
```

### Mock Server Extensions

**Adding New Mock Endpoints**:
```go
// In mocks/mock_mcp_server.go
func (s *MockMCPServer) handleNewEndpoint(w http.ResponseWriter, r *http.Request) {
    // Handle new test scenario
    response := map[string]interface{}{
        "test": "response",
    }
    json.NewEncoder(w).Encode(response)
}
```

This testing infrastructure ensures the MCP Security Scanner maintains high quality, reliability, and performance across all components and use cases.
