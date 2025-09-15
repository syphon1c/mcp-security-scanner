# User Manual

This  guide covers all aspects of using the MCP Security Scanner, from basic operations to advanced security assessment workflows.

## Getting Started

### Quick Start

After installation, verify the scanner is working:

```bash
# Check version
./build/mcpscan version

# List available security policies
./build/mcpscan policies

# Run a basic scan on the current directory
./build/mcpscan scan-local . standard-security
```

### Command Overview

The scanner provides several main commands:

- `scan-local` - Scan local files and directories
- `scan-remote` - Scan remote MCP servers
- `proxy` - Run real-time proxy with security monitoring
- `policies` - List available security policies
- `integrations` - Test enterprise integrations
- `version` - Show version information

## Local Scanning

### Basic Local Scan

```bash
# Scan current directory with standard security policy (JSON output)
./build/mcpscan scan-local . standard-security

# Scan specific directory with critical security policy (JSON output)
./build/mcpscan scan-local /path/to/project critical-security

# Scan with custom policy (create from template first)
./build/mcpscan scan-local /path/to/project your-custom-policy
```

### Advanced Local Scanning

```bash
# Generate HTML report with polymorphic detection
./build/mcpscan scan-local /path/to/project advanced-polymorphic-security --output-format html

# Use weighted pattern variants for higher accuracy
./build/mcpscan scan-local . mcp-advanced-security --verbose

# Performance-optimized scanning with caching
./build/mcpscan scan-local large-project/ standard-security --timeout 300s

# Generate multiple report formats simultaneously  
./build/mcpscan scan-local . critical-security --all-formats

# Custom output directory for reports
./build/mcpscan scan-local . standard-security --output-dir ./security-reports

# Confidence scoring with weighted patterns
./build/mcpscan scan-local . advanced-polymorphic-security --verbose
./build/mcpscan scan-local /path/to/project critical-security --output-format html

# Generate PDF report (requires wkhtmltopdf)
# Generate PDF report (pure Go implementation - no dependencies)
./mcpscan scan-local . critical-security --output-format pdf

# Generate text report
./build/mcpscan scan-local /path/to/project critical-security --output-format text

# Generate all available formats
./build/mcpscan scan-local /path/to/project critical-security --all-formats

# Advanced MCP security analysis (recommended for  assessment)
./build/mcpscan scan-local /path/to/project mcp-advanced-security --output-format html

# Enterprise-grade security assessment with all formats
./build/mcpscan scan-local /path/to/project mcp-advanced-security --all-formats --output-dir ./reports

# Specify custom output file
./build/mcpscan scan-local /path/to/project critical-security --output-file security-report.html

# Specify custom output directory for reports (overrides default ./reports/)
./build/mcpscan scan-local /path/to/project critical-security --output-dir ./security-reports

# Verbose output with detailed information
./build/mcpscan scan-local /path/to/project critical-security --verbose

# Generate HTML report with verbose console output
./build/mcpscan scan-local /path/to/project critical-security --output-format html --verbose

# Generate all formats in custom directory
./build/mcpscan scan-local /path/to/project critical-security --all-formats --output-dir /var/reports
```

## Report Formats

The MCP Security Scanner supports multiple output formats to suit different needs and use cases.

### Available Formats

#### JSON Format (Default)
- **Use Case**: Programmatic processing, CI/CD integration, API consumption
- **Features**: Complete structured data, machine-readable
- **Example**: `./build/mcpscan scan-local . critical-security`

#### HTML Format
- **Use Case**: Human-readable reports, executive summaries, web viewing
- **Features**: Professional styling, interactive elements, print-friendly
- **Example**: `./build/mcpscan scan-local . critical-security --output-format html`

#### PDF Format
- **Use Case**: Executive reports, compliance documentation, archival
- **Features**: Professional formatting, consistent layout, portable
- **Requirements**: Pure Go implementation, no external dependencies needed
- **Example**: `./build/mcpscan scan-local . critical-security --output-format pdf`

#### Text Format
- **Use Case**: Command-line viewing, email reports, legacy systems
- **Features**: Plain text, terminal-friendly, minimal formatting
- **Example**: `./build/mcpscan scan-local . critical-security --output-format text`

### Output Options

#### Default Behavior
By default, all reports are saved to the `./reports/` directory with timestamped filenames unless you specify a custom output file or directory.

```bash
# These commands save reports to ./reports/ automatically
./build/mcpscan scan-local . critical-security                    # → ./reports/mcp_security_report_YYYYMMDD_HHMMSS.json
./build/mcpscan scan-local . critical-security --output-format html # → ./reports/mcp_security_report_YYYYMMDD_HHMMSS.html
./build/mcpscan scan-local . critical-security --all-formats      # → ./reports/mcp_security_report_YYYYMMDD_HHMMSS.*
```

#### Single Format Output
```bash
# Generate specific format to default ./reports/ directory
./build/mcpscan scan-local . critical-security --output-format html
./build/mcpscan scan-local . critical-security --output-format pdf

# Generate to specific file (overrides default directory)
./build/mcpscan scan-local . critical-security --output-file report.html
./build/mcpscan scan-local . critical-security --output-file executive-summary.pdf

# Generate to custom directory
./build/mcpscan scan-local . critical-security --output-format html --output-dir ./custom-reports
```

#### Multiple Format Output
```bash
# Generate all available formats to default ./reports/ directory
./build/mcpscan scan-local . critical-security --all-formats

# Generate all formats to custom directory
./build/mcpscan scan-local . critical-security --all-formats --output-dir ./custom-reports

# Generate multiple specific formats to custom directory
./build/mcpscan scan-local . critical-security --output-format html --output-dir ./reports
./build/mcpscan scan-local . critical-security --output-format pdf --output-dir ./reports
```

### Report Features

#### HTML Reports
- **Professional Styling**: Clean, modern design with colour-coded severity levels
- **Interactive Elements**: Collapsible sections, hover effects, responsive design
- **Security Information**: Complete MCP server details, discovered tools and resources
- **Risk Visualization**: Progress bars, severity badges, summary cards
- **Print Optimization**: CSS print styles for clean PDF printing from browser

#### PDF Reports
- **Professional Layout**: A4 page format with proper margins
- **Consistent Formatting**: Guaranteed layout across different systems
- **Complete Content**: All scan information including findings and remediation
- **Archival Quality**: Suitable for compliance and documentation requirements

#### Text Reports
- **Terminal Friendly**: Optimized for command-line viewing
- **Email Compatible**: Plain text format suitable for email reports
- **Structured Layout**: Clear sections with consistent formatting
- **Minimal Dependencies**: No external dependencies required

### Installation Requirements

#### PDF Generation Setup

PDF reports are generated using a pure Go implementation with **no external dependencies required**.

**All Platforms:**
```bash
# No additional setup needed - PDF generation works out of the box
./mcpscan scan-local . critical-security --output-format pdf

# Test PDF generation
./mcpscan scan-local . critical-security --output-format pdf
ls -la reports/*.pdf
```

**Benefits:**
- ✅ **Zero Configuration**: Works immediately after building the scanner
- ✅ **Cross-Platform**: Consistent behavior on macOS, Linux, and Windows
- ✅ **No Dependencies**: No external tools to install or maintain
- ✅ **Professional Output**: Color-coded severity levels and proper formatting

The scanner uses `github.com/jung-kurt/gofpdf` for native PDF generation.

#### Checking Dependencies
```bash
# Check if PDF generation is available
./build/mcpscan scan-local . critical-security --output-format pdf
# If wkhtmltopdf is missing, you'll see a helpful error message
```

## Remote Scanning

### Basic Remote Scan

```bash
# Scan remote MCP server (JSON output)
./build/mcpscan scan-remote https://mcp-server.example.com standard-security

# Scan with authentication (JSON output)
./build/mcpscan scan-remote https://mcp-server.example.com critical-security --auth-token "your-token"

# Scan WebSocket endpoint (JSON output)
./build/mcpscan scan-remote wss://mcp-server.example.com/ws standard-security
```

### Remote Scan with Reporting

```bash
# Generate HTML report for remote scan
./build/mcpscan scan-remote https://mcp-server.example.com critical-security --output-format html

# Generate PDF report for remote scan
./build/mcpscan scan-remote https://mcp-server.example.com critical-security --output-format pdf

# Generate all report formats for remote scan
./build/mcpscan scan-remote https://mcp-server.example.com critical-security --all-formats --output-dir ./remote-reports

# Custom output file for remote scan
./build/mcpscan scan-remote https://mcp-server.example.com critical-security --output-file remote-security-assessment.html

# Verbose remote scan with HTML report
./build/mcpscan scan-remote https://mcp-server.example.com critical-security --output-format html --verbose
```

### Remote Scan Configuration

```bash
# Custom timeout for slow servers
./build/mcpscan scan-remote https://mcp-server.example.com standard-security --timeout 120s

# Limit number of test payloads
./build/mcpscan scan-remote https://mcp-server.example.com standard-security --max-payloads 50

# Skip certificate verification (testing only)
./build/mcpscan scan-remote https://mcp-server.example.com standard-security --insecure

# Custom User-Agent header
./build/mcpscan scan-remote https://mcp-server.example.com standard-security --user-agent "MyApp/1.0"
```

## Live Monitoring Proxy

The Live Monitoring Proxy provides real-time security analysis of MCP traffic by acting as a transparent intermediary between MCP clients and servers.

### Basic Proxy Usage

```bash
# Start proxy forwarding to target server on port 9080
./build/mcpscan proxy http://target-mcp-server.com 9080

# Start proxy with specific security policy
./build/mcpscan proxy http://localhost:8000 9080 critical-security

# Start proxy for HTTPS target with advanced detection
./build/mcpscan proxy https://api.mcp-service.com 8443 mcp-advanced-security

# Start proxy with polymorphic pattern detection
./build/mcpscan proxy http://mcp-server.internal 9080 advanced-polymorphic-security
```

### Proxy Architecture

```
[MCP Client] → [MCP Security Proxy:9080] → [MCP Server:8000]
                       ↓
              [Security Analysis]
                       ↓
           [Alerts/Logs/Monitoring]
```

The proxy:
1. **Intercepts** all HTTP/WebSocket traffic between client and server (✅ WebSocket fully tested)
2. **Analyses** requests and responses for security threats
3. **Blocks** malicious patterns based on security policies
4. **Logs** all security events with detailed forensic information
5. **Forwards** legitimate traffic transparently to the target server

### Proxy Monitoring Endpoints

Once the proxy is running, monitor its status and security events:

```bash
# Proxy health and performance metrics
curl http://localhost:9080/monitor/health
{
  "status": "healthy",
  "target": "http://target-server.com",
  "timestamp": "2025-09-01T10:30:00Z",
  "alerts_queue_size": 0,
  "logs_queue_size": 15,
  "uptime": "2h30m45s"
}

# Security alerts and incidents
curl http://localhost:9080/monitor/alerts
{
  "status": "ok",
  "message": "Alert endpoint active", 
  "alerts": [
    {
      "timestamp": "2025-09-01T10:25:00Z",
      "severity": "High",
      "type": "SQL Injection Detected",
      "source": "192.168.1.100",
      "evidence": "'; DROP TABLE users; --"
    }
  ]
}

# Traffic logs and analysis
curl http://localhost:9080/monitor/logs
{
  "status": "ok",
  "message": "Logs endpoint active",
  "logs": [
    {
      "timestamp": "2025-09-01T10:30:00Z",
      "method": "tools/call",
      "source": "192.168.1.100",
      "blocked": false,
      "analysis_time": "2.5ms"
    }
  ]
}
```

### Testing the Proxy

We provide  testing tools to verify proxy functionality:

#### Mock MCP Server Setup

```bash
# Start the vulnerable mock server (included in project)
python3 test/mocks/mock-mcp-server.py

# Server provides:
# - Standard MCP endpoints at http://localhost:8000
# - Intentionally vulnerable patterns for testing  
# - WebSocket support at ws://localhost:8000/ws
# - Health check at http://localhost:8000/health
# - Debug endpoint at http://localhost:8000/debug/info
```

#### Automated Proxy Testing

```bash
# Run comprehensive functionality tests
python3 test/integration/test-proxy-comprehensive.py

# Expected output:
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

📊 Results: 8 PASS, 0 WARN, 1 FAIL (9 total)

# Run final demonstration
python3 test/integration/proxy-final-demo.py

# Expected output:
🚀 MCP Live Monitoring Proxy - Final Verification
============================================================
✅ Proxy Health: healthy
✅ Request/Response Proxying: Working
✅ Security Threat Detection: Active
✅ Performance Under Load: 100.0% (20/20 successful)
✅ Monitoring Endpoints: All Active
```

#### Manual Security Testing

Test specific attack vectors manually:

```bash
# Test SQL injection detection
curl -X POST http://localhost:9080/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "id": "sql_test",
    "jsonrpc": "2.0", 
    "method": "tools/call",
    "params": {
      "name": "search",
      "arguments": {"query": "test\"; DROP TABLE users; --"}
    }
  }'

# Test path traversal detection
curl -X POST http://localhost:9080/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "id": "path_test",
    "jsonrpc": "2.0",
    "method": "tools/call", 
    "params": {
      "name": "read_file",
      "arguments": {"path": "../../../../etc/passwd"}
    }
  }'

# Test command injection detection
curl -X POST http://localhost:9080/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "id": "cmd_test",
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "run_command", 
      "arguments": {"cmd": "ls; rm -rf /tmp/*"}
    }
  }'

# Check if security alerts were generated
curl http://localhost:9080/monitor/alerts | jq .

# View detailed security logs
tail -f proxy.log
```

### Security Event Examples

When threats are detected, the proxy logs detailed security events:

```bash
2025/09/01 14:57:01 SECURITY ALERT [High]: Suspicious Tool Call - Potential injection attempt in tool parameter: query (Source: [::1]:54452)
2025/09/01 14:57:01 Alert details: {
  "timestamp": "2025-09-01T14:57:01.826058+10:00",
  "severity": "High",
  "alertType": "Suspicious Tool Call", 
  "description": "Potential injection attempt in tool parameter: query",
  "source": "[::1]:54452",
  "evidence": "test\"; DROP TABLE users; --",
  "action": "Monitor"
}

2025/09/01 14:57:01 SECURITY ALERT [High]: Blocked Pattern Detected - Blocks destructive SQL commands (Source: [::1]:54452)
2025/09/01 14:57:01 Alert details: {
  "timestamp": "2025-09-01T14:57:01.82608+10:00",
  "severity": "High",
  "alertType": "Blocked Pattern Detected",
  "description": "Blocks destructive SQL commands", 
  "source": "[::1]:54452",
  "evidence": "Pattern: DROP TABLE, Category: SQL Commands",
  "action": "Block"
}
```

### Proxy Deployment Scenarios

#### Development Environment
```bash
# Basic proxy for development testing
./build/mcpscan proxy http://localhost:8000 9080 standard-security

# Update client configuration to use proxy
export MCP_SERVER_URL=http://localhost:9080

# Test application through proxy
your-mcp-client --server $MCP_SERVER_URL
```

#### Staging Environment
```bash
# Monitoring for staging 
./build/mcpscan proxy https://staging-mcp.company.com 9080 mcp-advanced-security

# Monitor proxy health
watch -n 30 "curl -s http://localhost:9080/monitor/health | jq ."

# Tail security events
tail -f proxy.log | grep "SECURITY ALERT"
```

#### Production Environment  
```bash
# High-security proxy deployment
./build/mcpscan proxy https://prod-mcp.company.com 9080 advanced-polymorphic-security

# Background deployment with logging
nohup ./build/mcpscan proxy https://prod-mcp.company.com 9080 advanced-polymorphic-security > proxy.log 2>&1 &

# Monitor performance and security
curl http://localhost:9080/monitor/health
curl http://localhost:9080/monitor/alerts

# Integrate with monitoring systems
curl http://localhost:9080/monitor/alerts | \
  jq '.alerts[]' | \
  curl -X POST https://siem.company.com/api/events -d @-
```

### Proxy Performance Metrics

The proxy provides detailed performance monitoring:

- **Latency**: ~1-5ms additional latency per request
- **Throughput**: 500+ requests/second sustained (tested with 50 concurrent requests)
- **Memory Usage**: ~50MB base, +10MB per 1000 concurrent connections
- **CPU Impact**: Low for standard patterns, moderate for advanced analysis
- **Success Rate**: 100% under normal load conditions

### Proxy Configuration

Advanced proxy configuration via environment variables:

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG

# Customize security thresholds
export PROXY_BLOCK_THRESHOLD=Medium
export PROXY_ALERT_THRESHOLD=Low

# Configure external integrations
export SIEM_ENDPOINT=https://siem.company.com/api/events
export SLACK_WEBHOOK=https://hooks.slack.com/services/...

# Start proxy with environment configuration
./build/mcpscan proxy http://target-server.com 9080 mcp-advanced-security
```

### Troubleshooting Proxy Issues

#### Proxy Won't Start
```bash
# Check if port is already in use
lsof -i :9080

# Verify target server is accessible
curl -v http://target-server.com

# Check proxy logs for errors
tail -n 50 proxy.log
```

#### No Security Alerts Generated
```bash
# Verify security policies are loaded
./build/mcpscan policies

# Test with known malicious payload
curl -X POST http://localhost:9080/mcp/tools/call \
  -d '{"params": {"sql": "DROP TABLE users;"}}'

# Check if pattern is in security policy
grep -i "drop table" policies/critical-security.json
```

#### Performance Issues
```bash
# Check proxy health metrics
curl http://localhost:9080/monitor/health | jq .

# Monitor system resources
top -p $(pgrep mcpscan)

# Check queue sizes
curl http://localhost:9080/monitor/health | jq '.alerts_queue_size, .logs_queue_size'
```

#### Connection Issues
```bash
# Test direct connection to target
curl -v http://target-server.com/health

# Test proxy endpoint
curl -v http://localhost:9080/health

# Check proxy routing
curl -v http://localhost:9080/monitor/health
```

### Remote Scan Process

1. **Connection**: Establish connection to MCP server
2. **Initialisation**: Send MCP `initialize` message
3. **Discovery**: Enumerate tools and resources using `tools/list` and `resources/list`
4. **Static Analysis**: Analyse server responses for security patterns
5. **Dynamic Testing**: Inject test payloads into discovered endpoints
6. **Assessment**: Calculate risk score and generate report

### Remote Scan Example Output

```json
{
  "scan_id": "scan_20240315_143530",
  "target": "https://mcp-server.example.com",
  "policy": "critical-security",
  "timestamp": "2024-03-15T14:35:30Z",
  "duration": "12.567s",
  "server_info": {
    "protocol_version": "2024-11-05",
    "implementation": "example-mcp-server",
    "capabilities": {
      "tools": true,
      "resources": true,
      "prompts": false
    }
  },
  "discovered_endpoints": {
    "tools": [
      {
        "name": "execute_command",
        "description": "Execute system commands",
        "schema": {
          "type": "object",
          "properties": {
            "command": {"type": "string"}
          }
        }
      }
    ],
    "resources": [
      {
        "uri": "file:///etc/config",
        "name": "System Configuration",
        "description": "System configuration files"
      }
    ]
  },
  "findings": [
    {
      "rule_id": "INJECTION_DYNAMIC",
      "severity": "Critical",
      "description": "Command injection vulnerability in execute_command tool",
      "endpoint": "execute_command",
      "test_payload": "$(id)",
      "response_evidence": "uid=0(root) gid=0(root) groups=0(root)",
      "risk_factors": ["command_execution", "root_access", "external_input"]
    }
  ],
  "risk_level": {
    "level": "Critical",
    "score": 85
  }
}
```

## Proxy Mode

### Starting the Proxy

```bash
# Basic proxy setup
./build/mcpscan proxy https://target-server.com 8080

# Basic proxy usage
./build/mcpscan proxy https://target-server.com 8080

# Proxy uses security policies from the configuration file
# Edit configs/config.yaml to specify security policies
```

### Proxy Configuration

```yaml
# config.yaml - Proxy settings
proxy:
  bind_address: "0.0.0.0:8080"
  target_timeout: 10s
  monitoring_enabled: true
  block_suspicious: true
  log_all_traffic: false
  
  # Alert thresholds
  alert_thresholds:
    critical: "block"
    high: "alert"
    medium: "log"
    low: "ignore"

  # Rate limiting
  rate_limit:
    requests_per_minute: 1000
    burst_size: 100
```

### Using the Proxy

Once the proxy is running, configure your MCP client to use it:

```bash
# Configure client to use proxy
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080

# Or use proxy directly
curl -x http://localhost:8080 https://target-server.com/mcp/endpoint
```

### Proxy Monitoring

The proxy provides several monitoring endpoints:

```bash
# Health check
curl http://localhost:8080/monitor/health

# Active alerts
curl http://localhost:8080/monitor/alerts

# Traffic statistics
curl http://localhost:8080/monitor/stats

# Configuration status
curl http://localhost:8080/monitor/config
```

### Real-time Alerts

Example alert from proxy mode:

```json
{
  "alert_id": "alert_20240315_144122_001",
  "timestamp": "2024-03-15T14:41:22Z",
  "severity": "Critical",
  "rule_id": "INJECTION_001",
  "description": "Command injection attempt detected",
  "source_ip": "192.168.1.100",
  "target_url": "https://target-server.com/mcp/tools/call",
  "method": "POST",
  "payload": {
    "method": "execute_command",
    "params": {
      "command": "rm -rf /"
    }
  },
  "action_taken": "blocked",
  "risk_score": 95
}
```

## Security Policies

### Policy Management

```bash
# List all available policies
./build/mcpscan policies

# Check policy syntax manually with jq
jq '.' policies/critical-security.json

# Test policy by running a scan
./build/mcpscan scan-local . critical-security
```

### Built-in Policies

#### Critical Security Policy
- **Focus**: Critical vulnerabilities only
- **Severity**: Primarily Critical and High findings
- **Use Case**: Production security assessments
- **Rules**: 45+ critical security patterns

```bash
./build/mcpscan scan-local . critical-security
```

#### Standard Security Policy
- **Focus**: Security coverage
- **Severity**: All severity levels
- **Use Case**: Development and staging assessments
- **Rules**: 100+ security patterns

```bash
./build/mcpscan scan-local . standard-security
```

#### MCP Advanced Security Policy (Recommended)
- **Focus**: Advanced MCP-specific threats and sophisticated attacks
- **Severity**: All levels with emphasis on advanced threats
- **Use Case**: Enterprise security assessment
- **Rules**: 159+ advanced detection patterns including:
  - **Polymorphic attack detection** with multi-variant pattern matching
  - **MCP protocol abuse** (tool poisoning, resource manipulation, context hijacking)
  - **Behavioral analysis** (network anomalies, persistence mechanisms, crypto mining)
  - **Supply chain security** (typosquatting, dependency tampering, dynamic imports)
  - **Zero-day pattern recognition** (memory corruption, VM escape, prototype pollution)
  - **Obfuscation detection** (encoding schemes, string manipulation, code obfuscation)

```bash
./build/mcpscan scan-local . mcp-advanced-security
```

#### Advanced Polymorphic Security Policy (NEW)
- **Focus**: Policy-driven polymorphic and behavioral pattern detection
- **Severity**: Configurable per pattern type
- **Use Case**: Advanced threat hunting with customisable detection rules
- **Rules**: Policy-defined polymorphic patterns with configurable thresholds

**Key Features:**
- **Polymorphic Pattern Detection**: Multi-variant attack patterns that adapt to evasion techniques
  - Command injection variants (14 detection patterns)
  - SQL injection variants (13 detection patterns) 
  - XSS variants (13 detection patterns)
- **Behavioral Analysis Patterns**: Threshold-based anomaly detection
  - Excessive network activity (7 patterns, threshold: 5)
  - Suspicious file operations (7 patterns, threshold: 3)
  - Crypto mining behavior (7 patterns, threshold: 3)
  - Persistence mechanisms (8 patterns, threshold: 2)
- **Configurable Thresholds**: Each pattern defines minimum matches required for detection
- **Custom Severity Levels**: Policy-defined severity per pattern category

```bash
# Use the advanced polymorphic policy
./build/mcpscan scan-local . advanced-polymorphic-security

# Example output shows polymorphic detection:
# [Critical] Polymorphic Attack Pattern: command_injection_variants
# Description: Polymorphic command injection patterns (Score: 5/14)
# Evidence: exec("ls -la", eval(cmd + '("whoami")', chr(101) + chr(120)...
```

#### Organisation Internal Policy
- **Focus**: Organisation-specific patterns
- **Severity**: Custom severity levels
- **Use Case**: Internal compliance and standards
- **Rules**: Customisable rule set

```bash
# First create your custom policy from the template
cp policies/org-custom-template.json policies/your-org-security.json
# Edit your-org-security.json with your patterns
./build/mcpscan scan-local . your-org-security
```

### Custom Policy Creation

Create a custom policy file:

```json
{
  "policy_name": "my-custom-policy",
  "version": "1.0",
  "description": "Custom security policy for my organisation",
  "rules": [
    {
      "id": "CUSTOM_001",
      "name": "Forbidden Function Usage",
      "description": "Detects usage of forbidden functions",
      "patterns": [
        "forbiddenFunction\\s*\\(",
        "dangerousAPI\\s*\\("
      ],
      "severity": "High",
      "category": "Security"
    },
    {
      "id": "CUSTOM_002", 
      "name": "Insecure Configuration",
      "description": "Detects insecure configuration patterns",
      "patterns": [
        "debug\\s*=\\s*true",
        "ssl_verify\\s*=\\s*false"
      ],
      "severity": "Medium",
      "category": "Configuration"
    }
  ],
  "blocked_patterns": [
    "rm -rf",
    "DROP DATABASE",
    "eval\\s*\\("
  ],
  "risk_thresholds": {
    "critical": 50,
    "high": 30,
    "medium": 15,
    "low": 5
  },
  "exclusions": {
    "files": ["test/*", "vendor/*"],
    "patterns": ["// SECURITY: approved"]
  }
}
```

Save as `configs/my-custom-policy.json` and use:

```bash
./build/mcpscan scan-local . my-custom-policy
```

### Advanced Polymorphic Pattern Policies

Starting from version 1.1.0, the scanner supports advanced polymorphic and behavioral pattern detection through policy configuration. This allows for sophisticated threat detection with customisable thresholds and variants.

#### Creating Polymorphic Pattern Policies

```json
{
  "version": "1.0.0",
  "policyName": "custom-polymorphic-policy",
  "description": "Custom polymorphic pattern detection policy",
  "polymorphicPatterns": [
    {
      "name": "custom_command_injection",
      "description": "Custom command injection variants",
      "severity": "Critical",
      "category": "Advanced Injection",
      "threshold": 2,
      "variants": [
        "exec\\s*\\(\\s*[\"'].*[\"']",
        "system\\s*\\(\\s*[\"'].*[\"']",
        "eval\\s*\\(\\s*[\"'].*exec.*[\"']",
        "__import__\\s*\\(\\s*[\"']os[\"']",
        "eval\\s*\\(\\s*base64\\.b64decode"
      ]
    }
  ],
  "behavioralPatterns": [
    {
      "name": "suspicious_crypto_activity",
      "description": "Detects potential cryptocurrency mining",
      "severity": "Medium",
      "category": "Resource Abuse",
      "threshold": 3,
      "patterns": [
        "hashlib\\.(sha256|md5|blake2b)",
        "multiprocessing\\.Pool\\(",
        "threading\\.Thread\\(.*target=.*mine",
        "gpu.*cuda"
      ]
    }
  ],
  "riskThresholds": {
    "critical": 50,
    "high": 30,
    "medium": 15,
    "low": 5
  }
}
```

#### Polymorphic Pattern Structure

**PolymorphicPattern Fields:**
- `name`: Unique identifier for the pattern group
- `description`: Human-readable description
- `severity`: Severity level (Critical, High, Medium, Low)
- `category`: Classification category
- `threshold`: Minimum number of variants that must match to trigger detection
- `variants`: Array of regex patterns representing different attack variants

**BehavioralPattern Fields:**
- `name`: Unique identifier for the behavioral pattern
- `description`: Human-readable description  
- `severity`: Severity level
- `category`: Classification category
- `threshold`: Minimum number of pattern matches required
- `patterns`: Array of regex patterns to match

#### Example Advanced Detection

When scanning with a polymorphic policy, the scanner will:

1. **Evaluate each variant** in a polymorphic pattern
2. **Count matches** across all variants
3. **Compare against threshold** (e.g., 2 out of 5 variants must match)
4. **Generate finding** if threshold is met with aggregated evidence

**Example Output:**
```
[Critical] Polymorphic Attack Pattern: custom_command_injection
Description: Custom command injection variants (Score: 3/5)
Evidence: exec("malicious_cmd"), eval(base64.b64decode(...)), __import__("os")
Location: suspicious_file.py
```

#### Testing Polymorphic Policies

```bash
# Test polymorphic policy against sample files
./build/mcpscan scan-local ./test-samples custom-polymorphic-policy

# Validate polymorphic policy syntax
./build/mcpscan validate-policy policies/custom-polymorphic-policy.json

# View polymorphic policy details
./build/mcpscan policies --details custom-polymorphic-policy
```

## Configuration Management

### Configuration File

Create `configs/config.yaml`:

```yaml
# Scanner configuration
scanner:
  timeout: 30s
  max_payloads: 100
  verbose: false
  concurrent_jobs: 4

# Proxy configuration  
proxy:
  bind_address: "0.0.0.0:8080"
  target_timeout: 10s
  monitoring_enabled: true
  block_suspicious: true

# Policy configuration
policies:
  directory: "./configs"
  default_policy: "standard-security"
  auto_reload: true

# Integration configuration
integration:
  siem:
    enabled: true
    endpoint: "https://siem.example.com/api/alerts"
    api_key: "your-api-key"
    format: "json"
  
  soar:
    enabled: false
    endpoint: "https://soar.example.com/api/incidents"
    api_key: "your-api-key"
  
  slack:
    enabled: true
    webhook: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    channel: "#security-alerts"
    severity_filter: ["Critical", "High"]

# Logging configuration
logging:
  level: "INFO"
  format: "json"
  output: "/var/log/mcpscan/scanner.log"
  rotation: true
  max_size: "100MB"
  max_files: 10
```

### Environment Variables

Override configuration with environment variables:

```bash
# Scanner settings
export MCPSCAN_TIMEOUT=60s
export MCPSCAN_MAX_PAYLOADS=200
export MCPSCAN_VERBOSE=true

# Proxy settings
export MCPSCAN_PROXY_BIND=0.0.0.0:8080
export MCPSCAN_PROXY_TIMEOUT=15s

# Policy settings
export MCPSCAN_POLICY_DIR=/etc/mcpscan/policies
export MCPSCAN_DEFAULT_POLICY=critical-security

# Integration settings
export MCPSCAN_SIEM_ENDPOINT=https://siem.example.com/api/alerts
export MCPSCAN_SIEM_API_KEY=your-api-key
export MCPSCAN_SLACK_WEBHOOK=https://hooks.slack.com/services/...

# Logging settings
export MCPSCAN_LOG_LEVEL=DEBUG
export MCPSCAN_LOG_FILE=/var/log/mcpscan/scanner.log
```

## Advanced Usage

### Batch Scanning

Scan multiple targets:

```bash
# Create target list
cat > targets.txt << EOF
./project1
./project2 
https://server1.example.com
https://server2.example.com
EOF

# Batch scan with custom script
for target in $(cat targets.txt); do
  echo "Scanning $target..."
  ./build/mcpscan scan-local "$target" critical-security > "report-$(basename $target).json"
done
```

### Integration with CI/CD

`.github/workflows/security-scan.yml`:
```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Install MCP Scanner
      run: |
        wget https://github.com/syphon1c/mcp-security-scanner/releases/latest/mcpscan-linux-amd64.tar.gz
        tar -xzf mcpscan-linux-amd64.tar.gz
        chmod +x mcpscan
    
    - name: Run Security Scan
      run: |
        ./mcpscan scan-local . critical-security > security-report.json
        
    - name: Check for Critical Issues
      run: |
        critical_count=$(jq '.statistics.critical' security-report.json)
        if [ "$critical_count" -gt 0 ]; then
          echo "Critical security issues found: $critical_count"
          exit 1
        fi
        
    - name: Upload Security Report
      uses: actions/upload-artifact@v3
      with:
        name: security-report
        path: security-report.json
```

### Custom Integrations

#### SIEM Integration Example

```python
#!/usr/bin/env python3
import json
import requests
import subprocess

def run_scan(target, policy):
    """Run MCP security scan and return results"""
    result = subprocess.run([
        './build/mcpscan', 'scan-local', target, policy
    ], capture_output=True, text=True)
    
    if result.returncode == 0:
        return json.loads(result.stdout)
    else:
        raise Exception(f"Scan failed: {result.stderr}")

def send_to_siem(scan_result):
    """Send scan results to SIEM"""
    siem_endpoint = "https://siem.example.com/api/events"
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer YOUR_API_KEY"
    }
    
    for finding in scan_result['findings']:
        event = {
            "timestamp": scan_result['timestamp'],
            "source": "mcp-security-scanner",
            "event_type": "security_finding",
            "severity": finding['severity'].lower(),
            "description": finding['description'],
            "target": scan_result['target'],
            "details": finding
        }
        
        response = requests.post(siem_endpoint, headers=headers, json=event)
        response.raise_for_status()

# Usage
if __name__ == "__main__":
    scan_result = run_scan("./my-project", "critical-security")
    send_to_siem(scan_result)
    print(f"Sent {len(scan_result['findings'])} findings to SIEM")
```

## Troubleshooting

### Common Issues and Solutions

#### "No security policies found"
```bash
# Check policy directory
ls -la configs/
./build/mcpscan policies

# Validate policy files
jq '.' policies/critical-security.json
```

#### "Connection refused" (Remote scanning)
```bash
# Test connectivity
curl -v https://target-server.com
telnet target-server.com 443

# Check proxy settings
echo $HTTP_PROXY
echo $HTTPS_PROXY
```

#### "Timeout exceeded"
```bash
# Increase timeout
./build/mcpscan scan-remote https://slow-server.com standard-security --timeout 120s

# Check network latency
ping target-server.com
```

#### High false positive rate
```bash
# Use more specific policy
./build/mcpscan scan-local . critical-security

# Add exclusions to custom policy
# Edit policy file to add exclusion patterns
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
# Set debug environment
export LOG_LEVEL=DEBUG
export MCPSCAN_VERBOSE=true

# Run with verbose output
./build/mcpscan scan-local . standard-security --verbose

# Check logs
tail -f /var/log/mcpscan/scanner.log
```

### Performance Tuning

```bash
# Reduce concurrent jobs for low-memory systems
export MCPSCAN_CONCURRENT_JOBS=2

# Limit payload testing
export MCPSCAN_MAX_PAYLOADS=50

# Use faster policy for quick scans
./build/mcpscan scan-local . critical-security
```

This user manual provides  guidance for effective use of the MCP Security Scanner in various security assessment scenarios.
