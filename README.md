# MCP Security Scanner

[![Beta Release](https://img.shields.io/badge/Release-v1.0.0--beta-orange?style=flat-square)](https://github.com/syphon1c/mcp-security-scanner/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat-square&logo=go)](https://golang.org)

> **🚀 First Public Beta Release (v1.0.0-beta)** - Released as-is for feedback and testing. See [CHANGELOG.md](CHANGELOG.md) for complete release notes.

A security scanner and proxy for Model Context Protocol (MCP) servers. Provides static analysis, dynamic vulnerability testing, and real-time monitoring to protect MCP deployments in your local dev or enterprise environments.

## ⚠️ Beta Release Notice

This is the **first public beta release (v1.0.0-beta)** of my personal MCP Security Scanner. While the software has been tested, please note:

- **Use with caution** in your environments
- **Test thoroughly** in your specific environment before deployment  
- **Report bugs** and provide feedback via GitHub Issues (When I have time, I will get around to it)
- **Review the [CHANGELOG.md](CHANGELOG.md)** for complete feature details and known limitations
- **Community feedback** is welcomed to improve the software for the stable release

---

## Core Features

### 🔍 Local Scanning
Performs static analysis of MCP server source code to identify potential security vulnerabilities:
- Source code vulnerability detection (command injection, SQL injection, path traversal)
- MCP-specific security issues (tool poisoning, resource manipulation)
- Configuration analysis (hardcoded secrets, weak authentication)
- Multi-language support (JavaScript, TypeScript, Python, Go, Java, PHP, Ruby)

### 🌐 Remote Scanning  
Tests live MCP servers for potential security vulnerabilities and malicious behaviours:
- MCP protocol testing and capability enumeration
- Dynamic vulnerability testing (injection attacks, authentication bypass)
- Information disclosure detection
- Tool and resource security analysis

### 🔄 Live Monitoring Proxy
Real-time security monitoring and protection:
- Transparent traffic interception between MCP clients and servers
- Real-time threat detection and blocking when the MCP Server goes bad
- WebSocket and HTTP support
- Security alerting with SIEM integration and Slack alerts

## Security Policies

The scanner includes a few default security policies, that you can modify or add additional custom policies:

- **critical-security**: High-risk vulnerabilities and critical security issues
- **standard-security**: General security checks and best practices
- **mcp-advanced-security**: Advanced MCP-specific threats with 159+ detection rules

Custom policies can be created using JSON configuration files.

## Security Capabilities

- **Threat Detection**: Command injection, SQL injection, path traversal, template injection
- **Real-time Blocking**: Automatic blocking of detected malicious patterns
- **Risk Assessment**: Quantified risk scoring (Critical, High, Medium, Low)
- **Alert Integration**: SIEM/SOAR integration for enterprise security stacks. Slack for direct monitoring alerts too.
- **Reporting**: Multiple formats (JSON, HTML, PDF, Text) with half OK styling

> **Note**: Static analysis has limitations and cannot detect all vulnerability types (e.g., semantic issues like prompt injection). Consider combining with runtime testing and dynamic analysis for comprehensive security coverage.

## Quick Start

### Installation

```bash
# Clone and build
git clone https://github.com/syphon1c/mcp-security-scanner.git
cd mcp-security-scanner
go build -o mcpscan

# Verify installation
./mcpscan --help
```

### Basic Usage

```bash
# Scan local MCP server code using the critical-security.json policy
./mcpscan scan-local ./test-samples/ critical-security

# Scan remote MCP server with the standard policy
./mcpscan scan-remote http://localhost:8000 standard-security

# Start security proxy
./mcpscan proxy http://target-server.com 8080

# View available policies
./mcpscan policies
```

![Local Scanner Demo](docs/media/mcp_local_scanner.gif)

### Advanced Examples

```bash
# Generate HTML report
./mcpscan scan-local . critical-security --output-format html

# Scan with verbose output
./mcpscan scan-local . mcp-advanced-security --verbose

# Generate all report formats
./mcpscan scan-local . critical-security --all-formats

# Custom output directory
./mcpscan scan-local . critical-security --output-dir ./reports
```

## Live Monitoring Proxy

The proxy provides transparent security monitoring for MCP traffic:


![Live Monitoring Proxy Demo](docs/media/mcp_proxy_mode.gif)

```bash
# Start proxy with advanced security policy
./mcpscan proxy https://mcp-server.com 8080 mcp-advanced-security

# Monitor proxy status
curl http://localhost:8080/monitor/health

# View security alerts
curl http://localhost:8080/monitor/alerts

# Check traffic logs
curl http://localhost:8080/monitor/logs
```

### Proxy Features

- **Zero Configuration**: No client-side changes required
- **Real-time Analysis**: Immediate threat detection and blocking
- **Performance Monitoring**: Request/response timing and throughput metrics
- **Security Dashboard**: RESTful monitoring endpoints
- **Alert Integration**: Automatic forwarding to SIEM/SOAR systems

## Configuration

Basic configuration in `configs/config.yaml`:

```yaml
scanner:
  policy_directory: ./policies
  timeout: 30s
  output:
    default_format: json
    directory: ./reports

proxy:
  host: localhost
  port: 8080

integration:
  siem:
    enabled: false
    endpoint: ${SIEM_ENDPOINT}
  slack:
    enabled: false
    webhook_url: ${SLACK_WEBHOOK}
```

Environment variable support for sensitive data:

```bash
export SIEM_API_KEY="your-api-key"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
export MCP_SECURITY_CONFIG="/path/to/config.yaml"
```

## Example Security Detection

```bash
# SQL Injection Detection
curl -X POST http://localhost:8080/mcp/tools/call \
  -d '{"params": {"query": "SELECT * FROM users WHERE id = 1; DROP TABLE users;"}}'

# Security Alert Generated:
{
  "timestamp": "2025-09-02T10:30:00Z",
  "severity": "Critical",
  "alertType": "SQL Injection Detected",
  "description": "Malicious SQL pattern detected in tool parameter",
  "source": "192.168.1.100",
  "evidence": "DROP TABLE users;",
  "action": "Blocked"
}
```

## Build and Test

```bash
# Build
make build

# Run tests
make test

# Format code
make fmt

# Clean
make clean
```

## Documentation

Detailed documentation is available in the `/docs` directory:

- [User Manual](docs/user-manual.md) - Complete usage guide
- [Configuration Management](docs/configuration-management.md) - Configuration options
- [Proxy Documentation](docs/proxy-documentation.md) - Live monitoring setup
- [Advanced Traffic Analysis](docs/advanced-traffic-analysis.md) - Threat detection guide
- [Installation Guide](docs/installation.md) - Setup and deployment
- [Policy Examples](docs/policy-examples.md) - Custom security policies

## Project Structure

```
mcp-security/
├── cmd/mcpscan/          # Command-line interface
├── internal/             # Core application logic
│   ├── scanner/          # Vulnerability scanning engine
│   ├── proxy/            # Real-time monitoring proxy
│   ├── policy/           # Security policy engine
│   └── integration/      # SIEM/SOAR integrations
├── configs/              # Security policies and configuration
├── docs/                 # Documentation
├── test/                 # Test suites and mock servers
└── reports/              # Default output directory
```


## Support & Contributing

### 📚 Documentation
For detailed usage instructions, advanced configuration, and troubleshooting guides, see the complete documentation in the `/docs` directory.

### 🐛 Bug Reports & Feature Requests  
This is a beta release - I welcome community feedback! Please use GitHub Issues to:
- Report bugs and unexpected behaviour
- Request new features or improvements  
- Share usage experiences and suggestions
- Contribute to documentation improvements (yes I use AI to help document the features and functionality)

### 🤝 Contributing
Contributions are welcome! Please see our contributing guidelines and submit pull requests for:
- Bug fixes and improvements
- New security detection rules
- Additional security policies
- Documentation enhancements
- Note where you using AI for coding and always check the work to make sure its working like it should

### 📞 Support
- **GitHub Issues**: Primary support channel for bug reports and questions
- **Documentation**: Usage/How to guides in the `/docs` directory

## Development Note

This project has utilised AI assistance for portions of code implementation and documentation to enhance development efficiency while maintaining code quality (Unit Tests) and security standards.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**MCP Security Scanner v1.0.0-beta** - Advanced security testing for Model Context Protocol infrastructure.

*Released as-is for testing, feedback and if anyone else finds it useful. See [CHANGELOG.md](CHANGELOG.md) for complete release details.*