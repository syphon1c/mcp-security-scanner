# Changelog

All notable changes to the MCP Security Scanner project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-beta] - 2025-09-15

### 🎉 First Public Beta Release

This marks the first public beta release of MCP Security Scanner, a security assessment tool for Model Context Protocol (MCP) servers. The project combines static analysis, dynamic vulnerability testing, and real-time proxy monitoring to protect enterprise MCP deployments.

### ✨ Features Added

#### Core Scanner Engine
- **Local Scanning**: Static analysis of MCP server source code for vulnerability detection
- **Remote Scanning**: Dynamic testing of live MCP servers for security vulnerabilities
- **Multi-language Support**: JavaScript, TypeScript, Python, Go, Java, PHP, Ruby
- **Vulnerability Detection**: Command injection, SQL injection, path traversal, template injection
- **Risk Assessment**: Quantified risk scoring system (Critical, High, Medium, Low)

#### Live Monitoring Proxy
- **Real-time Traffic Interception**: Transparent monitoring between MCP clients and servers  
- **Threat Detection**: Automatic pattern matching and blocking of malicious activities
- **Protocol Support**: Both HTTP and WebSocket transport layers
- **Zero Configuration**: No client-side changes required for deployment
- **Performance Monitoring**: Request/response timing and throughput metrics

#### Security Policy Engine  
- **Policy-based Rules**: JSON-based rule engine with configurable detection patterns
- **Pre-built Policies**: 
  - `critical-security.json`: High-risk vulnerabilities and critical security issues
  - `standard-security.json`: General security checks and best practices  
  - `mcp-advanced-security.json`: Advanced MCP-specific threats with 159+ detection rules
  - `advanced-polymorphic-security.json`: Advanced pattern matching capabilities
- **Custom Policies**: Template and examples for organisation-specific security rules

#### Reporting System
- **Multiple Formats**: JSON, HTML, PDF, and Text output formats
- **Automated Directory Creation**: Reports save to `./reports/` by default
- **Timestamp Format**: `mcp_security_report_YYYYMMDD_HHMMSS.ext`
- **Batch Generation**: `--all-formats` flag for simultaneous multi-format output
- **Custom Output**: Configurable output directories and file names

#### Enterprise Integration
- **SIEM Integration**: JSON alert forwarding to security information and event management systems
- **SOAR Integration**: Incident creation via security orchestration platforms
- **Slack Notifications**: Webhook-based alerting for real-time monitoring
- **RESTful API**: Monitoring endpoints for proxy health and security alerts

#### Configuration Management
- **YAML Configuration**: Structured configuration files with environment variable support
- **Default Settings**: Sensible defaults for immediate deployment
- **Environment Variables**: Support for sensitive data injection (API keys, webhooks)
- **Runtime Configuration**: Dynamic policy loading and security rule updates

### 🔧 Technical Implementation

#### Architecture Components
- **MCPScanner**: Core scanning engine with static and dynamic analysis
- **MCPProxy**: Real-time traffic interception and threat detection
- **Policy Engine**: JSON-based rule matching with regex pattern support
- **MCP Protocol Handler**: Native MCP message parsing and tool/resource analysis

#### Performance Features
- **Concurrent Processing**: Multi-threaded scanning for improved performance
- **Memory Management**: Efficient handling of large codebases and traffic volumes
- **Error Handling**: Robust error recovery and logging throughout the application
- **Testing Infrastructure**: Unit tests, integration tests, and performance benchmarks

### 📚 Documentation
- Complete user manual with usage examples
- Configuration management guide  
- Proxy documentation with deployment instructions
- Advanced traffic analysis techniques
- Installation guide for various environments
- Policy creation examples and templates
- Testing guide with mock server examples
- Troubleshooting guide for common issues

### 🧪 Testing & Quality Assurance
- Unit test coverage for core components
- Integration testing with mock MCP servers
- Performance benchmarking suite
- GitHub Actions CI/CD pipeline
- Code quality checks with golangci-lint
- Security-focused development practices

### 🔒 Security Features
- **Pattern Detection**: Advanced regex-based threat identification
- **Real-time Blocking**: Automatic blocking of detected malicious patterns
- **Alert Generation**: Structured security alerts with evidence and context
- **Traffic Analysis**: Deep inspection of MCP protocol messages
- **Risk Scoring**: Quantitative risk assessment for detected vulnerabilities

### 📦 Deployment
- **Single Binary**: Self-contained executable with no external dependencies
- **Docker Support**: Containerised deployment options
- **Cross-platform**: Support for Linux, macOS, and Windows
- **Minimal Configuration**: Works out-of-the-box with sensible defaults

### ⚠️ Known Limitations
- Static analysis cannot detect all vulnerability types (e.g. semantic issues like prompt injection)
- Performance may vary with very large codebases or high-traffic environments
- Some advanced MCP protocol features may not be fully covered in initial release
- Beta software - use with appropriate testing in your environments or dev endpoints

### 📈 Metrics
- 159+ detection rules in advanced security policy
- Support for 7 programming languages
- 4 output report formats
- 3 enterprise integration types (SIEM, SOAR, Slack)
- Full MCP protocol version "2024-11-05" compatibility

### 🤝 Contributors
Initial development with AI assistance for enhanced development efficiency while maintaining code quality and security standards and of course, Unit Tests...because no-one loves doing Unit Tests.

---

**Note**: This is a beta release. While the software has been tested, users should conduct thorough testing in their specific environments. We welcome feedback and bug reports to improve the software for the stable release.

### Next Steps
- Community feedback incorporation
- Performance optimisation based on real-world usage
- Additional security policy templates or improvements
- Additional integration features
- Stable v1.0.0 release planning
