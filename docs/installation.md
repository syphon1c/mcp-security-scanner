# Installation Guide

This guide covers the complete installation process for MCP Security Scanner, from prerequisites to first scan.

## Prerequisites

### System Requirements
- Go 1.21 or later
- Git for source code management
- Make for build automation
- 4GB RAM minimum (8GB recommended)
- 500MB disk space for installation
- Network access for remote scanning

### Operating System Support
- Linux (Ubuntu 18.04+, CentOS 7+, RHEL 7+)
- macOS (10.15+)
- Windows (with WSL2 recommended)

### Network Requirements
- Outbound HTTPS (443) for remote MCP server scanning
- Configurable proxy listening port (default: 8080)
- SIEM/SOAR integration endpoints (if configured)

## Installation Methods

### Method 1: Source Installation (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-org/mcp-security.git
cd mcp-security

# Install dependencies and build
make deps
make build

# Verify installation
./build/mcpscan --version
```

### Method 2: Pre-built Binaries

```bash
# Download latest release (replace with actual URL)
wget https://github.com/your-org/mcp-security/releases/latest/mcpscan-linux-amd64.tar.gz

# Extract and install
tar -xzf mcpscan-linux-amd64.tar.gz
sudo mv mcpscan /usr/local/bin/

# Verify installation
mcpscan --version
```

### Method 3: Docker Installation

```bash
# Build Docker image
docker build -t mcp-security .

# Run scanner in container
docker run --rm -v $(pwd)/configs:/app/configs mcp-security scan-local /target critical-security
```

## Configuration Setup

### 1. Configuration File

Create the main configuration file:

```bash
# Copy example configuration
cp configs/config.example.yaml configs/config.yaml

# Edit configuration
vi configs/config.yaml
```

Basic configuration example:
```yaml
scanner:
  timeout: 30s
  max_payloads: 100
  verbose: false

proxy:
  bind_address: "0.0.0.0:8080"
  target_timeout: 10s
  monitoring_enabled: true

policies:
  directory: "./configs"
  default_policy: "standard-security"

integration:
  siem:
    enabled: false
    endpoint: ""
  soar:
    enabled: false
    endpoint: ""
  slack:
    enabled: false
    webhook: ""
```

### 2. Security Policies

The scanner includes three pre-configured security policies:

```bash
# List available policies
./build/mcpscan policies

# Validate policy syntax
jq '.' policies/critical-security.json
jq '.' policies/standard-security.json  
jq '.' policies/org-custom-template.json
```

### 3. Custom Policies

Create organisation-specific policies:

```bash
# Copy existing policy as template
cp configs/standard-security.json configs/my-org-policy.json

# Edit policy rules
vi configs/my-org-policy.json
```

Policy structure:
```json
{
  "policy_name": "my-org-policy",
  "version": "1.0",
  "description": "Custom security policy for my organisation",
  "rules": [
    {
      "id": "CUSTOM_001",
      "name": "Custom Pattern Detection",
      "description": "Detects organisation-specific patterns",
      "patterns": ["pattern1", "pattern2"],
      "severity": "Medium"
    }
  ],
  "blocked_patterns": ["blocked_pattern1"],
  "risk_thresholds": {
    "critical": 50,
    "high": 30,
    "medium": 15,
    "low": 5
  }
}
```

## Initial Testing

### 1. Verify Installation

```bash
# Check scanner version and help
./build/mcpscan --version
./build/mcpscan --help

# List available policies
./build/mcpscan policies
```

### 2. Run Self-Test

```bash
# Scan the scanner's own codebase (safe test)
./build/mcpscan scan-local . critical-security

# Expected output: JSON report with security findings
```

### 3. Test Proxy Mode

```bash
# Start proxy (use a safe target for testing)
./build/mcpscan proxy https://httpbin.org 8080 &

# Test proxy connectivity
curl http://localhost:8080/monitor/health

# Stop proxy
killall mcpscan
```

## Environment Setup

### Development Environment

```bash
# Install development dependencies
make dev-deps

# Run tests (when available)
make test

# Enable debug logging
export LOG_LEVEL=DEBUG
```

### Production Environment

```bash
# Create service user
sudo useradd -r -s /bin/false mcpscan

# Create directories
sudo mkdir -p /etc/mcpscan /var/log/mcpscan
sudo chown mcpscan:mcpscan /var/log/mcpscan

# Copy configuration
sudo cp configs/config.yaml /etc/mcpscan/
sudo cp -r configs/*.json /etc/mcpscan/

# Set permissions
sudo chmod 600 /etc/mcpscan/config.yaml
sudo chmod 644 /etc/mcpscan/*.json
```

### Systemd Service (Linux)

Create a systemd service file:

```bash
sudo tee /etc/systemd/system/mcpscan-proxy.service > /dev/null <<EOF
[Unit]
Description=MCP Security Scanner Proxy
After=network.target

[Service]
Type=simple
User=mcpscan
ExecStart=/usr/local/bin/mcpscan proxy https://target-server.com 8080
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl enable mcpscan-proxy
sudo systemctl start mcpscan-proxy
sudo systemctl status mcpscan-proxy
```

## Verification

### 1. Configuration Validation

```bash
# Validate configuration syntax
./build/mcpscan validate-config configs/config.yaml

# Test policy loading
./build/mcpscan policies --verbose
```

### 2. Network Connectivity

```bash
# Test remote scanning capability
./build/mcpscan scan-remote https://httpbin.org/json standard-security

# Test proxy functionality
./build/mcpscan proxy https://httpbin.org 8080 --test-mode
```

### 3. Performance Baseline

```bash
# Run performance test on known target
time ./build/mcpscan scan-local . standard-security

# Monitor resource usage
top -p $(pgrep mcpscan)
```

## Common Installation Issues

### Go Version Mismatch
```bash
# Check Go version
go version

# Install Go 1.21+ if needed
# See: https://golang.org/doc/install
```

### Permission Errors
```bash
# Fix binary permissions
chmod +x ./build/mcpscan

# Fix config permissions
chmod 644 configs/*.yaml
chmod 644 configs/*.json
```

### Port Conflicts
```bash
# Check if port is in use
netstat -tlnp | grep :8080

# Use alternative port
./build/mcpscan proxy https://target-server.com 8081
```

### DNS Resolution
```bash
# Test target connectivity
nslookup target-server.com
ping target-server.com

# Configure DNS if needed
echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf
```

## Next Steps

After successful installation:
1. Read the [User Manual](user-manual.md) for detailed usage instructions
2. Review [Configuration Reference](configuration.md) for advanced options
3. Explore [Security Policies](security-policies.md) for policy customisation
4. Consider [Enterprise Deployment](enterprise-deployment.md) for production use

## Support

For installation issues:
- Check [Troubleshooting Guide](troubleshooting.md)
- Review system logs for error details
- Verify all prerequisites are met
- Ensure network connectivity to target systems
