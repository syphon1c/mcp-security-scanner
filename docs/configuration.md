# Configuration Reference

This document provides  reference information for configuring the MCP Security Scanner, including all available options, their defaults, and usage examples.

## Configuration File Structure

The scanner uses YAML format for its primary configuration file. The default location is `configs/config.yaml`.

### Complete Configuration Example

```yaml
# MCP Security Scanner Configuration
# File: configs/config.yaml

# Scanner engine configuration
scanner:
  # Maximum time for a complete scan operation
  timeout: 30s
  
  # Maximum number of test payloads per tool/endpoint
  max_payloads: 100
  
  # Enable verbose logging and detailed output
  verbose: false
  
  # Number of concurrent scanning jobs
  concurrent_jobs: 4
  
  # Memory limit for scanner operations (in MB)
  memory_limit: 512
  
  # Maximum file size to analyse (in MB)
  max_file_size: 10
  
  # Maximum number of files to scan in a directory
  max_files: 1000

# Proxy server configuration  
proxy:
  # Address and port to bind the proxy server
  bind_address: "0.0.0.0:8080"
  
  # Timeout for connections to target servers
  target_timeout: 10s
  
  # Enable monitoring endpoints (/monitor/*)
  monitoring_enabled: true
  
  # Block requests that match suspicious patterns
  block_suspicious: true
  
  # Log all traffic (high disk usage)
  log_all_traffic: false
  
  # Enable WebSocket proxying
  websocket_enabled: true
  
  # Maximum concurrent proxy connections
  max_connections: 1000
  
  # Request rate limiting
  rate_limit:
    # Maximum requests per minute per IP
    requests_per_minute: 1000
    # Burst allowance
    burst_size: 100
    # Enable rate limiting
    enabled: true
  
  # Alert handling configuration
  alert_thresholds:
    # Action for critical severity findings
    critical: "block"     # Options: block, alert, log, ignore
    high: "alert"         # Options: block, alert, log, ignore  
    medium: "log"         # Options: block, alert, log, ignore
    low: "ignore"         # Options: block, alert, log, ignore
  
  # TLS configuration for proxy
  tls:
    # Enable TLS for proxy server
    enabled: false
    # Certificate file path
    cert_file: "/path/to/cert.pem"
    # Private key file path
    key_file: "/path/to/key.pem"
    # Minimum TLS version (1.2, 1.3)
    min_version: "1.2"
    # Verify upstream certificates
    verify_upstream: true

# Security policy configuration
policies:
  # Directory containing JSON policy files
  directory: "./policies"
  
  # Default policy to use when none specified
  default_policy: "standard-security"
  
  # Available security policies:
  # - critical-security: Enterprise-grade threat detection (50+ rules)
  # - standard-security: Balanced security assessment 
  # - mcp-advanced-security: Advanced pattern recognition (159+ rules)
  # - advanced-polymorphic-security: Policy-driven polymorphic detection (NEW)
  # - org-custom-template: Template for creating organization-specific policies
  
  # Automatically reload policies when files change
  auto_reload: true
  
  # Maximum policy file size (in MB)
  max_policy_size: 5
  
  # Cache compiled regex patterns for performance
  cache_patterns: true
  
  # Policy inheritance (not yet implemented)
  inheritance:
    enabled: false
    base_policy: "standard-security"

# External system integration configuration
integration:
  # SIEM (Security Information and Event Management) integration
  siem:
    # Enable SIEM integration
    enabled: false
    
    # SIEM API endpoint URL
    endpoint: "https://siem.example.com/api/alerts"
    
    # API authentication key
    api_key: ""
    
    # Alert format (json, cef, leef)
    format: "json"
    
    # HTTP timeout for SIEM requests
    timeout: 10s
    
    # Retry configuration
    retry:
      max_attempts: 3
      delay: 5s
      exponential_backoff: true
    
    # Only send alerts above this severity
    min_severity: "Medium"
    
    # Custom headers
    headers:
      User-Agent: "MCP-Security-Scanner/1.0"
      X-Source: "mcp-scanner"
  
  # SOAR (Security Orchestration, Automation and Response) integration  
  soar:
    # Enable SOAR integration
    enabled: false
    
    # SOAR platform API endpoint
    endpoint: "https://soar.example.com/api/incidents"
    
    # API authentication key  
    api_key: ""
    
    # Incident creation threshold
    severity_threshold: "High"
    
    # HTTP timeout for SOAR requests
    timeout: 15s
    
    # Incident template
    incident_template:
      category: "Security Alert"
      priority: "{{.Severity}}"
      description: "MCP Security Finding: {{.Description}}"
  
  # Slack integration for notifications
  slack:
    # Enable Slack notifications
    enabled: false
    
    # Slack webhook URL
    webhook: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
    
    # Target channel (optional, webhook determines channel)
    channel: "#security-alerts"
    
    # Only notify for these severity levels
    severity_filter: ["Critical", "High"]
    
    # Custom message template
    message_template: |
      🚨 *Security Alert*
      *Severity:* {{.Severity}}
      *Target:* {{.Target}}
      *Description:* {{.Description}}
      *Time:* {{.Timestamp}}
    
    # HTTP timeout for Slack requests
    timeout: 10s
  
  # Email notifications
  email:
    # Enable email notifications
    enabled: false
    
    # SMTP server configuration
    smtp:
      host: "smtp.example.com"
      port: 587
      username: "alerts@example.com"
      password: ""
      use_tls: true
    
    # Email recipients
    recipients:
      - "security-team@example.com"
      - "admin@example.com"
    
    # Email template
    template:
      subject: "[SECURITY] MCP Scanner Alert - {{.Severity}}"
      body: |
        Security finding detected by MCP Scanner:
        
        Severity: {{.Severity}}
        Target: {{.Target}}
        Description: {{.Description}}
        Time: {{.Timestamp}}
        
        Full details:
        {{.Details}}

# Logging configuration
logging:
  # Log level (DEBUG, INFO, WARN, ERROR)
  level: "INFO"
  
  # Log format (text, json)
  format: "json"
  
  # Log output destination (stdout, stderr, file path)
  output: "/var/log/mcpscan/scanner.log"
  
  # Enable log file rotation
  rotation: true
  
  # Maximum log file size before rotation
  max_size: "100MB"
  
  # Maximum number of rotated log files to keep
  max_files: 10
  
  # Maximum age of log files before deletion
  max_age: "30d"
  
  # Compress rotated log files
  compress: true
  
  # Include source code location in logs
  include_caller: false
  
  # Structured logging fields
  fields:
    service: "mcp-security-scanner"
    version: "1.0.0"
    environment: "production"

# Network and connection configuration
network:
  # HTTP client configuration
  http:
    # Default timeout for HTTP requests
    timeout: 30s
    
    # Maximum number of redirects to follow
    max_redirects: 10
    
    # User-Agent header
    user_agent: "MCP-Security-Scanner/1.0"
    
    # Custom headers for all requests
    headers:
      X-Scanner: "MCP-Security"
    
    # TLS configuration
    tls:
      # Skip certificate verification (insecure)
      insecure_skip_verify: false
      # Minimum TLS version
      min_version: "1.2"
      # Preferred cipher suites
      cipher_suites: []
  
  # Proxy configuration for outbound requests
  proxy:
    # HTTP proxy URL
    http_proxy: ""
    # HTTPS proxy URL  
    https_proxy: ""
    # No proxy hosts (comma-separated)
    no_proxy: "localhost,127.0.0.1"
  
  # DNS configuration
  dns:
    # Custom DNS servers
    servers: []
    # DNS lookup timeout
    timeout: 5s

# Performance and resource configuration
performance:
  # CPU usage limits
  cpu:
    # Maximum CPU cores to use (0 = all available)
    max_cores: 0
    # Enable CPU profiling
    profiling: false
  
  # Memory usage limits
  memory:
    # Maximum memory usage in MB (0 = unlimited)
    max_usage: 0
    # Enable memory profiling
    profiling: false
    # Garbage collection target percentage
    gc_target: 100
  
  # Caching configuration
  cache:
    # Enable result caching
    enabled: true
    # Maximum cache size in MB
    max_size: 100
    # Cache TTL for scan results
    ttl: "1h"
    # Cache directory
    directory: "/tmp/mcpscan-cache"

# Security configuration for the scanner itself
security:
  # Authentication configuration
  auth:
    # Enable authentication for monitoring endpoints
    enabled: false
    # Authentication method (basic, token, oauth)
    method: "basic"
    # Basic auth credentials
    basic:
      username: "admin"
      password: "secure-password"
    # Token authentication
    token:
      value: "your-secure-token"
      header: "Authorization"
  
  # Access control
  access:
    # Allowed IP addresses/ranges for monitoring endpoints
    allowed_ips:
      - "127.0.0.1"
      - "10.0.0.0/8"
      - "192.168.0.0/16"
    
    # Enable CORS for web interfaces
    cors:
      enabled: true
      origins: ["*"]
      methods: ["GET", "POST"]
      headers: ["Content-Type", "Authorization"]

# Experimental and advanced features
experimental:
  # Enable experimental features
  enabled: false
  
  # Advanced MCP protocol features
  mcp:
    # Support for custom protocol extensions
    custom_extensions: false
    # Protocol version negotiation
    version_negotiation: true
  
  # Machine learning-based detection
  ml:
    # Enable ML-based vulnerability detection
    enabled: false
    # Model file path
    model_path: ""
    # Confidence threshold
    confidence_threshold: 0.8
  
  # Distributed scanning
  distributed:
    # Enable distributed scanning mode
    enabled: false
    # Coordinator address
    coordinator: ""
    # Worker mode
    worker_mode: false
```

## Configuration Sections

### Scanner Configuration

Controls the core scanning engine behaviour:

```yaml
scanner:
  timeout: 30s              # Overall scan timeout
  max_payloads: 100         # Limit test payloads per endpoint
  verbose: false            # Enable detailed output
  concurrent_jobs: 4        # Parallel scanning jobs
  memory_limit: 512         # Memory limit in MB
  max_file_size: 10         # Max file size to scan (MB)
  max_files: 1000          # Max files per directory scan
```

### Proxy Configuration

Controls the real-time proxy functionality:

```yaml
proxy:
  bind_address: "0.0.0.0:8080"    # Proxy listening address
  target_timeout: 10s              # Target server timeout
  monitoring_enabled: true         # Enable /monitor endpoints
  block_suspicious: true           # Block malicious requests
  log_all_traffic: false          # Log all proxy traffic
  websocket_enabled: true          # Enable WebSocket proxying
  max_connections: 1000           # Max concurrent connections
```

### Policy Configuration

Controls security policy loading and management:

```yaml
policies:
  directory: "./configs"           # Policy file directory
  default_policy: "standard-security"  # Default policy name
  auto_reload: true               # Auto-reload changed policies
  max_policy_size: 5              # Max policy file size (MB)
  cache_patterns: true            # Cache compiled regex patterns
```

### Advanced Polymorphic Pattern Configuration

Starting from version 1.1.0, policies support advanced polymorphic and behavioral pattern detection:

```yaml
# Example policy file with polymorphic patterns
# File: policies/advanced-polymorphic-security.json
{
  "version": "1.0.0",
  "policyName": "advanced-polymorphic-security",
  "description": "Advanced polymorphic pattern detection policy",
  
  "polymorphicPatterns": [
    {
      "name": "command_injection_variants",
      "description": "Multi-variant command injection detection",
      "severity": "Critical",
      "category": "Advanced Injection",
      "threshold": 2,                    # Minimum variants to trigger
      "variants": [
        "exec\\s*\\(\\s*[\"'].*[\"']",
        "system\\s*\\(\\s*[\"'].*[\"']",
        "eval\\s*\\(\\s*[\"'].*exec.*[\"']",
        "__import__\\s*\\(\\s*[\"']os[\"']"
      ]
    }
  ],
  
  "behavioralPatterns": [
    {
      "name": "suspicious_file_operations",
      "description": "Detects suspicious file operation patterns",
      "severity": "High",
      "category": "File System Security",
      "threshold": 3,                    # Minimum pattern matches
      "patterns": [
        "open\\s*\\(\\s*[\"']/etc/",
        "os\\.remove\\(",
        "os\\.chmod\\(.*777"
      ]
    }
  ]
}
```

**Configuration Guidelines:**

**Polymorphic Pattern Thresholds:**
- `threshold: 1` - Single variant detection (high sensitivity)
- `threshold: 2-3` - Medium confidence detection (recommended)
- `threshold: 4+` - High confidence detection (low false positives)

**Behavioral Pattern Thresholds:**
- `threshold: 1-2` - Early warning detection
- `threshold: 3-5` - Balanced detection (recommended)
- `threshold: 6+` - High confidence anomaly detection

**Performance Considerations:**
- Large variant arrays may impact scan performance
- Use `cache_patterns: true` for frequently used policies
- Consider `max_policy_size` limits for complex patterns

### Integration Configuration

Controls external system integrations:

```yaml
integration:
  siem:
    enabled: true
    endpoint: "https://siem.example.com/api/alerts"
    api_key: "your-key"
    format: "json"
    min_severity: "Medium"
  
  slack:
    enabled: true
    webhook: "https://hooks.slack.com/services/..."
    severity_filter: ["Critical", "High"]
```

## Environment Variable Override

Any configuration value can be overridden using environment variables. The naming convention is:

```
MCPSCAN_<SECTION>_<SETTING>
```

Examples:

```bash
# Scanner configuration
export MCPSCAN_SCANNER_TIMEOUT=60s
export MCPSCAN_SCANNER_VERBOSE=true
export MCPSCAN_SCANNER_MAX_PAYLOADS=200

# Proxy configuration  
export MCPSCAN_PROXY_BIND_ADDRESS=127.0.0.1:8080
export MCPSCAN_PROXY_BLOCK_SUSPICIOUS=false

# Policy configuration
export MCPSCAN_POLICIES_DIRECTORY=/etc/mcpscan/policies
export MCPSCAN_POLICIES_DEFAULT_POLICY=critical-security

# Integration configuration
export MCPSCAN_INTEGRATION_SIEM_ENABLED=true
export MCPSCAN_INTEGRATION_SIEM_ENDPOINT=https://siem.example.com/api
export MCPSCAN_INTEGRATION_SLACK_WEBHOOK=https://hooks.slack.com/...

# Logging configuration
export MCPSCAN_LOGGING_LEVEL=DEBUG
export MCPSCAN_LOGGING_OUTPUT=/var/log/mcpscan/debug.log
```

## Command Line Override

Configuration can also be overridden via command line flags:

```bash
# Override timeout
./build/mcpscan scan-local . critical-security --timeout 60s

# Override verbosity
./build/mcpscan scan-local . critical-security --verbose

# Override configuration file
./build/mcpscan scan-local . critical-security --config /path/to/custom-config.yaml

# Override policy directory
./build/mcpscan scan-local . critical-security --policy-dir /custom/policies

# Use advanced security policy for  threat detection
./build/mcpscan scan-local . mcp-advanced-security --verbose

# Override proxy settings
./build/mcpscan proxy https://target.com 8080 --bind 127.0.0.1:8080 --timeout 15s
```

## Configuration Validation

Validate your configuration file:

```bash
# Validate configuration syntax and values
./build/mcpscan validate-config configs/config.yaml

# Check configuration with environment variables applied
env MCPSCAN_SCANNER_TIMEOUT=60s ./build/mcpscan validate-config configs/config.yaml

# Verbose validation with detailed output
./build/mcpscan validate-config configs/config.yaml --verbose
```

## Security Considerations

### Sensitive Information

Avoid storing sensitive information directly in configuration files:

```yaml
# Bad - credentials in plaintext
integration:
  siem:
    api_key: "secret-key-123"

# Good - use environment variables
integration:
  siem:
    api_key: "${SIEM_API_KEY}"
```

### File Permissions

Set appropriate permissions on configuration files:

```bash
# Restrict access to configuration files
chmod 600 configs/config.yaml
chown mcpscan:mcpscan configs/config.yaml

# Secure directory permissions
chmod 750 configs/
chown -R mcpscan:mcpscan configs/
```

### Network Security

Configure network security appropriately:

```yaml
# Bind proxy to specific interface
proxy:
  bind_address: "127.0.0.1:8080"  # Localhost only

# Enable authentication for monitoring
security:
  auth:
    enabled: true
    method: "token"
    token:
      value: "${MONITOR_TOKEN}"

# Restrict access by IP
security:
  access:
    allowed_ips:
      - "192.168.1.0/24"
      - "10.0.0.0/8"
```

## Performance Tuning

### High-Performance Configuration

For high-throughput environments:

```yaml
scanner:
  concurrent_jobs: 8
  memory_limit: 1024
  max_payloads: 200

proxy:
  max_connections: 2000
  rate_limit:
    requests_per_minute: 5000
    burst_size: 500

performance:
  cpu:
    max_cores: 0  # Use all available cores
  memory:
    max_usage: 2048
  cache:
    enabled: true
    max_size: 500
```

### Low-Resource Configuration

For resource-constrained environments:

```yaml
scanner:
  concurrent_jobs: 1
  memory_limit: 128
  max_payloads: 25
  max_files: 100

proxy:
  max_connections: 100
  rate_limit:
    requests_per_minute: 100
    burst_size: 10

performance:
  cpu:
    max_cores: 1
  memory:
    max_usage: 256
    gc_target: 50
  cache:
    enabled: false
```

## Production Configuration Examples

### Enterprise SIEM Integration

```yaml
scanner:
  timeout: 60s
  max_payloads: 150
  concurrent_jobs: 6

proxy:
  bind_address: "0.0.0.0:8080"
  monitoring_enabled: true
  block_suspicious: true

policies:
  directory: "/etc/mcpscan/policies"
  default_policy: "critical-security"
  auto_reload: true

integration:
  siem:
    enabled: true
    endpoint: "https://splunk.company.com/services/collector/event"
    api_key: "${SPLUNK_HEC_TOKEN}"
    format: "json"
    min_severity: "Medium"
    
  soar:
    enabled: true
    endpoint: "https://phantom.company.com/rest/container"
    api_key: "${PHANTOM_API_KEY}"
    severity_threshold: "High"

logging:
  level: "INFO"
  format: "json"
  output: "/var/log/mcpscan/scanner.log"
  rotation: true
  max_size: "100MB"
  max_files: 30

security:
  auth:
    enabled: true
    method: "token"
    token:
      value: "${MONITOR_TOKEN}"
  access:
    allowed_ips:
      - "10.0.0.0/8"
      - "192.168.0.0/16"
```

### Development Environment

```yaml
scanner:
  timeout: 15s
  max_payloads: 50
  verbose: true
  concurrent_jobs: 2

proxy:
  bind_address: "127.0.0.1:8080"
  monitoring_enabled: true
  block_suspicious: false
  log_all_traffic: true

policies:
  directory: "./configs"
  default_policy: "standard-security"
  auto_reload: true

integration:
  slack:
    enabled: true
    webhook: "${SLACK_WEBHOOK}"
    severity_filter: ["Critical"]

logging:
  level: "DEBUG"
  format: "text"
  output: "stdout"
  include_caller: true

performance:
  cache:
    enabled: false
```

This  configuration reference provides all the options needed to customize the MCP Security Scanner for your specific environment and requirements.
