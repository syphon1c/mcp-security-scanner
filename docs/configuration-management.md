# Configuration Management

The MCP Security Scanner uses a comprehensive YAML-based configuration system with environment variable support. This allows for flexible deployment across different environments while maintaining security best practices.

## Configuration Files

### Primary Configuration
- **File**: `configs/config.yaml`
- **Purpose**: Main configuration file with default values
- **Environment Override**: Set `MCP_SECURITY_CONFIG` environment variable to use a custom config path

### Example Configuration
- **File**: `configs/config.example.yaml`
- **Purpose**: Complete example showing all available options with environment variable syntax

## Configuration Structure

### Scanner Configuration
Controls core scanning behavior:

```yaml
scanner:
  policy_directory: ./policies        # Directory containing security policies
  default_policy: critical-security   # Default policy when none specified
  max_concurrent_jobs: 5              # Maximum concurrent scanning jobs
  timeout: 30s                        # Scanner operation timeout
  max_retries: 3                      # Maximum retries for failed operations
  user_agent: MCP-Security-Scanner/1.0.0  # HTTP User-Agent header
  log_level: INFO                     # Logging level (DEBUG, INFO, WARN, ERROR)
  
  output:
    default_format: json              # Default output format (json, html, pdf, text)
    directory: ./reports              # Output directory for reports
    filename_base: mcp_security_report # Base filename for generated reports
```

### Proxy Configuration
Controls proxy server behavior:

```yaml
proxy:
  host: localhost                     # Proxy server host
  port: 8080                         # Proxy server port
  timeout: 30s                       # Proxy operation timeout
  max_buffer_mb: 10                  # Maximum buffer size in MB
  enable_tls: false                  # Enable TLS/SSL
  cert_file: ""                      # TLS certificate file path
  key_file: ""                       # TLS private key file path
  alert_webhook: ""                  # Webhook URL for real-time alerts
```

### Integration Configuration
Controls external system integrations:

```yaml
integration:
  siem:
    enabled: false                    # Enable SIEM integration
    endpoint: ""                      # SIEM API endpoint
    api_key: ""                       # SIEM API key
    index: mcp-security               # SIEM event index/destination
  
  soar:
    enabled: false                    # Enable SOAR integration
    endpoint: ""                      # SOAR API endpoint
    api_key: ""                       # SOAR API key
    username: ""                      # SOAR username
  
  slack:
    enabled: false                    # Enable Slack notifications
    webhook_url: ""                   # Slack webhook URL
    channel: "#security-alerts"       # Slack channel
    username: "MCP Security Scanner"  # Bot username
    icon_emoji: ":shield:"            # Bot icon emoji
    min_severity: HIGH                # Minimum severity for notifications
```

### Logging Configuration
Controls application logging:

```yaml
logging:
  level: INFO                         # Log level
  format: json                        # Log format (json, text)
  output: stdout                      # Output destination (stdout, stderr, file path)
  max_size_mb: 100                   # Maximum log file size in MB
  max_backups: 3                     # Number of old log files to retain
  max_age: 30                        # Days to retain log files
```

## Environment Variable Support

The configuration system supports environment variable substitution using the syntax `${VAR_NAME:default_value}`.

### Basic Syntax
- `${VAR_NAME}` - Use environment variable, keep original if not set
- `${VAR_NAME:default}` - Use environment variable or default value if not set

### Examples

```yaml
# Basic substitution
api_key: ${SIEM_API_KEY}

# With default value
api_key: ${SIEM_API_KEY:default-key}

# In complex strings
endpoint: ${SIEM_HOST:localhost}:${SIEM_PORT:9200}/api

# Boolean values
enabled: ${SLACK_ENABLED:false}

# Numeric values
port: ${PROXY_PORT:8080}
```

### Common Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `MCP_SECURITY_CONFIG` | Custom config file path | `/etc/mcp-security/config.yaml` |
| `SIEM_API_KEY` | SIEM API authentication key | `abc123xyz789` |
| `SIEM_ENDPOINT` | SIEM API endpoint URL | `https://siem.company.com/api` |
| `SOAR_API_KEY` | SOAR API authentication key | `def456uvw012` |
| `SOAR_ENDPOINT` | SOAR API endpoint URL | `https://soar.company.com/api` |
| `SLACK_WEBHOOK_URL` | Slack webhook for notifications | `https://hooks.slack.com/services/...` |
| `SLACK_CHANNEL` | Slack channel for alerts | `#security-team` |
| `LOG_LEVEL` | Application log level | `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `OUTPUT_DIR` | Report output directory | `/var/log/mcp-security` |
| `POLICY_DIR` | Security policies directory | `/etc/mcp-security/policies` |

## Configuration Loading

### Load Order
1. Check `MCP_SECURITY_CONFIG` environment variable for custom config path
2. Use default path: `./configs/config.yaml`
3. If config file doesn't exist, use built-in defaults
4. Apply environment variable substitutions
5. Validate configuration values

### Validation Rules
- `scanner.policy_directory` must not be empty
- `scanner.timeout` must be positive
- `scanner.max_retries` must not be negative
- `proxy.port` must be between 1 and 65535
- TLS certificate and key files required when `proxy.enable_tls` is true

## Usage Examples

### Development Environment
```bash
# Use default configuration
./mcpscan scan-local server.py critical-security

# Override specific settings
export LOG_LEVEL=DEBUG
export OUTPUT_DIR=/tmp/scan-results
./mcpscan scan-local server.py critical-security --verbose
```

### Production Environment
```bash
# Use production configuration file
export MCP_SECURITY_CONFIG=/etc/mcp-security/prod-config.yaml

# Set integration credentials
export SIEM_API_KEY="prod-siem-key-xyz"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

# Run scanner
./mcpscan scan-remote https://api.internal.com critical-security
```

### Docker Environment
```dockerfile
# Dockerfile
ENV MCP_SECURITY_CONFIG=/app/config/production.yaml
ENV SIEM_API_KEY=""
ENV SLACK_WEBHOOK_URL=""

# Runtime
docker run -e SIEM_API_KEY="$SIEM_API_KEY" \
           -e SLACK_WEBHOOK_URL="$SLACK_WEBHOOK_URL" \
           mcp-security-scanner:latest
```

## Configuration Best Practices

### Security
1. **Never commit secrets**: Use environment variables for API keys and passwords
2. **Use restrictive permissions**: Set config files to 600 or 640 permissions
3. **Validate inputs**: All configuration values are validated on load
4. **Audit access**: Monitor configuration file access and modifications

### Deployment
1. **Environment-specific configs**: Use different config files per environment
2. **Default values**: Provide sensible defaults for all settings
3. **Documentation**: Comment configuration files thoroughly
4. **Version control**: Track configuration changes with version control

### Monitoring
1. **Log configuration loading**: Enable verbose logging during startup
2. **Validate integrations**: Test external system connections on startup
3. **Health checks**: Monitor configuration-dependent services
4. **Alert on failures**: Set up alerts for configuration loading errors

## Troubleshooting

### Common Issues

**Configuration file not found**
```
⚠️  Configuration file not found: ./configs/config.yaml. Using defaults.
```
- Solution: Create config file or set `MCP_SECURITY_CONFIG` environment variable

**Environment variable not substituted**
```yaml
# Wrong: Missing default value
api_key: ${MISSING_VAR}

# Correct: With default value
api_key: ${MISSING_VAR:}
```

**Invalid configuration values**
```
configuration validation failed: proxy.port must be between 1 and 65535
```
- Solution: Check configuration values against validation rules

**Permission denied**
```
failed to read config file /etc/mcp-security/config.yaml: permission denied
```
- Solution: Check file permissions and user access rights

### Debug Configuration Loading
```bash
# Enable verbose output to see configuration loading
./mcpscan scan-local server.py critical-security --verbose

# Test configuration loading only
export LOG_LEVEL=DEBUG
./mcpscan scan-local /nonexistent critical-security --verbose 2>&1 | grep -i config
```

### Validate Configuration
```bash
# Test with minimal config
echo "scanner: {policy_directory: ./policies}" > test-config.yaml
export MCP_SECURITY_CONFIG=test-config.yaml
./mcpscan scan-local server.py critical-security
```
