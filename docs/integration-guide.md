# MCP Security Scanner Integration Configuration Examples

This document provides examples for configuring enterprise integrations with SIEM, SOAR, and Slack systems.

## Configuration File Setup

The integrations are configured in the `config.yaml` file under the `integration` section:

```yaml
# Integration Configuration
integration:
  # SIEM Integration
  siem:
    # Enable SIEM integration
    enabled: true
    
    # SIEM API endpoint
    endpoint: ${SIEM_ENDPOINT:https://siem.company.com/api/events}
    
    # SIEM API key for authentication
    api_key: ${SIEM_API_KEY:your-siem-api-key}
    
    # Index/destination for SIEM events
    index: mcp-security
  
  # SOAR Integration
  soar:
    # Enable SOAR integration
    enabled: true
    
    # SOAR API endpoint
    endpoint: ${SOAR_ENDPOINT:https://soar.company.com/api}
    
    # SOAR API key for authentication
    api_key: ${SOAR_API_KEY:your-soar-api-key}
    
    # Username for SOAR authentication
    username: ${SOAR_USERNAME:security-scanner}
  
  # Slack Notifications
  slack:
    # Enable Slack notifications
    enabled: true
    
    # Slack webhook URL
    webhook_url: ${SLACK_WEBHOOK_URL:https://hooks.slack.com/services/YOUR/WEBHOOK/URL}
    
    # Slack channel for notifications
    channel: "#security-alerts"
    
    # Bot username for Slack messages
    username: "MCP Security Scanner"
    
    # Icon emoji for Slack messages
    icon_emoji: ":shield:"
    
    # Minimum severity level for Slack notifications
    min_severity: HIGH
```

## Environment Variables

For security, configure sensitive values using environment variables:

```bash
# SIEM Configuration
export SIEM_ENDPOINT="https://splunk.company.com:8088/services/collector"
export SIEM_API_KEY="your-splunk-hec-token"

# SOAR Configuration
export SOAR_ENDPOINT="https://phantom.company.com/rest"
export SOAR_API_KEY="your-phantom-api-key"
export SOAR_USERNAME="mcp-scanner"

# Slack Configuration
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
```

## SIEM Integration Examples

### Splunk Configuration
```yaml
integration:
  siem:
    enabled: true
    endpoint: "https://splunk.company.com:8088/services/collector"
    api_key: "${SPLUNK_HEC_TOKEN}"
    index: "mcp_security"
```

### Elastic SIEM Configuration
```yaml
integration:
  siem:
    enabled: true
    endpoint: "https://elasticsearch.company.com:9200/mcp-security/_doc"
    api_key: "${ELASTIC_API_KEY}"
    index: "mcp-security"
```

### QRadar Configuration
```yaml
integration:
  siem:
    enabled: true
    endpoint: "https://qradar.company.com/api/siem/events"
    api_key: "${QRADAR_SEC_TOKEN}"
    index: "mcp-security"
```

## SOAR Integration Examples

### Phantom/SOAR Configuration
```yaml
integration:
  soar:
    enabled: true
    endpoint: "https://phantom.company.com/rest"
    api_key: "${PHANTOM_API_KEY}"
    username: "mcp-security-scanner"
```

### IBM Resilient Configuration
```yaml
integration:
  soar:
    enabled: true
    endpoint: "https://resilient.company.com/rest/orgs/201"
    api_key: "${RESILIENT_API_KEY}"
    username: "mcp-scanner@company.com"
```

### Demisto/Cortex XSOAR Configuration
```yaml
integration:
  soar:
    enabled: true
    endpoint: "https://demisto.company.com/api/v1"
    api_key: "${DEMISTO_API_KEY}"
    username: "mcp-security-scanner"
```

## Slack Integration

### Basic Slack Setup
1. Create a Slack app in your workspace
2. Enable incoming webhooks
3. Copy the webhook URL to your configuration

```yaml
integration:
  slack:
    enabled: true
    webhook_url: "${SLACK_WEBHOOK_URL}"
    channel: "#security-alerts"
    username: "MCP Security Scanner"
    icon_emoji: ":shield:"
    min_severity: MEDIUM
```

### Severity Levels for Slack
- `CRITICAL`: Only critical alerts
- `HIGH`: High and critical alerts
- `MEDIUM`: Medium, high, and critical alerts
- `LOW`: All alerts (not recommended for production)

## Testing Integrations

Test your integration configuration:

```bash
# Test all integrations
./mcpscan integrations

# Run a scan to test real-time integration
./mcpscan scan-local ./test-server critical-security
```

## Event Types Sent to Integrations

### SIEM Events
- Security alerts from proxy monitoring
- Vulnerability findings from scans
- Scan completion summaries
- Risk assessment data

### SOAR Incidents
- Critical security alerts (auto-creates incidents)
- High-risk vulnerability findings
- Failed security scans
- Policy violations

### Slack Notifications
- Real-time security alerts
- Scan completion summaries
- Critical vulnerability discoveries
- Integration status changes

## Security Considerations

1. **API Keys**: Always use environment variables for sensitive data
2. **Network Security**: Ensure HTTPS endpoints are used
3. **Rate Limiting**: Configure appropriate timeouts and retry logic
4. **Access Control**: Use dedicated service accounts with minimal permissions
5. **Monitoring**: Monitor integration health and error rates

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Verify API keys and credentials
   - Check endpoint URLs
   - Ensure proper permissions

2. **Network Connectivity**
   - Test endpoint accessibility
   - Check firewall rules
   - Verify SSL certificates

3. **Configuration Errors**
   - Use `./mcpscan integrations` to validate
   - Check YAML syntax
   - Verify environment variables

### Debug Mode

Enable verbose logging for integration debugging:

```yaml
logging:
  level: DEBUG
```

### Integration Health Monitoring

Monitor integration status with:
```bash
# Check integration status
./mcpscan integrations

# Monitor integration logs
tail -f /var/log/mcp-security/integration.log
```

## Performance Considerations

- **Batch Size**: SIEM events are sent individually for real-time processing
- **Retry Logic**: Failed integrations are retried with exponential backoff
- **Async Processing**: Integrations run asynchronously to avoid blocking scans
- **Rate Limiting**: Built-in rate limiting prevents overwhelming external systems

## Compliance and Audit

The integration system supports compliance requirements:
- All events include timestamps and source attribution
- Integration attempts are logged for audit trails
- Configuration validation ensures proper setup
- Health monitoring provides operational visibility
