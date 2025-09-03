# Advanced Traffic Analysis

This guide explains how to use the MCP Security Scanner's advanced traffic analysis capabilities for detecting sophisticated threats and attack patterns in real-time.

## Overview

The advanced traffic analysis system provides multi-layered security monitoring that goes beyond simple pattern matching. It uses behavioural analysis, statistical modelling, and content inspection to identify complex attack sequences and anomalous activities.

### Key Capabilities

- **Behavioural Analysis**: Detects suspicious session patterns and user behaviour
- **Attack Sequence Recognition**: Identifies multi-step attack campaigns
- **Statistical Anomaly Detection**: Spots deviations from normal traffic patterns  
- **Content Analysis**: Examines payload entropy and encoding patterns
- **Real-time Blocking**: Automatically blocks detected threats

## When to Use Advanced Analysis

Advanced traffic analysis is particularly effective for:

- **High-value environments** where sophisticated attacks are expected
- **Enterprise deployments** requiring detailed threat intelligence
- **Compliance scenarios** needing audit trails and detailed logging
- **Research environments** where attack pattern analysis is important

## Configuration

### Enabling Advanced Analysis

Advanced analysis is automatically enabled when using the proxy mode:

```bash
# Start proxy with advanced analysis
./mcpscan proxy https://target-server.com 8080
```

### Analysis Thresholds

Configure detection sensitivity in your `configs/config.yaml`:

```yaml
proxy:
  advanced_analysis:
    # Statistical significance threshold (2.5 = 99.4% confidence)
    sigma_threshold: 2.5
    
    # Content entropy threshold (7.0 = highly random content)
    entropy_threshold: 7.0
    
    # Rapid-fire detection threshold
    rapid_fire_threshold: 100ms
    
    # Confidence interval for statistical models
    confidence_interval: 0.95
```

### Session Management

Control how sessions are tracked and analysed:

```yaml
proxy:
  sessions:
    # Session timeout (default: 1 hour)
    timeout: 3600s
    
    # Cleanup interval for expired sessions
    cleanup_interval: 300s
    
    # Maximum concurrent sessions to track
    max_sessions: 10000
```

## Understanding Detection Types

### Behavioural Anomalies

The system tracks session behaviour and identifies suspicious patterns:

#### Rapid-Fire Detection
Flags clients making requests faster than typical human interaction:

```bash
# Example alert
{
  "type": "BehavioralAnomaly",
  "subtype": "RapidFire", 
  "description": "Client making requests every 45ms (threshold: 100ms)",
  "confidence": 0.95,
  "evidence": {
    "intervals": [45, 52, 38, 41],
    "average": 44
  }
}
```

#### Method Domination
Detects when a session overwhelmingly uses one MCP method:

```bash
# Example alert
{
  "type": "BehavioralAnomaly",
  "subtype": "MethodDomination",
  "description": "85% of requests use tools/call method (threshold: 80%)",
  "confidence": 0.87,
  "evidence": {
    "dominant_method": "tools/call",
    "percentage": 85.3
  }
}
```

### Attack Sequence Detection

Identifies coordinated attack patterns across multiple requests:

#### Reconnaissance Sequence
Detects systematic information gathering:

```bash
# Typical sequence
1. tools/list     (enumerate available tools)
2. resources/list (discover accessible resources)  
3. tools/call     (probe specific functionality)
```

#### Privilege Escalation
Identifies attempts to gain elevated access:

```bash
# Example sequence
1. whoami        (identify current user)
2. sudo commands (attempt privilege elevation)
3. su commands   (alternative elevation method)
```

### Statistical Anomalies

Monitors traffic patterns and identifies deviations:

#### Payload Size Anomalies
Detects unusually large or small payloads:

```bash
# Example alert
{
  "type": "StatisticalAnomaly",
  "metric": "PayloadSize",
  "expected": 113.0,
  "observed": 5814.0,
  "deviation": 265.7,
  "significance": "Critical (>2.5σ)"
}
```

#### Request Timing Patterns
Identifies unusual timing characteristics:

```bash
# Example patterns detected
- Perfectly regular intervals (bot behaviour)
- Sudden rate changes (attack initiation)
- Time-based attack patterns
```

### Content Analysis

Examines request and response content for threats:

#### High Entropy Content
Detects encoded, encrypted, or obfuscated payloads:

```bash
# Shannon entropy calculation
- Normal text: ~3.0-4.0 bits
- Base64 data: ~4.0-5.0 bits
- Encrypted/random: >7.0 bits (flagged)
```

#### Encoding Detection
Identifies various obfuscation techniques:

```bash
# Detected patterns
- Base64 encoding
- Hexadecimal encoding  
- URL encoding variations
- Unicode escape sequences
```

## Monitoring and Alerts

### Real-time Monitoring

Check proxy status and current analysis:

```bash
# Check proxy health
curl http://localhost:8080/monitor/health

# View current sessions
curl http://localhost:8080/monitor/sessions

# Get analysis statistics
curl http://localhost:8080/monitor/stats
```

### Alert Integration

Configure enterprise integrations in `configs/config.yaml`:

```yaml
integration:
  siem:
    enabled: true
    endpoint: "https://siem.company.com/api/events"
    api_key: "${SIEM_API_KEY}"
    
  slack:
    enabled: true
    webhook_url: "${SLACK_WEBHOOK}"
    min_severity: "HIGH"
```

### Log Analysis

Advanced analysis generates detailed logs:

```bash
# View recent alerts
tail -f /var/log/mcpscan/proxy.log | grep "THREAT_DETECTED"

# Search for specific patterns
grep "BehavioralAnomaly" /var/log/mcpscan/proxy.log

# Analyse attack sequences
grep "AttackSequence" /var/log/mcpscan/proxy.log | jq '.confidence'
```

## Practical Examples

### Detecting Automated Tools

Automated scanning tools often exhibit behavioural patterns:

```bash
# Signs of automation
- Consistent timing intervals
- High request rates
- Systematic tool enumeration
- Lack of "think time" between requests
```

Configure detection:

```yaml
proxy:
  advanced_analysis:
    rapid_fire_threshold: 50ms  # More sensitive for automation
    automation_detection: true
```

### Identifying Data Exfiltration

Data exfiltration attempts show specific patterns:

```bash
# Common sequence
1. Resource enumeration (find data sources)
2. Large payload requests (extract data)
3. Encoded responses (obfuscated exfiltration)
```

Enable detection:

```yaml
proxy:
  advanced_analysis:
    content_inspection: true
    large_payload_threshold: 1MB
    encoding_detection: true
```

### Blocking Sophisticated Attacks

Configure automatic blocking for high-confidence threats:

```yaml
proxy:
  blocking:
    auto_block: true
    confidence_threshold: 0.8
    block_duration: 3600s  # 1 hour
```

## Performance Considerations

### Memory Usage

Advanced analysis maintains statistical models in memory:

```yaml
proxy:
  advanced_analysis:
    # Limit sample retention
    max_samples: 1000
    
    # Control session tracking
    max_sessions: 5000
    
    # Limit sequence history
    max_sequence_history: 10000
```

### CPU Impact

Analysis is computationally intensive. Consider:

```bash
# Reduce analysis depth for high-volume scenarios
analysis_depth: "basic"  # Options: basic, standard, comprehensive

# Enable selective analysis
selective_analysis:
  high_risk_only: true
  skip_large_payloads: true
```

### Storage Requirements

Detailed logging requires adequate storage:

```bash
# Estimate: ~1-5MB per hour per active session
# 100 concurrent sessions = ~500MB/hour of logs
```

## Troubleshooting

### High False Positive Rates

If experiencing too many false alerts:

```yaml
proxy:
  advanced_analysis:
    # Increase thresholds
    sigma_threshold: 3.0        # From 2.5
    confidence_threshold: 0.9   # From 0.8
    
    # Adjust specific detectors
    rapid_fire_threshold: 200ms # From 100ms
```

### Missing Detections

If sophisticated attacks aren't being caught:

```yaml
proxy:
  advanced_analysis:
    # Increase sensitivity
    sigma_threshold: 2.0        # From 2.5
    entropy_threshold: 6.0      # From 7.0
    
    # Enable all analysis modules
    full_analysis: true
```

### Performance Issues

For high-volume environments:

```yaml
proxy:
  advanced_analysis:
    # Reduce computational load
    statistical_sampling: 0.1   # Sample 10% of traffic
    fast_mode: true
    
    # Limit memory usage
    max_sessions: 1000
    max_samples: 500
```

## Best Practices

### Baseline Establishment

Allow 24-48 hours for statistical models to establish baselines:

```bash
# Monitor baseline establishment
curl http://localhost:8080/monitor/stats | jq '.baseline_status'
```

### Tuning for Environment

Adjust thresholds based on your specific environment:

```bash
# Development environments: Higher thresholds
# Production environments: Lower thresholds  
# High-security environments: Maximum sensitivity
```

### Regular Review

Periodically review and adjust configurations:

```bash
# Weekly review of detection rates
# Monthly threshold adjustments
# Quarterly policy updates
```

### Integration Testing

Test alert flows before production deployment:

```bash
# Trigger test alerts
./mcpscan test-alerts --config configs/config.yaml

# Validate SIEM integration  
./mcpscan validate-integrations
```

## Advanced Features

### Custom Attack Sequences

Define organisation-specific attack patterns:

```yaml
custom_sequences:
  - name: "Custom Recon"
    description: "Organisation-specific reconnaissance pattern"
    pattern:
      - method: "tools/list"
        required: true
      - method: "custom/internal"
        required: true
      - method: "tools/call"
        required: false
    confidence: 0.85
```

### Machine Learning Integration

Future releases will include ML-based detection:

```yaml
experimental:
  ml_detection:
    enabled: false  # Coming soon
    model_path: "/opt/mcpscan/models/threat_detection.pkl"
    confidence_boost: 0.1
```

This advanced traffic analysis provides enterprise-grade security monitoring for MCP environments, helping detect and prevent sophisticated attacks that would bypass traditional security measures.
