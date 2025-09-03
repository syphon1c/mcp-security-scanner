# MCP Security Scanner - Security Runbook

This runbook provides step-by-step procedures for security incident response, system monitoring, and operational security for MCP Security Scanner deployments.

## Table of Contents

1. [Incident Response](#incident-response)
2. [Security Monitoring](#security-monitoring)
3. [Threat Detection Procedures](#threat-detection-procedures)
4. [System Recovery](#system-recovery)
5. [Escalation Procedures](#escalation-procedures)
6. [Security Configuration](#security-configuration)
7. [Regular Security Tasks](#regular-security-tasks)

## Incident Response

### Critical Security Alert Response

When a **Critical** severity alert is detected by the MCP Security Scanner:

#### Immediate Actions (Within 5 minutes)

1. **Verify the Alert**
   ```bash
   # Check the proxy monitoring endpoint for details
   curl http://localhost:9081/monitor/alerts?severity=Critical
   
   # Review recent logs for context
   curl http://localhost:9081/monitor/logs?risk=Critical
   ```

2. **Isolate Affected Systems**
   ```bash
   # If using proxy mode, check if traffic was blocked
   # Look for "action": "blocked" in alert details
   
   # For unblocked threats, consider emergency blocking:
   # Stop the proxy temporarily if immediate threat
   pkill -f "mcpscan proxy"
   ```

3. **Document the Incident**
   - Timestamp of detection
   - Source IP/system involved
   - Type of attack detected
   - Evidence from scanner output
   - Actions taken

#### Investigation (Within 30 minutes)

1. **Analyze Attack Patterns**
   ```bash
   # Generate detailed scan report for affected MCP server
   ./mcpscan scan-local /path/to/mcp/server critical-security --output-dir ./incident-$(date +%Y%m%d-%H%M%S)
   
   # Check for persistence mechanisms
   grep -r "subprocess\|exec\|system\|eval" /path/to/mcp/server/
   ```

2. **Check System Integrity**
   ```bash
   # Verify no unauthorized changes to MCP server code
   git status  # If using version control
   find /path/to/mcp/server -type f -mtime -1  # Recent file changes
   ```

3. **Review Access Logs**
   ```bash
   # Check web server access logs for unusual patterns
   tail -n 1000 /var/log/nginx/access.log | grep -E "(POST|PUT)" 
   
   # Look for unusual user agents or request patterns
   tail -n 1000 /var/log/nginx/access.log | awk '{print $1}' | sort | uniq -c | sort -nr
   ```

#### Response Actions (Within 60 minutes)

1. **Containment**
   - Apply immediate patches if vulnerabilities found
   - Update security policies to block similar attacks
   - Consider rate limiting or IP blocking

2. **Eradication**
   ```bash
   # Remove any malicious code found
   # Restore from clean backups if necessary
   
   # Update MCP server dependencies
   pip install --upgrade package-name
   ```

3. **Recovery**
   ```bash
   # Restart services with monitoring
   ./mcpscan proxy http://localhost:8000 9081 critical-security
   
   # Verify functionality
   curl http://localhost:9081/monitor/health
   ```

### High Severity Alert Response

For **High** severity alerts (command injection, SQL injection, etc.):

1. **Quick Assessment** (Within 15 minutes)
   - Review alert details and evidence
   - Check if attack was successful
   - Determine scope of potential impact

2. **Implement Controls** (Within 30 minutes)
   - Update input validation
   - Apply emergency patches
   - Enhance monitoring for similar attacks

### Medium/Low Severity Alerts

1. **Daily Review Process**
   - Review accumulated alerts during business hours
   - Look for patterns or escalating threats
   - Update security policies as needed

2. **Weekly Analysis**
   - Generate trend reports
   - Review false positive rates
   - Tune detection rules

## Security Monitoring

### Real-Time Monitoring Dashboard

Set up continuous monitoring using the proxy API:

```bash
# Health check every 60 seconds
while true; do
    curl -s http://localhost:9081/monitor/health | jq '.status'
    sleep 60
done

# Alert monitoring script
#!/bin/bash
LAST_CHECK=$(date -d "1 hour ago" -Iseconds)
while true; do
    ALERTS=$(curl -s "http://localhost:9081/monitor/alerts?since=${LAST_CHECK}&severity=Critical,High")
    COUNT=$(echo $ALERTS | jq '.count')
    
    if [ "$COUNT" -gt 0 ]; then
        echo "⚠️  $COUNT new high-priority alerts detected"
        echo $ALERTS | jq '.alerts[]'
        # Send to SIEM/notification system
    fi
    
    LAST_CHECK=$(date -Iseconds)
    sleep 300  # Check every 5 minutes
done
```

### Key Metrics to Monitor

1. **Alert Volume**
   - Critical alerts: 0 per day (target)
   - High alerts: < 5 per day
   - Total alerts: < 50 per day

2. **System Performance**
   - Proxy response time: < 100ms
   - Queue sizes: < 1000 items
   - Memory usage: < 512MB

3. **False Positive Rate**
   - Target: < 5% for Critical/High alerts
   - Review weekly and tune policies

### SIEM Integration

Forward security events to your SIEM system:

```python
#!/usr/bin/env python3
import requests
import time
import json

def forward_to_siem(siem_endpoint, api_key):
    """Forward MCP security alerts to SIEM"""
    last_check = time.time() - 3600
    
    while True:
        try:
            # Get new alerts
            since = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(last_check))
            response = requests.get(
                'http://localhost:9081/monitor/alerts',
                params={'since': since, 'severity': 'Critical,High'}
            )
            
            if response.status_code == 200:
                data = response.json()
                for alert in data.get('alerts', []):
                    # Format for SIEM
                    siem_event = {
                        'source': 'mcp-security-scanner',
                        'timestamp': alert['timestamp'],
                        'severity': alert['severity'],
                        'category': 'security_alert',
                        'description': alert['description'],
                        'source_ip': alert['source'],
                        'evidence': alert['evidence'],
                        'action_taken': alert['action']
                    }
                    
                    # Send to SIEM
                    requests.post(
                        siem_endpoint,
                        headers={'Authorization': f'Bearer {api_key}'},
                        json=siem_event
                    )
            
            last_check = time.time()
            time.sleep(300)  # Check every 5 minutes
            
        except Exception as e:
            print(f"Error forwarding to SIEM: {e}")
            time.sleep(60)  # Wait before retry

# Usage
forward_to_siem('https://siem.company.com/api/events', 'your-api-key')
```

## Threat Detection Procedures

### Signature-Based Detection

1. **Command Injection Detection**
   ```bash
   # Look for patterns in MCP tool calls
   ./mcpscan scan-local /path/to/server critical-security | grep -i "command injection"
   
   # Check for suspicious subprocess usage
   grep -r "subprocess.*shell=True" /path/to/mcp/server/
   ```

2. **SQL Injection Detection**
   ```bash
   # Scan for SQL injection patterns
   ./mcpscan scan-local /path/to/server critical-security | grep -i "sql injection"
   
   # Manual check for dangerous queries
   grep -r "SELECT.*+\|INSERT.*+" /path/to/mcp/server/
   ```

### Behavioral Analysis

1. **Unusual MCP Tool Usage**
   ```bash
   # Monitor for new tools being called
   curl http://localhost:9081/monitor/logs | jq '.logs[] | select(.request.body.params.name)'
   
   # Check for unusual argument patterns
   curl http://localhost:9081/monitor/logs | jq '.logs[] | select(.risk == "High")'
   ```

2. **Traffic Pattern Analysis**
   ```bash
   # Look for high-frequency requests (potential automation)
   curl http://localhost:9081/monitor/logs | jq '.logs[].timestamp' | sort | uniq -c
   
   # Check for unusual HTTP methods
   curl http://localhost:9081/monitor/logs | jq '.logs[].method' | sort | uniq -c
   ```

## System Recovery

### Emergency Procedures

1. **Total System Compromise**
   ```bash
   # Stop all MCP-related services
   pkill -f mcpscan
   pkill -f mcp
   
   # Isolate the system
   iptables -A INPUT -j DROP
   iptables -A OUTPUT -j DROP
   
   # Preserve evidence
   cp -r /path/to/mcp/server /tmp/evidence-$(date +%Y%m%d-%H%M%S)
   
   # Contact incident response team
   ```

2. **Partial Compromise Recovery**
   ```bash
   # Restore from clean backup
   systemctl stop mcp-server
   rm -rf /path/to/mcp/server
   tar -xzf /backups/mcp-server-clean.tar.gz -C /path/to/
   
   # Verify integrity
   ./mcpscan scan-local /path/to/mcp/server critical-security
   
   # Restart with monitoring
   systemctl start mcp-server
   ./mcpscan proxy http://localhost:8000 9081 critical-security
   ```

### Data Recovery

1. **Configuration Recovery**
   ```bash
   # Restore security policies from backup
   cp /backups/policies/* ./policies/
   
   # Verify policy integrity
   for policy in ./policies/*.json; do
       echo "Checking $policy"
       python -m json.tool "$policy" > /dev/null && echo "✓ Valid" || echo "✗ Invalid"
   done
   ```

2. **Log Recovery**
   ```bash
   # Recover proxy logs if available
   journalctl -u mcpscan-proxy > /tmp/proxy-logs-$(date +%Y%m%d).log
   
   # Extract security events
   grep -E "(Critical|High)" /tmp/proxy-logs-*.log
   ```

## Escalation Procedures

### Alert Escalation Matrix

| Severity | Immediate Response | Escalation Time | Contact |
|----------|-------------------|-----------------|---------|
| Critical | Security Team Lead | Immediate | 24/7 phone + email |
| High | Security Analyst | 30 minutes | Email + Slack |
| Medium | SOC Analyst | 2 hours | Email |
| Low | Daily Review | Next business day | Email |

### Contact Information

```yaml
# Update with your organization's contacts
security_team:
  lead: 
    name: "Security Team Lead"
    phone: "+1-555-SECURITY"
    email: "security-lead@company.com"
  analyst:
    name: "Security Analyst"
    email: "security-analyst@company.com"
    slack: "@security-analyst"

operations:
  manager:
    name: "Operations Manager"
    phone: "+1-555-OPS-MGR"
    email: "ops-manager@company.com"

external:
  incident_response:
    name: "External IR Firm"
    phone: "+1-555-IR-FIRM"
    email: "emergency@ir-firm.com"
```

### Communication Templates

**Critical Incident Notification:**
```
Subject: [CRITICAL] MCP Security Incident - Immediate Attention Required

INCIDENT SUMMARY:
- Time: [timestamp]
- System: [affected MCP server]
- Threat Type: [e.g., Command Injection]
- Status: [Investigation/Containment/Recovery]

IMMEDIATE ACTIONS TAKEN:
- [list actions]

IMPACT ASSESSMENT:
- [describe potential impact]

NEXT STEPS:
- [planned actions]

Contact: [your contact info]
```

## Security Configuration

### Hardening Checklist

1. **MCP Server Security**
   ```bash
   # Check file permissions
   find /path/to/mcp/server -type f -perm /o+w
   
   # Verify no hardcoded secrets
   ./mcpscan scan-local /path/to/server critical-security | grep -i "credential\|password\|secret"
   
   # Check for unnecessary services
   netstat -tlnp | grep :80
   ```

2. **Proxy Security**
   ```bash
   # Run proxy with restricted user
   sudo -u mcpscan-user ./mcpscan proxy http://localhost:8000 9081 critical-security
   
   # Verify monitoring endpoints are protected
   curl -I http://localhost:9081/monitor/health
   ```

3. **Network Security**
   ```bash
   # Limit proxy access to monitoring network
   iptables -A INPUT -p tcp --dport 9081 -s 10.1.1.0/24 -j ACCEPT
   iptables -A INPUT -p tcp --dport 9081 -j DROP
   ```

### Security Policy Updates

1. **Regular Policy Review**
   ```bash
   # Monthly policy effectiveness review
   ./mcpscan scan-local /path/to/test/vulnerable critical-security > review-$(date +%Y%m).json
   
   # Compare with previous month's results
   # Update policies based on new threat intelligence
   ```

2. **Custom Rule Creation**
   ```json
   {
     "id": "CUSTOM_001",
     "title": "Organization Specific Threat",
     "category": "Custom",
     "severity": "High",
     "patterns": ["specific-threat-pattern"],
     "description": "Custom rule for organization-specific threats",
     "remediation": "Apply organization-specific mitigation"
   }
   ```

## Regular Security Tasks

### Daily Tasks

1. **Morning Security Review** (30 minutes)
   ```bash
   # Check overnight alerts
   curl "http://localhost:9081/monitor/alerts?since=$(date -d yesterday -Iseconds)"
   
   # Verify system health
   curl http://localhost:9081/monitor/health
   
   # Review high-risk transactions
   curl "http://localhost:9081/monitor/logs?risk=High,Critical"
   ```

2. **Evening Security Summary** (15 minutes)
   ```bash
   # Generate daily summary report
   ./scripts/daily-security-summary.sh
   
   # Update threat intelligence
   ./scripts/update-threat-patterns.sh
   ```

### Weekly Tasks

1. **Security Assessment** (2 hours)
   ```bash
   # Full security scan of all MCP servers
   for server in /path/to/mcp/servers/*; do
       ./mcpscan scan-local "$server" critical-security --output-dir "./weekly-scans/$(basename $server)"
   done
   
   # Trend analysis
   ./scripts/weekly-trend-analysis.sh
   ```

2. **Policy Tuning** (1 hour)
   ```bash
   # Review false positives
   grep "false positive" /var/log/mcpscan/*.log
   
   # Update policies based on feedback
   # Test policy changes in staging environment
   ```

### Monthly Tasks

1. **Security Review** (4 hours)
   - Review incident response effectiveness
   - Update contact information
   - Test escalation procedures
   - Update security policies
   - Review and update this runbook

2. **Threat Intelligence Update** (2 hours)
   - Research new MCP-specific threats
   - Update detection patterns
   - Share threat intelligence with community

## Appendix

### Log Locations

```bash
# MCP Security Scanner logs
/var/log/mcpscan/scanner.log
/var/log/mcpscan/proxy.log

# System logs
/var/log/syslog
/var/log/auth.log

# Application logs (adjust paths as needed)
/var/log/nginx/access.log
/var/log/nginx/error.log
```

### Useful Commands

```bash
# Quick security check
./mcpscan scan-local . critical-security --output-file quick-check.json

# Monitor proxy in real-time
watch -n 5 'curl -s http://localhost:9081/monitor/health | jq'

# Search for specific threat patterns
grep -r "exec\|system\|subprocess" /path/to/mcp --include="*.py"

# Check for recent file modifications
find /path/to/mcp -type f -mtime -1 -exec ls -la {} \;
```

### Emergency Contacts

Keep this information updated and easily accessible:

- **Internal Security Team**: [phone] / [email]
- **External Incident Response**: [phone] / [email]  
- **Management Escalation**: [phone] / [email]
- **Legal/Compliance**: [phone] / [email]

---

**Document Version**: 1.0  
**Last Updated**: September 2025  
**Next Review**: December 2025
