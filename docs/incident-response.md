# MCP Security Scanner - Incident Response Guide

This guide provides detailed procedures for responding to security incidents detected by the MCP Security Scanner. It covers threat classification, response procedures, and post-incident analysis.

## Quick Reference

### Incident Severity Matrix

| Severity | Description | Response Time | Examples |
|----------|-------------|---------------|----------|
| **Critical** | Active exploitation, immediate threat | 5 minutes | Command injection executed, SQL injection successful |
| **High** | High-probability attack, potential for exploitation | 30 minutes | Command injection attempt blocked, hardcoded credentials |
| **Medium** | Suspicious activity, needs investigation | 2 hours | Path traversal attempt, unusual MCP tool usage |
| **Low** | Policy violation, informational | 24 hours | Deprecated function usage, weak encryption |


## Incident Classification

### Critical Incidents

**Characteristics:**
- Evidence of successful attack execution
- Active command injection or code execution
- Data exfiltration in progress
- System compromise confirmed

**Examples from MCP Scanner:**
```json
{
  "severity": "Critical",
  "alertType": "Command Injection",
  "description": "Successful command execution detected",
  "evidence": "subprocess.run('rm -rf /', shell=True)",
  "action": "logged"
}
```

**Immediate Response Required:**
1. Isolate affected systems
2. Preserve evidence
3. Activate incident response team
4. Begin containment procedures

### High Severity Incidents

**Characteristics:**
- Attack attempts blocked by security controls
- Discovery of critical vulnerabilities
- Privilege escalation attempts
- Unauthorized access attempts

**Examples:**
```json
{
  "severity": "High", 
  "alertType": "SQL Injection",
  "description": "SQL injection attempt blocked",
  "evidence": "SELECT * FROM users WHERE id = '1' OR '1'='1'",
  "action": "blocked"
}
```

**Response Actions:**
1. Verify blocking effectiveness
2. Investigate attack source
3. Implement additional controls
4. Monitor for follow-up attacks

## Incident Response Procedures

### Phase 1: Preparation and Detection

#### Automated Detection Setup

```bash
#!/bin/bash
# Real-time monitoring script for critical alerts

PROXY_URL="http://localhost:9081"
ALERT_WEBHOOK="https://your-siem.com/webhook"

while true; do
    # Check for new critical alerts
    ALERTS=$(curl -s "${PROXY_URL}/monitor/alerts?severity=Critical&since=$(date -d '5 minutes ago' -Iseconds)")
    COUNT=$(echo "$ALERTS" | jq '.count // 0')
    
    if [ "$COUNT" -gt 0 ]; then
        echo "🚨 CRITICAL ALERT DETECTED - $COUNT alerts"
        
        # Send to SIEM
        curl -X POST "$ALERT_WEBHOOK" \
             -H "Content-Type: application/json" \
             -d "$ALERTS"
        
        # Page incident commander
        echo "$ALERTS" | ./scripts/send-page.sh
        
        # Log incident start
        echo "$(date): Critical incident detected - $COUNT alerts" >> /var/log/incidents.log
    fi
    
    sleep 30
done
```

#### Preparation Checklist

- [ ] Incident response team contacts updated
- [ ] Backup systems ready and tested
- [ ] Forensic tools available
- [ ] Network isolation procedures documented
- [ ] Communication channels tested

### Phase 2: Identification and Analysis

#### Critical Incident Analysis

When a critical alert is detected:

```bash
#!/bin/bash
# Critical incident analysis script

INCIDENT_ID="INC-$(date +%Y%m%d-%H%M%S)"
EVIDENCE_DIR="/tmp/incident-${INCIDENT_ID}"

echo "🔍 Starting critical incident analysis: ${INCIDENT_ID}"

# Create evidence directory
mkdir -p "$EVIDENCE_DIR"

# 1. Capture current system state
echo "📸 Capturing system state..."
curl -s http://localhost:9081/monitor/health > "$EVIDENCE_DIR/proxy-health.json"
curl -s http://localhost:9081/monitor/alerts > "$EVIDENCE_DIR/all-alerts.json"
curl -s http://localhost:9081/monitor/logs > "$EVIDENCE_DIR/recent-logs.json"

# 2. Get detailed alert information
echo "🔍 Analyzing critical alerts..."
curl -s "http://localhost:9081/monitor/alerts?severity=Critical" | \
    jq '.alerts[]' > "$EVIDENCE_DIR/critical-alerts.json"

# 3. Extract attack details
echo "📋 Extracting attack details..."
while read -r alert; do
    SOURCE=$(echo "$alert" | jq -r '.source')
    EVIDENCE=$(echo "$alert" | jq -r '.evidence')
    TIMESTAMP=$(echo "$alert" | jq -r '.timestamp')
    
    echo "Attack from: $SOURCE at $TIMESTAMP" >> "$EVIDENCE_DIR/attack-summary.txt"
    echo "Evidence: $EVIDENCE" >> "$EVIDENCE_DIR/attack-summary.txt"
    echo "---" >> "$EVIDENCE_DIR/attack-summary.txt"
done < "$EVIDENCE_DIR/critical-alerts.json"

# 4. Check for persistence mechanisms
echo "🔎 Checking for persistence..."
find /path/to/mcp/server -type f -name "*.py" -exec grep -l "exec\|eval\|subprocess" {} \; > "$EVIDENCE_DIR/suspicious-files.txt"

# 5. Network analysis
echo "🌐 Analyzing network connections..."
netstat -an | grep :8000 > "$EVIDENCE_DIR/network-connections.txt"

# 6. Process analysis
echo "⚙️ Analyzing running processes..."
ps aux | grep -E "(python|node|mcp)" > "$EVIDENCE_DIR/processes.txt"

echo "✅ Initial analysis complete. Evidence saved to: $EVIDENCE_DIR"
echo "📧 Sending analysis to incident team..."

# Send summary to incident team
{
    echo "Subject: CRITICAL INCIDENT $INCIDENT_ID - Initial Analysis"
    echo "To: incident-team@company.com"
    echo ""
    echo "Critical MCP security incident detected."
    echo ""
    echo "Evidence location: $EVIDENCE_DIR"
    echo ""
    cat "$EVIDENCE_DIR/attack-summary.txt"
} | sendmail incident-team@company.com
```

#### Threat Intelligence Gathering

```python
#!/usr/bin/env python3
"""
Threat intelligence analysis for MCP incidents
"""
import json
import requests
import hashlib
from datetime import datetime

def analyze_attack_patterns(evidence_dir):
    """Analyze attack patterns and correlate with threat intelligence"""
    
    # Load critical alerts
    with open(f"{evidence_dir}/critical-alerts.json", 'r') as f:
        alerts = [json.loads(line) for line in f]
    
    threat_intel = []
    
    for alert in alerts:
        evidence = alert.get('evidence', '')
        source_ip = alert.get('source', '')
        
        # Hash evidence for IOC tracking
        evidence_hash = hashlib.sha256(evidence.encode()).hexdigest()
        
        # Check against known attack patterns
        if 'subprocess.run' in evidence and 'shell=True' in evidence:
            threat_intel.append({
                'type': 'Command Injection',
                'confidence': 'High',
                'evidence_hash': evidence_hash,
                'source_ip': source_ip,
                'technique': 'T1059.006',  # MITRE ATT&CK
                'description': 'Python subprocess command injection'
            })
        
        elif 'SELECT' in evidence and ("'" in evidence or '"' in evidence):
            threat_intel.append({
                'type': 'SQL Injection',
                'confidence': 'High', 
                'evidence_hash': evidence_hash,
                'source_ip': source_ip,
                'technique': 'T1190',  # MITRE ATT&CK
                'description': 'SQL injection attempt'
            })
    
    # Save threat intelligence
    with open(f"{evidence_dir}/threat-intel.json", 'w') as f:
        json.dump(threat_intel, f, indent=2)
    
    return threat_intel

def check_reputation(ip_address):
    """Check IP reputation against threat feeds"""
    # This would integrate with real threat intel feeds
    reputation_sources = [
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}",
        f"https://api.virustotal.com/vtapi/v2/ip-address/report?ip={ip_address}"
    ]
    
    # In a real implementation, you'd call these APIs
    # For now, return mock data
    return {
        'ip': ip_address,
        'reputation': 'unknown',
        'sources_checked': len(reputation_sources)
    }

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 threat_intel.py <evidence_directory>")
        sys.exit(1)
    
    evidence_dir = sys.argv[1]
    threat_intel = analyze_attack_patterns(evidence_dir)
    
    print(f"Found {len(threat_intel)} threat indicators")
    for intel in threat_intel:
        print(f"- {intel['type']}: {intel['description']}")
```

### Phase 3: Containment

#### Immediate Containment Actions

```bash
#!/bin/bash
# Emergency containment script

INCIDENT_ID="$1"
EVIDENCE_DIR="/tmp/incident-${INCIDENT_ID}"

echo "🚨 Starting emergency containment for incident: $INCIDENT_ID"

# 1. Stop proxy if necessary (extreme cases only)
read -p "Stop MCP proxy immediately? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🛑 Stopping MCP proxy..."
    pkill -f "mcpscan proxy"
    echo "$(date): Emergency proxy stop - $INCIDENT_ID" >> /var/log/incidents.log
fi

# 2. Block suspicious IPs
echo "🚫 Reviewing IPs for blocking..."
if [ -f "$EVIDENCE_DIR/critical-alerts.json" ]; then
    SUSPICIOUS_IPS=$(jq -r '.source' "$EVIDENCE_DIR/critical-alerts.json" | sort | uniq)
    
    for IP in $SUSPICIOUS_IPS; do
        if [[ "$IP" != "localhost" && "$IP" != "127.0.0.1" ]]; then
            read -p "Block IP $IP? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                iptables -A INPUT -s "$IP" -j DROP
                echo "Blocked IP: $IP" >> "$EVIDENCE_DIR/blocked-ips.txt"
                echo "$(date): Blocked IP $IP - $INCIDENT_ID" >> /var/log/incidents.log
            fi
        fi
    done
fi

# 3. Isolate MCP server (if needed)
read -p "Isolate MCP server from network? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🔒 Isolating MCP server..."
    # Allow only essential management traffic
    iptables -A INPUT -p tcp --dport 22 -s 10.1.1.0/24 -j ACCEPT  # SSH from mgmt network
    iptables -A INPUT -p tcp --dport 9081 -s 10.1.1.0/24 -j ACCEPT  # Monitoring
    iptables -A INPUT -j DROP
    echo "$(date): Network isolation applied - $INCIDENT_ID" >> /var/log/incidents.log
fi

# 4. Create system snapshot
echo "📸 Creating system snapshot..."
tar -czf "$EVIDENCE_DIR/system-snapshot.tar.gz" \
    /path/to/mcp/server \
    /var/log/mcpscan \
    /etc/mcpscan 2>/dev/null

echo "✅ Emergency containment complete for incident: $INCIDENT_ID"
```

#### Short-term Containment

```bash
#!/bin/bash
# Short-term containment and hardening

INCIDENT_ID="$1"

echo "🔧 Implementing short-term containment measures..."

# 1. Update security policies with new patterns
echo "📝 Updating security policies..."
ATTACK_PATTERNS=$(jq -r '.evidence' "/tmp/incident-${INCIDENT_ID}/critical-alerts.json" | head -5)

# Create emergency policy update
cat > "./policies/emergency-${INCIDENT_ID}.json" << EOF
{
  "version": "1.0",
  "policyName": "emergency-${INCIDENT_ID}",
  "description": "Emergency policy for incident ${INCIDENT_ID}",
  "severity": "Critical",
  "rules": [
    {
      "id": "EMRG_001",
      "title": "Emergency Block Pattern",
      "category": "Emergency Response",
      "severity": "Critical",
      "patterns": [
        "$(echo "$ATTACK_PATTERNS" | head -1 | sed 's/[[\.*^$()+?{|]/\\&/g')"
      ],
      "description": "Emergency pattern blocking for active incident",
      "remediation": "Block immediately and investigate"
    }
  ],
  "blockedPatterns": [
    "$(echo "$ATTACK_PATTERNS" | sed 's/[[\.*^$()+?{|]/\\&/g')"
  ],
  "riskThresholds": {
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 1
  }
}
EOF

# 2. Restart proxy with monitoring
echo "🔄 Restarting proxy with monitoring..."
./mcpscan proxy http://localhost:8000 9081 "emergency-${INCIDENT_ID}" &
PROXY_PID=$!

# 3. Logging
echo "📋 Enabling logging..."
tail -f /var/log/mcpscan/proxy.log | while read line; do
    echo "$(date): $line" >> "/var/log/incidents/${INCIDENT_ID}.log"
done &

echo "✅ Short-term containment implemented for incident: $INCIDENT_ID"
echo "🔍 Monitor progress: tail -f /var/log/incidents/${INCIDENT_ID}.log"
```

### Phase 4: Eradication

#### Vulnerability Remediation

```bash
#!/bin/bash
# Vulnerability eradication script

INCIDENT_ID="$1"
EVIDENCE_DIR="/tmp/incident-${INCIDENT_ID}"

echo "🧹 Starting eradication phase for incident: $INCIDENT_ID"

# 1. Identify root causes
echo "🔍 Identifying root causes..."
./mcpscan scan-local /path/to/mcp/server critical-security \
    --output-file "$EVIDENCE_DIR/post-incident-scan.json"

# 2. Apply security patches
echo "🔧 Applying security patches..."

# Update MCP server dependencies
if [ -f "/path/to/mcp/server/requirements.txt" ]; then
    echo "📦 Updating Python dependencies..."
    pip install --upgrade -r /path/to/mcp/server/requirements.txt
fi

# Fix identified vulnerabilities
python3 << 'EOF'
import json
import os
import re

# Load scan results
with open(os.environ['EVIDENCE_DIR'] + '/post-incident-scan.json', 'r') as f:
    scan_results = json.load(f)

findings = scan_results.get('findings', [])
critical_findings = [f for f in findings if f['severity'] == 'Critical']

print(f"Found {len(critical_findings)} critical vulnerabilities to fix:")

for finding in critical_findings:
    file_path = finding['filePath']
    line_num = finding['lineNumber']
    rule_id = finding['ruleID']
    
    print(f"- {rule_id} in {file_path}:{line_num}")
    
    # Auto-fix common patterns (be very careful with this!)
    if rule_id == "CMD_001" and "shell=True" in finding['evidence']:
        print(f"  ⚠️  Manual fix required: Remove shell=True from {file_path}")
    elif rule_id == "SQL_001":
        print(f"  ⚠️  Manual fix required: Use parameterized queries in {file_path}")
    elif rule_id.startswith("CRED_"):
        print(f"  ⚠️  Manual fix required: Remove hardcoded credentials from {file_path}")
EOF

# 3. Remove malicious code (if any)
echo "🗑️  Checking for malicious code..."
MALICIOUS_FILES=$(grep -r "rm -rf\|curl.*|.*sh\|wget.*|.*sh" /path/to/mcp/server --include="*.py" -l || true)

if [ -n "$MALICIOUS_FILES" ]; then
    echo "⚠️  Potential malicious code found in:"
    echo "$MALICIOUS_FILES"
    
    for file in $MALICIOUS_FILES; do
        echo "Review file: $file"
        read -p "Remove this file? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            mv "$file" "$EVIDENCE_DIR/removed-$(basename $file)"
            echo "Moved $file to evidence directory"
        fi
    done
fi

# 4. Update security configurations
echo "🔒 Updating security configurations..."

# Create hardened configuration
cat > "/path/to/mcp/server/security.conf" << EOF
# Security configuration added after incident $INCIDENT_ID

# Disable dangerous functions
DISABLE_SUBPROCESS_SHELL = True
DISABLE_EXEC_EVAL = True
ENABLE_INPUT_VALIDATION = True

# Logging
SECURITY_LOGGING = True
LOG_ALL_REQUESTS = True
LOG_LEVEL = DEBUG

# Rate limiting
ENABLE_RATE_LIMIT = True
MAX_REQUESTS_PER_MINUTE = 60

# Input sanitization
ENABLE_INPUT_SANITIZATION = True
BLOCK_SPECIAL_CHARS = True
EOF

echo "✅ Eradication phase complete for incident: $INCIDENT_ID"
```

### Phase 5: Recovery

#### System Recovery Procedures

```bash
#!/bin/bash
# System recovery script

INCIDENT_ID="$1"
EVIDENCE_DIR="/tmp/incident-${INCIDENT_ID}"

echo "🔄 Starting recovery phase for incident: $INCIDENT_ID"

# 1. Verify system integrity
echo "🔍 Verifying system integrity..."
./mcpscan scan-local /path/to/mcp/server critical-security \
    --output-file "$EVIDENCE_DIR/recovery-scan.json"

CRITICAL_COUNT=$(jq '.summary.criticalCount' "$EVIDENCE_DIR/recovery-scan.json")

if [ "$CRITICAL_COUNT" -gt 0 ]; then
    echo "❌ Critical vulnerabilities still present. Recovery cannot proceed."
    echo "Critical issues: $CRITICAL_COUNT"
    jq '.findings[] | select(.severity == "Critical")' "$EVIDENCE_DIR/recovery-scan.json"
    exit 1
fi

echo "✅ No critical vulnerabilities found. Proceeding with recovery."

# 2. Gradual service restoration
echo "🔄 Gradual service restoration..."

# Start with monitoring only
echo "Starting monitoring-only mode..."
./mcpscan proxy http://localhost:8000 9081 critical-security --monitor-only &
MONITOR_PID=$!

# Test connectivity
sleep 10
if curl -s http://localhost:9081/monitor/health | jq -e '.status == "healthy"' > /dev/null; then
    echo "✅ Monitoring service healthy"
else
    echo "❌ Monitoring service failed to start"
    kill $MONITOR_PID 2>/dev/null
    exit 1
fi

# 3. Limited traffic restoration
echo "🚦 Starting limited traffic restoration..."
kill $MONITOR_PID 2>/dev/null

# Start with strict policy
./mcpscan proxy http://localhost:8000 9081 critical-security &
PROXY_PID=$!

# Monitor for 5 minutes
echo "🔍 Monitoring system behavior for 5 minutes..."
for i in {1..30}; do
    sleep 10
    HEALTH=$(curl -s http://localhost:9081/monitor/health)
    QUEUE_SIZE=$(echo "$HEALTH" | jq '.alerts_queue_size')
    
    if [ "$QUEUE_SIZE" -gt 10 ]; then
        echo "⚠️  High alert queue size: $QUEUE_SIZE"
        echo "Recent alerts:"
        curl -s "http://localhost:9081/monitor/alerts?limit=5" | jq '.alerts[]'
    fi
    
    echo "Monitoring check $i/30: Queue size $QUEUE_SIZE"
done

# 4. Full service restoration
echo "🌟 Full service restoration..."

# Check if everything looks good
RECENT_ALERTS=$(curl -s "http://localhost:9081/monitor/alerts?since=$(date -d '5 minutes ago' -Iseconds)" | jq '.count')

if [ "$RECENT_ALERTS" -gt 5 ]; then
    echo "⚠️  High number of recent alerts: $RECENT_ALERTS"
    read -p "Continue with full restoration? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborting full restoration"
        exit 1
    fi
fi

echo "✅ System recovery complete for incident: $INCIDENT_ID"

# 5. Post-recovery validation
echo "🔍 Post-recovery validation..."

# Run comprehensive scan
./mcpscan scan-local /path/to/mcp/server critical-security \
    --all-formats \
    --output-dir "$EVIDENCE_DIR/post-recovery"

# Generate recovery report
cat > "$EVIDENCE_DIR/recovery-report.md" << EOF
# Recovery Report - Incident $INCIDENT_ID

## Recovery Summary
- **Incident ID**: $INCIDENT_ID
- **Recovery Start**: $(date)
- **Recovery Status**: ✅ Complete
- **Final Scan Results**: $(jq '.summary' "$EVIDENCE_DIR/post-recovery/"*.json)

## Services Restored
- [x] MCP Security Proxy
- [x] Monitoring Endpoints  
- [x] Security Scanning
- [x] Alert Processing

## Validation Results
- Critical Vulnerabilities: 0
- High Vulnerabilities: $(jq '.summary.highCount' "$EVIDENCE_DIR/post-recovery/"*.json)
- System Health: Healthy

## Next Steps
1. Continue monitoring for 24 hours
2. Review and update security policies
3. Conduct lessons learned session
4. Update incident response procedures

---
Generated: $(date)
EOF

echo "📋 Recovery report generated: $EVIDENCE_DIR/recovery-report.md"
```

### Phase 6: Lessons Learned

#### Post-Incident Analysis Template

```markdown
# Post-Incident Analysis - {{INCIDENT_ID}}

## Incident Summary

**Incident ID**: {{INCIDENT_ID}}
**Date/Time**: {{INCIDENT_DATETIME}}
**Duration**: {{INCIDENT_DURATION}}
**Severity**: {{INCIDENT_SEVERITY}}
**Status**: Closed

## Timeline of Events

| Time | Event | Action Taken | By Whom |
|------|-------|--------------|---------|
| {{TIME1}} | Initial detection | Alert generated by MCP Scanner | Automated |
| {{TIME2}} | First response | Investigation started | {{RESPONDER1}} |
| {{TIME3}} | Containment | Traffic blocked, systems isolated | {{RESPONDER2}} |
| {{TIME4}} | Eradication | Vulnerabilities patched | {{RESPONDER3}} |
| {{TIME5}} | Recovery | Services restored | {{RESPONDER4}} |

## Root Cause Analysis

### Primary Cause
{{ROOT_CAUSE_DESCRIPTION}}

### Contributing Factors
1. {{FACTOR1}}
2. {{FACTOR2}}
3. {{FACTOR3}}

### Evidence
- Scanner detection: {{SCANNER_EVIDENCE}}
- Log analysis: {{LOG_EVIDENCE}}
- System artifacts: {{SYSTEM_EVIDENCE}}

## Impact Assessment

### Systems Affected
- {{AFFECTED_SYSTEM1}}
- {{AFFECTED_SYSTEM2}}

### Business Impact
- Downtime: {{DOWNTIME_DURATION}}
- Data exposure: {{DATA_IMPACT}}
- Financial impact: {{FINANCIAL_IMPACT}}

### Technical Impact
- Security controls effectiveness: {{CONTROLS_ASSESSMENT}}
- Detection capabilities: {{DETECTION_ASSESSMENT}}
- Response time: {{RESPONSE_TIME_ASSESSMENT}}

## Response Effectiveness

### What Went Well
1. {{SUCCESS1}}
2. {{SUCCESS2}}
3. {{SUCCESS3}}

### What Could Be Improved
1. {{IMPROVEMENT1}}
2. {{IMPROVEMENT2}}
3. {{IMPROVEMENT3}}

## Action Items

| Action | Owner | Due Date | Status |
|--------|-------|----------|--------|
| {{ACTION1}} | {{OWNER1}} | {{DATE1}} | {{STATUS1}} |
| {{ACTION2}} | {{OWNER2}} | {{DATE2}} | {{STATUS2}} |
| {{ACTION3}} | {{OWNER3}} | {{DATE3}} | {{STATUS3}} |

## Recommendations

### Immediate (1-2 weeks)
1. {{IMMEDIATE_REC1}}
2. {{IMMEDIATE_REC2}}

### Short-term (1-3 months)
1. {{SHORT_TERM_REC1}}
2. {{SHORT_TERM_REC2}}

### Long-term (3-12 months)
1. {{LONG_TERM_REC1}}
2. {{LONG_TERM_REC2}}

## Policy Updates

### Security Policies
- {{POLICY_UPDATE1}}
- {{POLICY_UPDATE2}}

### Detection Rules
- {{RULE_UPDATE1}}
- {{RULE_UPDATE2}}

### Procedure Updates
- {{PROCEDURE_UPDATE1}}
- {{PROCEDURE_UPDATE2}}

---

**Analysis completed by**: {{ANALYST_NAME}}
**Date**: {{ANALYSIS_DATE}}
**Review approved by**: {{APPROVER_NAME}}
```

#### Automated Lessons Learned Generator

```python
#!/usr/bin/env python3
"""
Generate lessons learned report from incident data
"""
import json
import sys
from datetime import datetime

def generate_lessons_learned(incident_dir):
    """Generate lessons learned report from incident evidence"""
    
    # Load incident data
    with open(f"{incident_dir}/critical-alerts.json", 'r') as f:
        alerts = [json.loads(line) for line in f]
    
    with open(f"{incident_dir}/attack-summary.txt", 'r') as f:
        attack_summary = f.read()
    
    # Analyze response effectiveness
    response_data = analyze_response_time(incident_dir)
    detection_data = analyze_detection_effectiveness(alerts)
    
    # Generate report
    report = {
        'incident_id': incident_dir.split('/')[-1],
        'analysis_date': datetime.now().isoformat(),
        'attack_patterns': extract_attack_patterns(alerts),
        'response_effectiveness': response_data,
        'detection_effectiveness': detection_data,
        'recommendations': generate_recommendations(alerts, response_data, detection_data)
    }
    
    # Save report
    with open(f"{incident_dir}/lessons-learned.json", 'w') as f:
        json.dump(report, f, indent=2)
    
    return report

def analyze_response_time(incident_dir):
    """Analyze incident response timing"""
    # This would parse timestamps from logs and calculate response times
    return {
        'detection_to_response': '5 minutes',
        'containment_time': '15 minutes',
        'total_resolution': '2 hours',
        'effectiveness_score': 85
    }

def analyze_detection_effectiveness(alerts):
    """Analyze how well the scanner detected threats"""
    total_alerts = len(alerts)
    critical_alerts = len([a for a in alerts if a.get('severity') == 'Critical'])
    blocked_attacks = len([a for a in alerts if a.get('action') == 'blocked'])
    
    return {
        'total_alerts': total_alerts,
        'critical_alerts': critical_alerts,
        'blocked_percentage': (blocked_attacks / total_alerts * 100) if total_alerts > 0 else 0,
        'false_positive_rate': 0,  # Would calculate from manual review
        'time_to_detection': '< 30 seconds'
    }

def extract_attack_patterns(alerts):
    """Extract common attack patterns for policy updates"""
    patterns = []
    for alert in alerts:
        evidence = alert.get('evidence', '')
        if 'subprocess' in evidence:
            patterns.append('subprocess command injection')
        if 'SELECT' in evidence:
            patterns.append('SQL injection')
        # Add more pattern extraction logic
    
    return list(set(patterns))

def generate_recommendations(alerts, response_data, detection_data):
    """Generate recommendations based on incident analysis"""
    recommendations = []
    
    # Detection improvements
    if detection_data['blocked_percentage'] < 80:
        recommendations.append({
            'category': 'Detection',
            'priority': 'High',
            'recommendation': 'Improve blocking policies - only {}% of attacks were blocked'.format(
                detection_data['blocked_percentage']
            )
        })
    
    # Response improvements
    if 'minutes' in response_data['detection_to_response'] and int(response_data['detection_to_response'].split()[0]) > 10:
        recommendations.append({
            'category': 'Response',
            'priority': 'Medium', 
            'recommendation': 'Improve automated response time - currently taking {} to respond'.format(
                response_data['detection_to_response']
            )
        })
    
    # Policy improvements
    attack_patterns = extract_attack_patterns(alerts)
    if attack_patterns:
        recommendations.append({
            'category': 'Policy',
            'priority': 'High',
            'recommendation': 'Add specific patterns for: {}'.format(', '.join(attack_patterns))
        })
    
    return recommendations

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 lessons_learned.py <incident_directory>")
        sys.exit(1)
    
    incident_dir = sys.argv[1]
    report = generate_lessons_learned(incident_dir)
    
    print(f"Lessons learned report generated for: {report['incident_id']}")
    print(f"Key recommendations: {len(report['recommendations'])}")
    for rec in report['recommendations']:
        print(f"- [{rec['priority']}] {rec['category']}: {rec['recommendation']}")
```

## Quick Reference Cards

### Critical Incident Checklist

```
□ Alert confirmed and classified
□ Incident commander notified
□ Evidence preservation started
□ Systems isolated (if needed)
□ Attack source identified
□ Containment measures applied
□ Stakeholders notified
□ Recovery plan initiated
□ Post-incident analysis scheduled
```

### Common MCP Attack Indicators

```
🚨 Command Injection
- subprocess.run(..., shell=True)
- os.system()
- exec() / eval()

🚨 SQL Injection  
- Dynamic query construction
- Unescaped user input in queries
- Error-based injection attempts

🚨 Path Traversal
- ../ sequences
- Encoded traversal attempts
- Absolute path manipulation

🚨 Information Disclosure
- Hardcoded credentials
- Debug information leakage
- Sensitive data in logs
```

---

**Document Version**: 1.0
**Last Updated**: September 2025
**Emergency Contact**: +1-555-SOC-HELP
