# MCP Security Policy Examples

This document provides examples of security policies for different use cases and environments. These policies can be customised and extended based on specific requirements.

## Policy Structure Overview

All MCP security policies follow a standardised JSON structure:

```json
{
  "policyName": "policy-identifier",
  "version": "1.0",
  "description": "Policy description",
  "rules": [...],
  "blockedPatterns": [...],
  "riskThresholds": {...},
  "settings": {...}
}
```

## Basic Security Policy

A minimal security policy for general MCP server protection:

```json
{
  "policyName": "basic-security",
  "version": "1.0",
  "description": "Basic security policy for MCP servers",
  "rules": [
    {
      "id": "INJECTION_001",
      "name": "Command Injection Detection",
      "patterns": [
        "exec\\s*\\(",
        "system\\s*\\(",
        "subprocess\\.(run|call|Popen)"
      ],
      "severity": "Critical",
      "description": "Detects potential command injection vulnerabilities"
    },
    {
      "id": "PATH_001",
      "name": "Path Traversal Detection",
      "patterns": [
        "\\.\\./",
        "%2e%2e%2f",
        "\\\\\\.\\.\\\\",
        "file:///"
      ],
      "severity": "High",
      "description": "Detects path traversal attempts"
    }
  ],
  "blockedPatterns": [
    "rm\\s+-rf",
    "format\\s+c:",
    "shutdown\\s+",
    "reboot"
  ],
  "riskThresholds": {
    "critical": 50,
    "high": 30,
    "medium": 15,
    "low": 5
  }
}
```

## Enterprise Security Policy

Security policy for enterprise environments:

```json
{
  "policyName": "enterprise-security",
  "version": "1.0",
  "description": "Enterprise-grade security policy with strict controls",
  "rules": [
    {
      "id": "DATA_001",
      "name": "Sensitive Data Pattern Detection",
      "patterns": [
        "(?i)(password|passwd|pwd)\\s*[=:]\\s*['\"][^'\"]{3,}['\"]",
        "(?i)(api[_-]?key|apikey)\\s*[=:]\\s*['\"][^'\"]{10,}['\"]",
        "(?i)(secret|token)\\s*[=:]\\s*['\"][^'\"]{8,}['\"]",
        "-----BEGIN\\s+(RSA\\s+)?PRIVATE\\s+KEY-----"
      ],
      "severity": "Critical",
      "description": "Detects embedded secrets and credentials"
    },
    {
      "id": "NETWORK_001",
      "name": "Network Access Detection",
      "patterns": [
        "requests\\.(get|post|put|delete)",
        "urllib\\.request",
        "http\\.client",
        "socket\\.(socket|connect)"
      ],
      "severity": "Medium",
      "description": "Monitors network communication attempts"
    },
    {
      "id": "CRYPTO_001",
      "name": "Weak Cryptography Detection",
      "patterns": [
        "md5\\(",
        "sha1\\(",
        "DES\\(",
        "RC4\\(",
        "ssl_verify\\s*=\\s*False"
      ],
      "severity": "High",
      "description": "Detects use of weak cryptographic algorithms"
    }
  ],
  "blockedPatterns": [
    "eval\\s*\\(",
    "exec\\s*\\(",
    "__import__\\s*\\(",
    "compile\\s*\\("
  ],
  "riskThresholds": {
    "critical": 40,
    "high": 25,
    "medium": 10,
    "low": 1
  },
  "settings": {
    "strictMode": true,
    "blockOnCritical": true,
    "requireApproval": ["Critical", "High"]
  }
}
```

## Development Environment Policy

Relaxed policy for development environments:

```json
{
  "policyName": "development-security",
  "version": "1.0",
  "description": "Development-friendly security policy with warnings",
  "rules": [
    {
      "id": "DEV_001",
      "name": "Debug Code Detection",
      "patterns": [
        "console\\.log\\(",
        "print\\s*\\(",
        "debugger;",
        "TODO:",
        "FIXME:",
        "XXX:"
      ],
      "severity": "Low",
      "description": "Detects debug code and development comments"
    },
    {
      "id": "DEV_002",
      "name": "Test Credentials Detection",
      "patterns": [
        "test_password",
        "admin/admin",
        "user:password",
        "123456"
      ],
      "severity": "Medium",
      "description": "Detects common test credentials"
    }
  ],
  "blockedPatterns": [],
  "riskThresholds": {
    "critical": 60,
    "high": 40,
    "medium": 20,
    "low": 1
  },
  "settings": {
    "strictMode": false,
    "blockOnCritical": false,
    "warningsOnly": true
  }
}
```

## Financial Services Policy

Specialised policy for financial sector compliance:

```json
{
  "policyName": "financial-security",
  "version": "1.0",
  "description": "Financial services security policy with PCI-DSS compliance",
  "rules": [
    {
      "id": "PCI_001",
      "name": "Credit Card Number Detection",
      "patterns": [
        "\\b4[0-9]{12}(?:[0-9]{3})?\\b",
        "\\b5[1-5][0-9]{14}\\b",
        "\\b3[47][0-9]{13}\\b",
        "\\b6(?:011|5[0-9]{2})[0-9]{12}\\b"
      ],
      "severity": "Critical",
      "description": "Detects credit card number patterns"
    },
    {
      "id": "PCI_002",
      "name": "Financial Data Patterns",
      "patterns": [
        "(?i)(ssn|social.security)\\s*[=:]\\s*[0-9]{3}-?[0-9]{2}-?[0-9]{4}",
        "(?i)(account.number|acct.num)\\s*[=:]\\s*[0-9]{8,}",
        "(?i)(routing.number)\\s*[=:]\\s*[0-9]{9}"
      ],
      "severity": "Critical",
      "description": "Detects financial data patterns"
    }
  ],
  "blockedPatterns": [
    "\\b4[0-9]{12}(?:[0-9]{3})?\\b",
    "\\b5[1-5][0-9]{14}\\b"
  ],
  "riskThresholds": {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 1
  },
  "settings": {
    "strictMode": true,
    "blockOnCritical": true,
    "auditLogging": true,
    "requireApproval": ["Critical", "High", "Medium"]
  }
}
```

## Healthcare Policy

HIPAA-compliant policy for healthcare environments:

```json
{
  "policyName": "healthcare-security",
  "version": "1.0",
  "description": "Healthcare security policy with HIPAA compliance",
  "rules": [
    {
      "id": "HIPAA_001",
      "name": "PHI Detection",
      "patterns": [
        "(?i)(patient.id|medical.record)\\s*[=:]\\s*[A-Z0-9]{6,}",
        "(?i)(diagnosis|icd.?10?)\\s*[=:]\\s*[A-Z][0-9]{2,}",
        "(?i)(dob|date.of.birth)\\s*[=:]\\s*[0-9]{1,2}[/-][0-9]{1,2}[/-][0-9]{4}"
      ],
      "severity": "Critical",
      "description": "Detects Protected Health Information (PHI)"
    },
    {
      "id": "HIPAA_002",
      "name": "Medical Device Communication",
      "patterns": [
        "HL7",
        "DICOM",
        "FHIR",
        "medical.device"
      ],
      "severity": "Medium",
      "description": "Monitors medical device communications"
    }
  ],
  "blockedPatterns": [
    "(?i)patient.*ssn",
    "(?i)medical.*record.*export"
  ],
  "riskThresholds": {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 1
  },
  "settings": {
    "strictMode": true,
    "blockOnCritical": true,
    "auditLogging": true,
    "encryptionRequired": true
  }
}
```

## Custom Policy Template

Template for creating organisation-specific policies:

```json
{
  "policyName": "custom-policy-template",
  "version": "1.0",
  "description": "Template for custom security policies",
  "rules": [
    {
      "id": "CUSTOM_001",
      "name": "Custom Rule Name",
      "patterns": [
        "your-regex-pattern-here"
      ],
      "severity": "Medium",
      "description": "Description of what this rule detects"
    }
  ],
  "blockedPatterns": [
    "pattern-to-block"
  ],
  "riskThresholds": {
    "critical": 50,
    "high": 30,
    "medium": 15,
    "low": 5
  },
  "settings": {
    "strictMode": false,
    "blockOnCritical": false,
    "customSettings": "value"
  }
}
```

## Policy Customisation Guidelines

### Rule Severity Levels

- **Critical**: Immediate security threats requiring blocking
- **High**: Serious vulnerabilities needing prompt attention
- **Medium**: Potential risks requiring investigation
- **Low**: Best practice violations and warnings

### Pattern Development

When creating detection patterns:

1. Use specific regex patterns to minimise false positives
2. Test patterns against known vulnerable code samples
3. Consider context and legitimate use cases
4. Document pattern purpose and expected matches

### Risk Threshold Tuning

Adjust risk thresholds based on:

- Organisational risk tolerance
- Environment criticality
- Compliance requirements
- Operational impact

### Settings Configuration

Common settings include:

- `strictMode`: Enables additional validation checks
- `blockOnCritical`: Automatically blocks critical findings
- `auditLogging`: Enables detailed audit trails
- `requireApproval`: Specifies severities requiring manual approval

## Policy Management Best Practices

### Version Control

- Track policy changes using version control
- Document changes in policy descriptions
- Test policies before deployment
- Maintain policy change logs

### Testing and Validation

- Test policies against known vulnerable samples
- Validate detection accuracy and false positive rates
- Performance test policy impact on scanning speed
- Regular policy effectiveness reviews

### Deployment Strategy

- Start with warning-only mode for new policies
- Gradually increase enforcement levels
- Monitor policy impact on operations
- Provide training on policy requirements

## Related Documentation

- [Configuration Reference](configuration.md) - Policy configuration options
- [Scanner Engine](scanner-engine.md) - Policy engine implementation
- [Threat Model](threat-model.md) - Security threats and attack vectors
- [Troubleshooting](troubleshooting.md) - Policy-related issues and solutions
