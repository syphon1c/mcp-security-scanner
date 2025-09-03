# Reporting System Documentation

The MCP Security Scanner includes a  reporting system that generates professional security assessment reports in multiple formats. This document covers all aspects of the reporting capabilities.

## Overview

The reporting system transforms scan results into various output formats suitable for different audiences and use cases:

- **Technical Teams**: JSON and text formats for integration and analysis
- **Security Teams**: HTML reports for detailed analysis and review
- **Management/Executives**: PDF reports for presentations and compliance
- **Automated Systems**: JSON for CI/CD pipelines and SIEM integration

## Supported Formats

### JSON Format
- **Purpose**: Machine-readable data for automation and integration
- **Use Cases**: CI/CD pipelines, SIEM systems, API integration, custom tooling
- **Features**: Complete structured data, all scan metadata, findings details
- **File Extension**: `.json`

**Example Usage:**
```bash
# Default JSON output (console + file)
./mcpscan scan-local . critical-security

# Generate JSON report to specific file
./mcpscan scan-local . critical-security --output-file scan-results.json

# Generate JSON to custom directory  
./mcpscan scan-local . critical-security --output-dir ./reports
```

### HTML Format
- **Purpose**: Human-readable reports with professional styling
- **Use Cases**: Security team reviews, stakeholder presentations, web viewing
- **Features**: 
  - Responsive design for desktop and mobile viewing
  - Interactive elements and collapsible sections
  - Color-coded severity levels and risk visualization
  - Print-optimized CSS for browser-based PDF generation
  - Professional styling with modern UI components

**Example Usage:**
```bash
# Generate HTML report with default timestamped filename
./mcpscan scan-local . critical-security --output-format html

# HTML report to specific file
./mcpscan scan-local . critical-security --output-file security-assessment.html

# HTML report to custom directory
./mcpscan scan-local . critical-security --output-format html --output-dir ./web-reports
```

**HTML Report Features:**
- **Executive Summary**: High-level risk assessment with visual indicators
- **Server Information**: Complete MCP server details and capabilities
- **Findings Table**: Detailed vulnerability information with evidence
- **Risk Visualization**: Progress bars and severity badges
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Print Optimization**: Clean printing for PDF generation from browser

### PDF Format
- **Purpose**: Professional reports for executive presentations and archival
- **Use Cases**: Executive briefings, compliance documentation, formal reports
- **Features**:
  - A4 page format with professional margins
  - Consistent layout across different systems
  - High-quality typography and formatting
  - Suitable for printing and digital distribution

**Requirements:**
- Uses pure Go implementation for native PDF generation
- No external dependencies required
- See [Installation Requirements](#installation-requirements) for setup instructions

**Example Usage:**
```bash
# Generate PDF report (pure Go implementation - no dependencies)
./mcpscan scan-local . critical-security --output-format pdf

# PDF report to specific file
./mcpscan scan-local . critical-security --output-file executive-summary.pdf

# PDF report to custom directory
./mcpscan scan-local . critical-security --output-format pdf --output-dir ./executive-reports
```

### Text Format
- **Purpose**: Plain text reports for terminal viewing and basic systems
- **Use Cases**: Command-line analysis, email reports, legacy system integration
- **Features**:
  - Terminal-friendly formatting
  - No external dependencies
  - Email-compatible plain text
  - Structured sections with clear hierarchy

**Example Usage:**
```bash
# Generate text report
./mcpscan scan-local . critical-security --output-format text

# Text report to specific file
./mcpscan scan-local . critical-security --output-file scan-summary.txt

# Text report to custom directory
./mcpscan scan-local . critical-security --output-format text --output-dir ./text-reports
```

## Advanced Reporting Options

### Multi-Format Generation

Generate reports in all available formats simultaneously:

```bash
# Generate all formats with default timestamped filenames in ./reports directory (default behavior)
./mcpscan scan-local . critical-security --all-formats

# Generate all formats to specific directory (overrides default)
./mcpscan scan-local . critical-security --all-formats --output-dir ./security-reports

# Generate all formats for remote scan to custom directory
./mcpscan scan-remote http://localhost:8000 critical-security --all-formats --output-dir ./remote-assessment
```

### Default Report Location

Starting from v1.0, all reports are automatically saved to the `./reports/` directory unless you specify otherwise:

```bash
# These commands automatically use ./reports/ directory:
./mcpscan scan-local . critical-security                    # → ./reports/mcp_security_report_YYYYMMDD_HHMMSS.json
./mcpscan scan-local . critical-security --output-format html # → ./reports/mcp_security_report_YYYYMMDD_HHMMSS.html
./mcpscan scan-local . critical-security --all-formats      # → ./reports/mcp_security_report_YYYYMMDD_HHMMSS.*
```

### Custom Output Paths

```bash
# Specify exact output file (overrides default directory)
./mcpscan scan-local . critical-security --output-file ./reports/monthly-assessment.html

# Specify custom output directory (overrides default ./reports/)
./mcpscan scan-local . critical-security --output-format pdf --output-dir ./executive-reports

# Generate multiple reports to different locations
./mcpscan scan-local . critical-security --output-format html --output-file ./web/security-dashboard.html
./mcpscan scan-remote http://localhost:8000 critical-security --output-format pdf --output-file ./documents/remote-audit.pdf
```

### Verbose Output

Combine file reports with detailed console output:

```bash
# HTML report with verbose console output showing detailed findings
./mcpscan scan-local . critical-security --output-format html --verbose

# All formats with verbose console feedback
./mcpscan scan-local . critical-security --all-formats --verbose

# Remote scan with text output and detailed console findings
./mcpscan scan-remote http://localhost:8000 advanced-polymorphic-security --output-format text --verbose
```

## Report Structure and Content

### Executive Summary Section
- **Overall Risk Assessment**: Critical, High, Medium, Low, or Minimal
- **Risk Score**: Numerical score from 0-100
- **Finding Counts**: Breakdown by severity level
- **Scan Metadata**: Target, policy used, timestamp, duration

### MCP Server Information Section
- **Server Details**: Name, version, protocol version
- **Capabilities**: Supported MCP features and extensions
- **Discovered Tools**: Available tools with descriptions
- **Discovered Resources**: Accessible resources and endpoints

### Security Findings Section
- **Detailed Findings**: Complete vulnerability information
- **Evidence**: Code snippets, patterns, or responses that triggered the finding
- **Severity Assessment**: Risk level and impact analysis
- **Remediation Guidance**: Specific steps to address each finding
- **Location Information**: File paths, line numbers, or endpoint URLs

### Technical Information Section
- **Scan Configuration**: Policy details and scan parameters
- **Coverage Statistics**: Files scanned, endpoints tested, patterns matched
- **Performance Metrics**: Scan duration and resource usage
- **Tool Information**: Scanner version and generation timestamp

## Installation Requirements

### PDF Generation Setup

### PDF Dependencies

PDF reports are generated using a pure Go implementation with no external dependencies.

**Benefits:**
- **Zero Setup**: Works immediately after installation
- **Cross-Platform**: Consistent behavior across all operating systems  
- **No External Tools**: No need to install or maintain additional software
- **Reliable**: No dependency on external tools that might be discontinued

**Usage:**
```bash
# Generate PDF report - works out of the box
./mcpscan scan-local . critical-security --output-format pdf
```

The scanner uses the `github.com/jung-kurt/gofpdf` library for native PDF generation with professional formatting, color-coded severity levels, and automatic pagination.

## Integration Examples

### CI/CD Pipeline Integration

#### GitHub Actions
```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Go
      uses: actions/setup-go@v3
      with:
        go-version: '1.21'
    
    - name: Build MCP Security Scanner
      run: go build -o mcpscan
    
    - name: Run MCP Security Scan
      run: |
        # Generate all report formats
        ./mcpscan scan-local . critical-security --all-formats --output-dir ./security-reports
        
    - name: Upload Security Reports
      uses: actions/upload-artifact@v3
      with:
        name: security-reports
        path: security-reports/
        
    - name: Check for Critical Issues
      run: |
        # Parse JSON report for critical findings
        critical_count=$(jq '.summary.criticalFindings' security-reports/*.json)
        if [ "$critical_count" -gt 0 ]; then
          echo "Critical security issues found: $critical_count"
          exit 1
        fi
```

#### Jenkins Pipeline
```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    // Generate  security reports
                    sh '''
                        ./build/mcpscan scan-local . critical-security \
                          --all-formats \
                          --output-dir ./security-reports \
                          --verbose
                    '''
                }
            }
        }
        
        stage('Publish Reports') {
            steps {
                // Archive all report formats
                archiveArtifacts artifacts: 'security-reports/*', fingerprint: true
                
                // Publish HTML report
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'security-reports',
                    reportFiles: '*.html',
                    reportName: 'MCP Security Report'
                ])
            }
        }
    }
}
```

### Automated Report Distribution

#### Email Distribution Script
```bash
#!/bin/bash
# distribute-security-reports.sh

# Generate reports
./build/mcpscan scan-local . critical-security --all-formats --output-dir ./reports

# Email HTML report to security team
mail -s "MCP Security Scan Results" \
     -a "Content-Type: text/html" \
     security-team@company.com < ./reports/*.html

# Email PDF report to executives
echo "Please find attached the latest MCP security assessment." | \
mail -s "Security Assessment Report" \
     -A ./reports/*.pdf \
     executives@company.com
```

#### SIEM Integration
```python
#!/usr/bin/env python3
import json
import requests
from datetime import datetime

def send_to_siem(report_file):
    """Send scan results to SIEM system"""
    
    with open(report_file, 'r') as f:
        scan_results = json.load(f)
    
    # Transform to SIEM format
    for finding in scan_results['findings']:
        siem_event = {
            'timestamp': datetime.now().isoformat(),
            'source': 'mcp-security-scanner',
            'event_type': 'security_finding',
            'severity': finding['severity'].lower(),
            'description': finding['description'],
            'evidence': finding['evidence'],
            'target': scan_results['target'],
            'policy': scan_results['policyUsed']
        }
        
        # Send to SIEM
        response = requests.post(
            'https://siem.company.com/api/events',
            json=siem_event,
            headers={'Authorization': 'Bearer API_TOKEN'}
        )
        response.raise_for_status()

# Usage
send_to_siem('./reports/mcp_security_report_*.json')
```

## Best Practices

### Report Organization

1. **Use Consistent Naming**: Use timestamps or version numbers in report names
2. **Organize by Environment**: Separate reports for dev, staging, and production
3. **Archive Historical Reports**: Keep previous reports for trend analysis
4. **Access Control**: Restrict access to security reports based on sensitivity

### Format Selection Guidelines

1. **JSON**: For automated processing, CI/CD integration, and API consumption
2. **HTML**: For human review, sharing with technical teams, and web viewing
3. **PDF**: For executive presentations, compliance documentation, and archival
4. **Text**: For quick command-line review and email distribution

### Performance Considerations

1. **Large Codebases**: Use specific policies to reduce scan time for routine checks
2. **Automated Scans**: Generate only necessary formats in CI/CD to save time
3. **Storage Management**: Clean up old reports regularly to manage disk space
4. **Network Scans**: Consider timeout settings for remote scanning with reporting

### Security Considerations

1. **Report Access**: Secure reports contain sensitive security information
2. **Transport Security**: Use HTTPS/TLS when transmitting reports
3. **Storage Security**: Encrypt stored reports if they contain sensitive data
4. **Retention Policies**: Implement appropriate report retention and disposal policies

This reporting system provides the flexibility and professionalism needed for  MCP security assessment documentation and integration into enterprise security workflows.
