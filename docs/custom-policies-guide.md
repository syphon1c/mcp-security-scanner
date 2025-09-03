# Creating Custom Security Policies

This guide explains how to create your own organization-specific security policies for the MCP Security Scanner.

## Quick Start

1. **Copy the template**: Use the provided `org-custom-template.json` as your starting point
2. **Rename the file**: Give it a meaningful name like `acme-corp-security.json`
3. **Customize the content**: Modify patterns, rules, and metadata for your needs
4. **Test the policy**: Run scans with your new policy to ensure it works correctly

## Template Policy Location

The template policy is located at:
```
policies/org-custom-template.json
```

This file contains example patterns and detailed documentation to help you create your own policies.

## Creating Your Custom Policy

### Step 1: Copy and Rename

```bash
# Copy the template
cp policies/org-custom-template.json policies/your-company-security.json

# List available policies (should now include your new one)
./mcpscan policies
```

### Step 2: Customize Basic Information

Edit the policy metadata:

```json
{
  "version": "1.0",
  "policyName": "your-company-security",
  "description": "Security policy for Your Company Name - Custom patterns and rules",
  "severity": "High",
  "author": "Your Security Team",
  "created": "2025-09-02"
}
```

### Step 3: Add Organization-Specific Rules

Replace the template patterns with your organization's specific patterns:

#### Example: Employee ID Detection
```json
{
  "id": "COMPANY_001",
  "name": "Employee ID Detection",
  "description": "Detect company employee ID patterns in MCP traffic",
  "category": "Data Protection",
  "severity": "Medium",
  "patterns": [
    "\\b(EMP|EMPL)[-_]?\\d{6}\\b",        // EMP123456 or EMP-123456
    "\\b[A-Z]{2}\\d{6}\\b"                // AB123456 format
  ],
  "enabled": true
}
```

#### Example: API Key Protection
```json
{
  "id": "COMPANY_002", 
  "name": "Company API Key Protection",
  "description": "Protect company-specific API keys from exposure",
  "category": "API Security",
  "severity": "Critical",
  "patterns": [
    "\\bCOMP[-_]?[A-Za-z0-9]{32,64}\\b",  // Company API keys
    "\\byour[-_]?api[-_]?[A-Za-z0-9]+\\b" // Your API pattern
  ],
  "enabled": true
}
```

#### Example: Internal System Protection
```json
{
  "id": "COMPANY_003",
  "name": "Internal System Access Control",
  "description": "Prevent access to internal systems and endpoints",
  "category": "Access Control",
  "severity": "High",
  "patterns": [
    "/internal/",
    "/admin/company/",
    "/api/v[0-9]+/internal",
    "\\binternal[-_]?system\\b"
  ],
  "enabled": true
}
```

### Step 4: Configure Risk Thresholds

Adjust the risk thresholds based on your organization's risk tolerance:

```json
"riskThresholds": {
  "critical": 50,    // Block immediately
  "high": 30,        // Block and alert
  "medium": 15,      // Alert only
  "low": 5          // Log only
}
```

### Step 5: Add Blocked Patterns

Define patterns that should be immediately blocked:

```json
"blockedPatterns": [
  {
    "pattern": "\\bdrop\\s+table\\s+company_data\\b",
    "action": "block",
    "message": "Attempted access to protected company data table"
  },
  {
    "pattern": "/company/confidential/",
    "action": "block", 
    "message": "Access to confidential company resources blocked"
  }
]
```

## Policy Pattern Examples

### Common Organization Patterns

#### Financial Data
```json
"patterns": [
  "\\b\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}\\b",  // Credit card
  "\\b\\d{3}-\\d{2}-\\d{4}\\b",                            // SSN
  "\\b[A-Z]{2}\\d{2}[A-Z0-9]{4}\\d{7}([A-Z0-9]?){0,16}\\b" // IBAN
]
```

#### Employee Information
```json
"patterns": [
  "\\b(EMP|EMPLOYEE|STAFF)[-_]?\\d{4,8}\\b",
  "\\b[A-Za-z]+\\.[A-Za-z]+@yourcompany\\.com\\b",
  "\\b(DEPT|DEPARTMENT)[-_]?[A-Z]{2,6}\\b"
]
```

#### Project and Customer Codes
```json
"patterns": [
  "\\b(PROJ|PROJECT)[-_]?[A-Z]{2,4}[-_]?\\d{3,6}\\b",
  "\\b(CUST|CUSTOMER)[-_]?\\d{6,10}\\b",
  "\\b(CONTRACT|CNTR)[-_]?[A-Z0-9]{6,12}\\b"
]
```

## Testing Your Policy

### Validate Policy Syntax
```bash
# Test that your policy loads correctly
./mcpscan policies

# Should show your custom policy in the list
```

### Test with Sample Data
```bash
# Run a scan using your custom policy
./mcpscan scan-local /path/to/test/server your-company-security --verbose

# Test against a remote server
./mcpscan scan-remote http://test-server:8000 your-company-security
```

### Test Pattern Matching
Create a test file with sample patterns to verify your rules work:

```bash
# Create test file with sample patterns
echo "EMP123456 accessing /internal/data" > test-patterns.txt
echo "PROJ-ABC-001234 with API key COMP_abc123def456" >> test-patterns.txt

# Test if patterns are detected (manual verification)
grep -E "\\b(EMP|EMPL)[-_]?\\d{6}\\b" test-patterns.txt
```

## Advanced Configuration

### Polymorphic Patterns
For advanced threat detection, add polymorphic patterns:

```json
"polymorphicPatterns": [
  {
    "basePattern": "company_secret",
    "variations": [
      "c0mp4ny_s3cr3t",
      "company-secret", 
      "COMPANY_SECRET",
      "CompanySecret"
    ],
    "severity": "High"
  }
]
```

### Context-Aware Rules
Add rules that consider context:

```json
{
  "id": "CONTEXT_001",
  "name": "Database Query in Tool Call",
  "description": "Detect dangerous database operations in MCP tool calls",
  "category": "SQL Injection",
  "severity": "Critical",
  "patterns": [
    "(?i)(drop|delete|truncate)\\s+(table|database).*company"
  ],
  "context": "tool_call",
  "enabled": true
}
```

## Deployment Best Practices

1. **Version Control**: Keep your policies in version control
2. **Testing**: Thoroughly test policies in non-production environments
3. **Documentation**: Document your custom patterns and their purposes
4. **Review**: Regularly review and update patterns as threats evolve
5. **Monitoring**: Monitor policy effectiveness and adjust thresholds as needed

## Policy Management Commands

```bash
# List all policies
./mcpscan policies

# Test a specific policy (ensure it loads correctly)
./mcpscan scan-local /path/to/safe/test/file your-policy-name --verbose

# Use your policy with the proxy
./mcpscan proxy http://target-server:8000 9080 your-policy-name
```

## Troubleshooting

### Policy Not Loading
- Check JSON syntax with a validator
- Ensure file is in the policies directory
- Check file permissions
- Review error messages in verbose output

### Patterns Not Matching
- Test patterns individually with tools like `grep -E`
- Check for proper escaping of special characters
- Verify pattern syntax with online regex testers
- Use `--verbose` flag to see pattern matching details

### Performance Issues
- Avoid overly complex regex patterns
- Test pattern performance with large data sets
- Consider combining similar patterns
- Monitor CPU usage during scans

## Support

For questions about creating custom policies:
1. Review the template policy documentation
2. Check existing policies for examples
3. Test thoroughly in development environments
4. Document your patterns for team reference

Remember: Security policies should be tailored to your specific organizational needs and threat model.
