# Polymorphic Pattern Detection Guide

This guide covers the advanced polymorphic pattern detection capabilities introduced in MCP Security Scanner v1.1.0, enabling policy-driven detection of sophisticated attack patterns that adapt to evade traditional signature-based detection.

## Overview

Polymorphic pattern detection represents a significant advancement in the MCP Security Scanner's threat detection capabilities. Unlike traditional static pattern matching, polymorphic detection uses configurable multi-variant pattern analysis to identify attacks that change their signature to evade detection.

### Key Features

- **Policy-Driven Configuration**: Define patterns in JSON policy files without code changes
- **Multi-Variant Detection**: Each pattern can include multiple attack variations
- **Configurable Thresholds**: Set minimum variant matches required for detection
- **Evidence Aggregation**: Collection of matched variants for forensic analysis
- **Backward Compatibility**: Automatic fallback to legacy hardcoded patterns

## Architecture

### Core Components

```go
// SecurityPolicy structure with weighted patterns
type SecurityPolicy struct {
    PolymorphicPatterns []PolymorphicPattern `json:"polymorphicPatterns,omitempty"`
    BehavioralPatterns  []BehavioralPattern  `json:"behavioralPatterns,omitempty"`
    // ... other fields
}

type PolymorphicPattern struct {
    Name             string           `json:"name"`             // Unique pattern identifier
    Description      string           `json:"description"`      // Human-readable description
    Severity         string           `json:"severity"`         // Critical, High, Medium, Low
    Category         string           `json:"category"`         // Classification category
    Variants         []string         `json:"variants"`         // Array of regex patterns
    WeightedVariants []PatternVariant `json:"weightedVariants"` // Weighted pattern variants
    Threshold        int              `json:"threshold"`        // Minimum variants to trigger
    WeightThreshold  float64          `json:"weightThreshold"`  // Minimum weighted score
    MaxMatches       int              `json:"maxMatches"`       // Performance limit for matches
}

//  Advanced pattern variant with weights and context
type PatternVariant struct {
    Pattern  string  `json:"pattern"`   // Regex pattern
    Weight   float64 `json:"weight"`    // Pattern weight (0.1 - 10.0)
    Context  string  `json:"context"`   // Context description
    Severity string  `json:"severity"`  // Variant-specific severity
}

//  Pattern matching result
type PolymorphicMatchResult struct {
    PatternName     string         `json:"pattern_name"`
    MatchedVariants []VariantMatch `json:"matched_variants"`
    WeightedScore   float64        `json:"weighted_score"`
    Confidence      float64        `json:"confidence"`      //  0.0 - 1.0
    MatchCount      int            `json:"match_count"`
    TotalScore      float64        `json:"total_score"`
    Evidence        []string       `json:"evidence"`
}

type BehavioralPattern struct {
    Name        string   `json:"name"`
    Description string   `json:"description"`
    Severity    string   `json:"severity"`
    Category    string   `json:"category"`
    Patterns    []string `json:"patterns"`    // Behavioral indicators
    Threshold   int      `json:"threshold"`   // Minimum pattern matches
}
```

### Detection Flow

1. **Policy Loading**: Security policy loaded with polymorphic pattern definitions
2. **Content Analysis**: Target content analyzed against each polymorphic pattern
3. **Parallel Processing**: Patterns processed using worker pools for better performance
4. **Weighted Variant Matching**: Each variant regex tested with context-aware weight calculation
5. **Score Calculation**: Weighted score with confidence analysis and entropy validation
6. **Advanced Threshold Evaluation**: Support for both legacy count and weighted thresholds
7. **False Positive Filtering**: Multi-layer filtering with pattern-specific validation
8. **Finding Generation**: Security finding created with scoring information
9. **Evidence Collection**: Matched variants collected with quality assessment

## Policy Configuration

### Basic Polymorphic Pattern

```json
{
  "version": "1.0.0",
  "policyName": "example-polymorphic-policy",
  "polymorphicPatterns": [
    {
      "name": "command_injection_variants",
      "description": "Multi-variant command injection detection",
      "severity": "Critical",
      "category": "Advanced Injection",
      "threshold": 2,
      "variants": [
        "exec\\s*\\(\\s*[\"'].*[\"']",
        "system\\s*\\(\\s*[\"'].*[\"']",
        "os\\.system\\s*\\(",
        "subprocess\\.(run|call|Popen)",
        "eval\\s*\\(\\s*[\"'].*exec.*[\"']",
        "__import__\\s*\\(\\s*[\"']os[\"']"
      ]
    }
  ]
}
```

### Advanced Weighted Patterns (v1.2.0+)

```json
{
  "version": "1.2.0",
  "policyName": "advanced-weighted-polymorphic",
  "polymorphicPatterns": [
    {
      "name": "advanced_command_injection",
      "description": "Weighted command injection with context analysis",
      "severity": "Critical",
      "category": "Advanced Injection",
      "weightThreshold": 3.0,
      "maxMatches": 50,
      "weightedVariants": [
        {
          "pattern": "exec\\s*\\(\\s*[\"'].*[\"']",
          "weight": 2.5,
          "context": "Direct exec call",
          "severity": "Critical"
        },
        {
          "pattern": "eval\\s*\\(\\s*[\"'].*exec.*[\"']",
          "weight": 3.0,
          "context": "Obfuscated exec via eval",
          "severity": "Critical"
        },
        {
          "pattern": "subprocess\\.(run|call|Popen)",
          "weight": 2.0,
          "context": "Subprocess execution",
          "severity": "High"
        },
        {
          "pattern": "__import__\\s*\\(\\s*[\"']os[\"']",
          "weight": 1.5,
          "context": "Dynamic OS import",
          "severity": "Medium"
        }
      ]
    }
  ]
}
```

### Performance Optimizations (v1.2.0+)

```json
{
  "polymorphicPatterns": [
    {
      "name": "optimized_sql_injection",
      "description": "Performance-optimized SQL injection detection",
      "severity": "High",
      "category": "Database Security",
      "weightThreshold": 2.5,
      "maxMatches": 25,
      "weightedVariants": [
        {
          "pattern": "UNION\\s+SELECT",
          "weight": 2.0,
          "context": "Standard UNION attack",
          "severity": "High"
        },
        {
          "pattern": "OR\\s+1\\s*=\\s*1",
          "weight": 1.8,
          "context": "Boolean-based injection",
          "severity": "High"
        }
      ]
    }
  ]
}
```

## Usage Examples

### Scanning with Polymorphic Policies

```bash
# Use built-in advanced polymorphic policy
./mcpscan scan-local . advanced-polymorphic-security

# Use custom polymorphic policy
./mcpscan scan-local ./target custom-polymorphic-policy

# Generate detailed report showing polymorphic detections
./mcpscan scan-local . advanced-polymorphic-security --output-format html
```

### Example Detection Output

```
[Critical] Polymorphic Attack Pattern: advanced_command_injection
Category: Advanced Injection
Location: suspicious_file.py
Description: Weighted command injection with context analysis (Weighted Score: 4.50, Matches: 3, Confidence: 0.87)
Evidence: exec("malicious_cmd"), eval(base64.b64decode(...)), subprocess.call(...)
Remediation: Implement input validation and output encoding.

[High] Behavioral Anomaly: excessive_network_activity
Category: Behavioral Analysis
Location: network_script.py
Description: Detects excessive network activity patterns (Count: 7, Threshold: 5)
Evidence: requests.get(, urllib.request.urlopen(, socket.socket(, http.client.HTTPConnection(, telnetlib.Telnet(
Remediation: Review code for legitimate use cases. Implement behavioral monitoring.
```

### Performance Metrics

```
🧪 Pattern Compilation Caching Performance
============================================================
📁 Test file: /tmp/test_patterns.py

🔄 First run (compilation required):
   ⏱️  Duration: 0.038 seconds
   ✅ Scan completed successfully

🚀 Second run (using cached patterns):
   ⏱️  Duration: 0.017 seconds
   ✅ Scan completed successfully

📈 Performance Improvement: 55.44%

💾 Cache Features:
   ✓ Compiled regex patterns cached in memory
   ✓ Thread-safe access with sync.RWMutex  
   ✓ Reduces pattern compilation overhead
   ✓ Significant benefit for large files with many patterns
```

## Best Practices

### Threshold Configuration

**Low Sensitivity (High Confidence)**
- Use higher thresholds (3-4+ variants) for production environments
- Reduces false positives but may miss sophisticated attacks
- Recommended for automated blocking scenarios

**Medium Sensitivity (Balanced)**
- Use moderate thresholds (2-3 variants) for most environments
- Balances detection accuracy with false positive rate
- Recommended for general security monitoring

**High Sensitivity (Early Warning)**
- Use lower thresholds (1-2 variants) for research environments
- Maximizes detection but increases false positive rate
- Recommended for threat hunting and forensic analysis

### Pattern Design Guidelines

**Effective Variant Selection:**
- Include common attack patterns as baseline variants
- Add obfuscated and encoded variants for evasion detection
- Consider programming language-specific variations
- Test patterns against known attack samples

**Performance Considerations:**
- Limit variant arrays to 15-20 patterns for optimal performance
- Use specific patterns rather than overly broad regex
- Consider regex complexity and compilation overhead
- Monitor scan performance with large pattern sets

### Security Recommendations

**Policy Security:**
- Store policies in version control for audit trails
- Validate policy syntax before deployment
- Use principle of least privilege for policy access
- Regularly review and update pattern definitions

**Deployment Strategy:**
- Test new policies in development environments first
- Implement gradual rollout for production deployments
- Monitor detection accuracy and false positive rates
- Maintain separate policies for different environments

## Features

### Weighted Pattern Variants

The polymorphic detection system supports weighted pattern variants with context-aware scoring:

**Key Improvements:**
- **Individual Variant Weights**: Each pattern variant can have a custom weight (0.1 - 10.0)
- **Context Analysis**: Patterns are analyzed in context (comments, strings, code)
- **Confidence Scoring**: Machine learning-inspired confidence calculation (0.0 - 1.0)
- **Performance Caching**: Compiled regex patterns cached for 55%+ performance improvement
- **Parallel Processing**: Worker pools for large pattern sets with timeout protection
- **Advanced False Positive Filtering**: Multi-layer validation with entropy analysis

### Threshold Configuration

**Legacy Count-Based Thresholds**
- Use `threshold` field for number of variant matches required
- Backward compatible with existing policies
- Simple counting mechanism

**Weighted Thresholds**
- Use `weightThreshold` field for minimum weighted score
- Context-aware weight calculation
- Severity-based weight adjustments
- More accurate threat detection

**Adaptive Sensitivity (Recommended)**
- **High Security Environments**: `weightThreshold: 4.0+` (low sensitivity, high confidence)
- **Balanced Environments**: `weightThreshold: 2.5-4.0` (medium sensitivity)
- **Research/Development**: `weightThreshold: 1.5-2.5` (high sensitivity)

### Performance Optimization

**Pattern Compilation Caching:**
- Thread-safe compiled regex storage
- 55% performance improvement demonstrated
- Automatic cache hit/miss tracking
- Significant benefit for repeated scans

**Parallel Processing:**
- Worker pools for large pattern sets (8 workers max)
- Sequential processing for small sets (≤2 patterns)
- 30-second timeout protection
- Optimized for multi-core systems

**False Positive Reduction:**
- Pattern-specific confidence thresholds
- Context validation (60% evidence in valid contexts)
- File type awareness (test files, documentation, configs)
- Entropy analysis for evidence quality
- Security context cross-referencing

### Pattern Inheritance

Future versions will support pattern inheritance for policy reuse:

```json
{
  "inherits": "base-polymorphic-patterns",
  "polymorphicPatterns": [
    // Additional patterns specific to this policy
  ]
}
```

### Dynamic Pattern Updates

Planned features for dynamic pattern management:

- Remote pattern repository synchronization
- Automatic pattern updates from threat intelligence feeds
- Machine learning-assisted pattern generation
- Community-contributed pattern sharing

## Troubleshooting

### Common Issues

**Pattern Not Triggering:**
- Check threshold configuration (may be too high)
- Verify regex pattern syntax
- Test individual variants against sample data
- Review pattern specificity (too narrow/broad)

**Performance Issues:**
- Reduce number of variants per pattern
- Optimize regex patterns for efficiency
- Enable pattern caching in configuration
- Consider pattern complexity and length

**False Positives:**
- Increase threshold requirements
- Refine pattern specificity
- Add exclusion patterns
- Review legitimate code patterns

### Debugging

```bash
# Validate policy syntax
./mcpscan validate-policy policies/custom-polymorphic.json

# Test policy against sample file
./mcpscan test-policy policies/custom-polymorphic.json sample.py

# View detailed policy information
./mcpscan policies --details custom-polymorphic

# Run scan with verbose output
./mcpscan scan-local . custom-polymorphic --verbose
```

## Contributing

To contribute new polymorphic patterns:

1. Test patterns against diverse attack samples
2. Validate regex syntax and performance
3. Document pattern purpose and detection logic
4. Submit patterns through standard policy files
5. Include threshold recommendations and evidence

For more information, see the [Contributing Guide](CONTRIBUTING.md).
