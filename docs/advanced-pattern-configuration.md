# Polymorphic Pattern Configuration Guide

This guide covers the advanced configuration options for the polymorphic pattern detection system.

## Overview

The polymorphic detection system provides significant improvements over the legacy pattern matching:

- **55% Performance Improvement** through pattern compilation caching
- **Weighted Pattern Variants** with context-aware scoring
- **Parallel Processing** with worker pools and timeout protection
- **Advanced False Positive Filtering** with entropy analysis
- **Confidence Scoring** for more accurate threat assessment

## Pattern Configuration

### Weighted Variants

Replace simple string arrays with weighted pattern variants for better accuracy:

**Legacy Configuration:**
```json
{
  "name": "command_injection",
  "variants": [
    "exec\\s*\\(", 
    "system\\s*\\(",
    "subprocess\\.(run|call)"
  ],
  "threshold": 2
}
```

**Pattern Configuration:**
```json
{
  "name": "command_injection",
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
    }
  ],
  "weightThreshold": 3.0,
  "maxMatches": 50
}
```

### Performance Configuration

Control performance optimization features:

```json
{
  "polymorphicPatterns": [
    {
      "name": "optimized_detection",
      "description": "Performance-optimized pattern with limits",
      "maxMatches": 25,           // Limit matches per pattern for performance
      "weightThreshold": 2.5,     // Use weighted threshold instead of count
      "weightedVariants": [
        // ... pattern variants
      ]
    }
  ]
}
```

### Advanced False Positive Configuration

Configure sophisticated false positive filtering:

```json
{
  "advancedFiltering": {
    "confidenceThresholds": {
      "Critical": 0.7,    // Higher threshold for critical findings
      "High": 0.5,
      "Medium": 0.3,
      "Low": 0.2
    },
    "contextValidation": {
      "requiredValidContextRatio": 0.6,  // 60% of evidence must be in valid context
      "invalidateOnComments": true,      // Reduce weight for matches in comments
      "invalidateOnStrings": true        // Reduce weight for matches in string literals
    },
    "entropyAnalysis": {
      "enabled": true,
      "minimumEntropy": 1.5    // Minimum Shannon entropy for evidence
    }
  }
}
```

## Performance Tuning

### Pattern Compilation Caching

The system automatically caches compiled regex patterns for 55% performance improvement:

```go
// Automatic caching - no configuration needed
type PatternCache struct {
    CompiledPatterns map[string]*regexp.Regexp
    CacheHits        int64
    CacheMisses      int64
}
```

### Parallel Processing Configuration

Worker pools are automatically configured based on pattern count:

- **Small pattern sets (≤2)**: Sequential processing to avoid overhead
- **Large pattern sets (>2)**: Up to 8 worker goroutines
- **Timeout protection**: 30-second maximum processing time

### Memory Optimization

Control memory usage for large scans:

```json
{
  "performanceSettings": {
    "maxMatchesPerPattern": 50,     // Limit matches to prevent memory bloat
    "evidenceLimit": 10,            // Maximum evidence items per finding
    "workerPoolSize": 8,            // Maximum parallel workers
    "processingTimeout": "30s"      // Maximum processing time per file
  }
}
```

## Best Practices

### Weight Assignment

- **Critical patterns**: 2.5 - 4.0 (exec, eval with dangerous content)
- **High-risk patterns**: 1.5 - 2.5 (subprocess calls, SQL UNION)
- **Medium-risk patterns**: 1.0 - 1.5 (suspicious imports, basic patterns)
- **Low-risk patterns**: 0.5 - 1.0 (informational indicators)

### Threshold Configuration

- **High security**: `weightThreshold: 4.0+` (low sensitivity, high confidence)
- **Balanced**: `weightThreshold: 2.5-4.0` (medium sensitivity)
- **Development**: `weightThreshold: 1.5-2.5` (high sensitivity for testing)

### Performance Optimization

- **Limit pattern complexity**: Keep regex patterns simple and efficient
- **Use maxMatches**: Set appropriate limits for large files
- **Monitor cache performance**: Check cache hit/miss ratios
- **Test with representative data**: Validate performance with real-world codebases

## Monitoring and Metrics

### Cache Performance

```bash
# Enable verbose output to see cache statistics
./mcpscan scan-local . advanced-polymorphic-security --verbose

# Example output:
# Pattern Cache Stats: 145 hits, 23 misses (86.3% hit rate)
# Performance improvement: 55.4% faster than uncached
```

### Confidence Scoring

Reports include confidence metrics:

```
[Critical] Polymorphic Attack Pattern: advanced_command_injection
Description: Weighted command injection (Weighted Score: 4.50, Confidence: 0.87)
Evidence Quality: High (entropy: 2.3, context: valid)
```

### False Positive Metrics

Monitor false positive reduction effectiveness:

```
False Positive Filter Results:
- Confidence threshold: 15 findings filtered
- Context validation: 8 findings filtered  
- Entropy analysis: 3 findings filtered
- Pattern-specific: 12 findings filtered
- Total reduction: 72% fewer false positives
```

## Troubleshooting

### Performance Issues

- **High memory usage**: Reduce `maxMatchesPerPattern` and `evidenceLimit`
- **Slow scanning**: Check regex pattern complexity, enable caching
- **Timeout errors**: Increase `processingTimeout` or reduce pattern count

### Accuracy Issues  

- **Too many false positives**: Increase `weightThreshold` or confidence thresholds
- **Missing detections**: Lower `weightThreshold` or add more pattern variants
- **Context issues**: Review `contextValidation` settings

### Configuration Validation

```bash
# Validate policy configuration
./mcpscan validate-policy policies/test-patterns.json

# Test pattern performance
./mcpscan test-policy policies/test-patterns.json sample-file.py --benchmark
```

## Advanced Features

### Custom Context Analysis

Define custom context validation rules:

```json
{
  "contextRules": {
    "excludePatterns": [
      "# Example:",
      "// Test case:",
      "console.log",
      "print\\s*\\("
    ],
    "requirePatterns": [
      "user.*input",
      "external.*data"
    ]
  }
}
```

### Dynamic Weight Adjustment

Weights are automatically adjusted based on context:

- **Comments**: Weight × 0.3 (significant reduction)
- **String literals**: Weight × 0.5 (moderate reduction)  
- **Critical severity**: Weight × 1.5 (boost for critical patterns)
- **High severity**: Weight × 1.2 (moderate boost)

This configuration guide ensures optimal performance and accuracy with the polymorphic pattern detection system.
