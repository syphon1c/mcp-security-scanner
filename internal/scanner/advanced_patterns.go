package scanner

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

// AdvancedPatternDetector implements machine learning-inspired pattern detection with caching and parallel processing
type AdvancedPatternDetector struct {
	scanner      *Scanner
	patternCache *types.PatternCache
	cacheMutex   sync.RWMutex
}

// NewAdvancedPatternDetector creates a new advanced threat detection engine with machine learning-inspired capabilities.
// The detector implements sophisticated pattern recognition algorithms for detecting polymorphic attacks,
// behavioral anomalies, supply chain compromises, and zero-day exploit patterns that traditional
// signature-based detection methods might miss.
//
// Parameters:
//   - scanner: Parent scanner instance providing access to policy engine and configuration
//
// Returns:
//   - *AdvancedPatternDetector: Configured detector ready for advanced threat analysis
//
// The detector utilizes both policy-defined patterns and hardcoded heuristics to identify
// advanced persistent threats, evasion techniques, and novel attack vectors in MCP environments.
func NewAdvancedPatternDetector(scanner *Scanner) *AdvancedPatternDetector {
	return &AdvancedPatternDetector{
		scanner: scanner,
		patternCache: &types.PatternCache{
			CompiledPatterns: make(map[string]*regexp.Regexp),
			CacheHits:        0,
			CacheMisses:      0,
		},
	}
}

// DetectAdvancedThreats performs comprehensive advanced threat detection using multiple analysis techniques.
// The function combines policy-driven pattern matching with machine learning-inspired heuristics to
// identify sophisticated attack patterns including polymorphic threats, behavioral anomalies,
// supply chain attacks, and zero-day exploit patterns.
//
// Parameters:
//   - content: Source code or configuration content to analyze for advanced threats
//   - filePath: Path to the file being analyzed for context and evidence extraction
//   - policy: Security policy containing advanced threat detection patterns and configurations
//   - result: Scan result structure that will be populated with detected advanced threats
//
// The function implements a multi-layered approach:
// 1. Policy-defined polymorphic pattern detection for configurable threat identification
// 2. Behavioral anomaly detection using statistical analysis and pattern correlation
// 3. Hardcoded heuristics for supply chain, obfuscation, and zero-day pattern detection
func (apd *AdvancedPatternDetector) DetectAdvancedThreats(content string, filePath string, policy *types.SecurityPolicy, result *types.ScanResult) {
	if apd == nil || result == nil {
		return // Handle nil detector or result gracefully
	}

	// Detect polymorphic attack patterns using policy-defined patterns
	apd.detectPolymorphicAttacks(content, filePath, policy, result)

	// Detect behavioral anomalies using policy-defined patterns
	apd.detectBehavioralAnomalies(content, filePath, policy, result)

	// Keep existing hardcoded detection for backward compatibility
	apd.detectObfuscatedPayloads(content, filePath, result)
	apd.detectSupplyChainAttacks(content, filePath, result)
	apd.detectZeroDayPatterns(content, filePath, result)
}

// detectPolymorphicAttacks detects attacks that change their signature using weighted scoring
func (apd *AdvancedPatternDetector) detectPolymorphicAttacks(content, filePath string, policy *types.SecurityPolicy, result *types.ScanResult) {
	if policy == nil {
		// Fallback to hardcoded patterns for backward compatibility when policy is nil
		apd.detectPolymorphicAttacksLegacy(content, filePath, result)
		return
	}

	// Use policy-defined polymorphic patterns if available
	if policy.PolymorphicPatterns != nil && len(policy.PolymorphicPatterns) > 0 {
		// Process patterns in parallel for better performance
		apd.processPolymorphicPatternsParallel(content, filePath, policy.PolymorphicPatterns, result)
	} else {
		// Fallback to legacy hardcoded patterns
		apd.detectPolymorphicAttacksLegacy(content, filePath, result)
	}
}

// processPolymorphicPatternsParallel processes patterns in parallel with scoring and worker pool
func (apd *AdvancedPatternDetector) processPolymorphicPatternsParallel(content, filePath string, patterns []types.PolymorphicPattern, result *types.ScanResult) {
	// For small pattern sets, process sequentially to avoid overhead
	if len(patterns) <= 2 {
		for _, pattern := range patterns {
			apd.processPolymorphicPatternDirect(content, filePath, pattern, result)
		}
		return
	}

	// Use worker pool for larger pattern sets
	numWorkers := min(len(patterns), 8) // Limit workers to avoid excessive goroutines
	patternChan := make(chan types.PolymorphicPattern, len(patterns))
	findingsChan := make(chan types.Finding, len(patterns)*2) // Buffer for potential multiple findings per pattern

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pattern := range patternChan {
				apd.processPolymorphicPattern(content, filePath, pattern, findingsChan)
			}
		}()
	}

	// Send patterns to workers
	go func() {
		for _, pattern := range patterns {
			patternChan <- pattern
		}
		close(patternChan)
	}()

	// Close findings channel when all workers complete
	go func() {
		wg.Wait()
		close(findingsChan)
	}()

	// Collect findings with timeout protection
	timeout := time.After(30 * time.Second) // Prevent hanging on large scans
	for {
		select {
		case finding, ok := <-findingsChan:
			if !ok {
				return // Channel closed, all workers done
			}
			result.Findings = append(result.Findings, finding)
		case <-timeout:
			// Log timeout but don't fail the scan
			log.Printf("Warning: Polymorphic pattern processing timed out for %s", filePath)
			return
		}
	}
}

// processPolymorphicPatternDirect processes a pattern directly without goroutines (for small sets)
func (apd *AdvancedPatternDetector) processPolymorphicPatternDirect(content, filePath string, pattern types.PolymorphicPattern, result *types.ScanResult) {
	// Use scoring algorithm
	matchResult := apd.calculatePolymorphicScore(content, pattern)

	// Check thresholds - support both legacy and weighted thresholds
	meetsCriteria := false

	if pattern.WeightThreshold > 0 {
		// Use weighted threshold if specified
		meetsCriteria = matchResult.WeightedScore >= pattern.WeightThreshold
	} else {
		// Fallback to legacy count-based threshold
		meetsCriteria = len(matchResult.MatchedVariants) >= pattern.Threshold
	}

	// Apply false positive filtering
	if meetsCriteria && apd.passesfalsePositiveFilter(matchResult, pattern, content) {
		finding := types.Finding{
			ID:          fmt.Sprintf("POLYMORPHIC_%s_%d", strings.ToUpper(pattern.Name), time.Now().UnixNano()),
			RuleID:      fmt.Sprintf("POLYMORPHIC_%s", strings.ToUpper(pattern.Name)),
			Severity:    pattern.Severity,
			Category:    pattern.Category,
			Title:       fmt.Sprintf("Polymorphic Attack Pattern: %s", pattern.Name),
			Description: apd.generateDescription(pattern, matchResult),
			Evidence:    strings.Join(matchResult.Evidence, ", "),
			Location:    filePath,
			Remediation: "Implement input validation and output encoding. Use allowlists instead of blocklists.",
			Timestamp:   time.Now(),
		}

		result.Findings = append(result.Findings, finding)
	}
}

// min helper function for Go versions that don't have it built-in
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// processPolymorphicPattern processes a single polymorphic pattern with scoring
func (apd *AdvancedPatternDetector) processPolymorphicPattern(content, filePath string, pattern types.PolymorphicPattern, findingsChan chan<- types.Finding) {
	// Use scoring algorithm
	matchResult := apd.calculatePolymorphicScore(content, pattern)

	// Check thresholds - support both legacy and weighted thresholds
	meetsCriteria := false

	if pattern.WeightThreshold > 0 {
		// Use weighted threshold if specified
		meetsCriteria = matchResult.WeightedScore >= pattern.WeightThreshold
	} else {
		// Fallback to legacy count-based threshold
		meetsCriteria = len(matchResult.MatchedVariants) >= pattern.Threshold
	}

	// Apply false positive filtering
	if meetsCriteria && apd.passesfalsePositiveFilter(matchResult, pattern, content) {
		finding := types.Finding{
			ID:          fmt.Sprintf("POLYMORPHIC_%s_%d", strings.ToUpper(pattern.Name), time.Now().UnixNano()),
			RuleID:      fmt.Sprintf("POLYMORPHIC_%s", strings.ToUpper(pattern.Name)),
			Severity:    pattern.Severity,
			Category:    pattern.Category,
			Title:       fmt.Sprintf("Polymorphic Attack Pattern: %s", pattern.Name),
			Description: apd.generateDescription(pattern, matchResult),
			Evidence:    strings.Join(matchResult.Evidence, ", "),
			Location:    filePath,
			Remediation: "Implement input validation and output encoding. Use allowlists instead of blocklists.",
			Timestamp:   time.Now(),
		}

		// Try to send finding, non-blocking
		select {
		case findingsChan <- finding:
		default:
			// Channel full, skip this finding
		}
	}
}

// generateDescription creates detailed description with scoring information
func (apd *AdvancedPatternDetector) generateDescription(pattern types.PolymorphicPattern, result types.PolymorphicMatchResult) string {
	if len(pattern.WeightedVariants) > 0 {
		return fmt.Sprintf("%s (Weighted Score: %.2f, Matches: %d, Confidence: %.2f)",
			pattern.Description, result.WeightedScore, result.MatchCount, result.Confidence)
	}

	// Legacy format for backward compatibility
	totalVariants := len(pattern.Variants)
	if totalVariants == 0 {
		totalVariants = len(pattern.WeightedVariants)
	}
	return fmt.Sprintf("%s (Score: %d/%d)", pattern.Description, len(result.MatchedVariants), totalVariants)
}

// passesfalsePositiveFilter applies sophisticated false positive filtering with algorithms
func (apd *AdvancedPatternDetector) passesfalsePositiveFilter(result types.PolymorphicMatchResult, pattern types.PolymorphicPattern, content string) bool {
	// Confidence threshold filtering with pattern-specific thresholds
	confidenceThreshold := apd.getConfidenceThreshold(pattern)
	if result.Confidence < confidenceThreshold {
		return false
	}

	// Evidence quality and quantity check
	if len(result.Evidence) == 0 {
		return false
	}

	// Context-aware filtering
	if !apd.validateEvidenceContext(result.Evidence, content) {
		return false
	}

	// File type and context exclusions
	if apd.shouldExcludeBasedOnContext(content, pattern) {
		return false
	}

	// Pattern-specific advanced filtering
	if !apd.applyPatternSpecificFiltering(result, pattern, content) {
		return false
	}

	// Entropy analysis for high-confidence patterns
	if pattern.Severity == "Critical" && !apd.validateEvidenceEntropy(result.Evidence) {
		return false
	}

	// Cross-reference validation - check for complementary security patterns
	if !apd.validateWithSecurityContext(result, content) {
		return false
	}

	return true
}

// getConfidenceThreshold returns pattern-specific confidence thresholds
func (apd *AdvancedPatternDetector) getConfidenceThreshold(pattern types.PolymorphicPattern) float64 {
	switch pattern.Severity {
	case "Critical":
		return 0.7 // Higher threshold for critical findings
	case "High":
		return 0.5
	case "Medium":
		return 0.3
	case "Low":
		return 0.2
	default:
		return 0.3 // Default moderate threshold
	}
}

// validateEvidenceContext checks if evidence appears in valid contexts
func (apd *AdvancedPatternDetector) validateEvidenceContext(evidence []string, content string) bool {
	validContexts := 0
	totalEvidence := len(evidence)

	for _, ev := range evidence {
		if apd.isValidEvidenceContext(ev, content) {
			validContexts++
		}
	}

	// Require at least 60% of evidence to be in valid contexts
	return float64(validContexts)/float64(totalEvidence) >= 0.6
}

// isValidEvidenceContext checks if a single piece of evidence is in a valid context
func (apd *AdvancedPatternDetector) isValidEvidenceContext(evidence, content string) bool {
	evidenceIndex := strings.Index(content, evidence)
	if evidenceIndex == -1 {
		return false
	}

	// Check context around evidence (500 characters window)
	contextStart := evidenceIndex - 250
	contextEnd := evidenceIndex + len(evidence) + 250
	if contextStart < 0 {
		contextStart = 0
	}
	if contextEnd > len(content) {
		contextEnd = len(content)
	}

	context := content[contextStart:contextEnd]

	// Check for invalidating contexts
	invalidatingPatterns := []string{
		"# Example:",
		"// Example:",
		"/* Example",
		"'''",
		`"""`,
		"console.log",
		"print(",
		"log.info",
		"log.debug",
		"// TODO:",
		"# TODO:",
		"// FIXME:",
		"# FIXME:",
		"test_",
		"spec_",
		"mock_",
		"fake_",
		"example_",
		"demo_",
		"placeholder",
	}

	for _, pattern := range invalidatingPatterns {
		if strings.Contains(context, pattern) {
			return false
		}
	}

	return true
}

// shouldExcludeBasedOnContext determines if findings should be excluded based on file context
func (apd *AdvancedPatternDetector) shouldExcludeBasedOnContext(content string, pattern types.PolymorphicPattern) bool {
	// Test file detection
	if apd.isTestFile(content) {
		// Only allow critical findings in test files
		return pattern.Severity != "Critical"
	}

	// Documentation context detection
	if apd.isDocumentationContext(content) {
		// Require higher evidence count for documentation
		return pattern.Threshold > 0 && pattern.Threshold < 3
	}

	// Configuration file detection
	if apd.isConfigurationFile(content) {
		// Skip most patterns in config files unless they're injection-related
		return pattern.Category != "Advanced Injection" && pattern.Category != "Command Injection"
	}

	// Template file detection
	if apd.isTemplateFile(content) {
		// Templates often contain pattern-like structures
		return pattern.Severity == "Low" || pattern.Severity == "Medium"
	}

	return false
}

// isConfigurationFile checks if content appears to be from a configuration file
func (apd *AdvancedPatternDetector) isConfigurationFile(content string) bool {
	configIndicators := []string{
		"config =",
		"settings =",
		"[database]",
		"[server]",
		"host =",
		"port =",
		"username =",
		"password =",
		"database_url",
		"connection_string",
		"api_key",
		"secret_key",
	}

	for _, indicator := range configIndicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}
	return false
}

// isTemplateFile checks if content appears to be from a template file
func (apd *AdvancedPatternDetector) isTemplateFile(content string) bool {
	templateIndicators := []string{
		"{{",
		"}}",
		"<%",
		"%>",
		"${",
		"}",
		"{% ",
		" %}",
		"<template>",
		"@template",
		"handlebars",
		"mustache",
		"jinja2",
	}

	for _, indicator := range templateIndicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}
	return false
}

// applyPatternSpecificFiltering applies filtering rules specific to pattern categories
func (apd *AdvancedPatternDetector) applyPatternSpecificFiltering(result types.PolymorphicMatchResult, pattern types.PolymorphicPattern, content string) bool {
	switch pattern.Category {
	case "Advanced Injection", "Command Injection":
		return apd.validateInjectionPattern(result, content)
	case "XSS", "Cross-site Scripting":
		return apd.validateXSSPattern(result, content)
	case "Path Traversal":
		return apd.validatePathTraversalPattern(result, content)
	case "Code Injection":
		return apd.validateCodeInjectionPattern(result, content)
	default:
		return true // No specific filtering for other categories
	}
}

// validateXSSPattern performs additional validation for XSS patterns
func (apd *AdvancedPatternDetector) validateXSSPattern(result types.PolymorphicMatchResult, content string) bool {
	// Check for XSS prevention mechanisms
	xssPreventionPatterns := []string{
		"htmlspecialchars",
		"htmlentities",
		"strip_tags",
		"filter_var",
		"FILTER_SANITIZE",
		"sanitize",
		"escape",
		"encodeURIComponent",
		"textContent",
		"innerText",
		"setAttribute",
		"createTextNode",
	}

	for _, evidence := range result.Evidence {
		evidenceIndex := strings.Index(content, evidence)
		if evidenceIndex > 0 {
			// Check 300 characters around evidence
			start := evidenceIndex - 150
			end := evidenceIndex + len(evidence) + 150
			if start < 0 {
				start = 0
			}
			if end > len(content) {
				end = len(content)
			}

			surroundingCode := content[start:end]
			for _, preventionPattern := range xssPreventionPatterns {
				if strings.Contains(surroundingCode, preventionPattern) {
					return false // XSS prevention detected
				}
			}
		}
	}

	return true
}

// validatePathTraversalPattern performs additional validation for path traversal patterns
func (apd *AdvancedPatternDetector) validatePathTraversalPattern(result types.PolymorphicMatchResult, content string) bool {
	// Check for path sanitization
	pathSanitizationPatterns := []string{
		"realpath",
		"abspath",
		"normpath",
		"path.resolve",
		"path.normalize",
		"path.join",
		"basename",
		"dirname",
		"os.path.join",
		"pathlib.Path",
		"Path(",
	}

	for _, evidence := range result.Evidence {
		evidenceIndex := strings.Index(content, evidence)
		if evidenceIndex > 0 {
			// Check surrounding code for path sanitization
			start := evidenceIndex - 200
			end := evidenceIndex + len(evidence) + 200
			if start < 0 {
				start = 0
			}
			if end > len(content) {
				end = len(content)
			}

			surroundingCode := content[start:end]
			for _, sanitizationPattern := range pathSanitizationPatterns {
				if strings.Contains(surroundingCode, sanitizationPattern) {
					return false // Path sanitization detected
				}
			}
		}
	}

	return true
}

// validateCodeInjectionPattern performs additional validation for code injection patterns
func (apd *AdvancedPatternDetector) validateCodeInjectionPattern(result types.PolymorphicMatchResult, content string) bool {
	// Check for safe evaluation contexts
	safeEvaluationPatterns := []string{
		"ast.literal_eval",
		"json.loads",
		"yaml.safe_load",
		"JSON.parse",
		"parseInt",
		"parseFloat",
		"Number(",
		"Boolean(",
	}

	for _, evidence := range result.Evidence {
		evidenceIndex := strings.Index(content, evidence)
		if evidenceIndex > 0 {
			// Check for safe alternatives nearby
			start := evidenceIndex - 100
			end := evidenceIndex + len(evidence) + 100
			if start < 0 {
				start = 0
			}
			if end > len(content) {
				end = len(content)
			}

			surroundingCode := content[start:end]
			for _, safePattern := range safeEvaluationPatterns {
				if strings.Contains(surroundingCode, safePattern) {
					return false // Safe evaluation detected
				}
			}
		}
	}

	return true
}

// validateEvidenceEntropy checks if evidence has sufficient entropy to be genuine
func (apd *AdvancedPatternDetector) validateEvidenceEntropy(evidence []string) bool {
	for _, ev := range evidence {
		if apd.calculateStringEntropy(ev) < 1.5 {
			return false // Too low entropy, likely a false positive
		}
	}
	return true
}

// calculateStringEntropy calculates the Shannon entropy of a string
func (apd *AdvancedPatternDetector) calculateStringEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count character frequencies
	charCount := make(map[rune]int)
	for _, char := range s {
		charCount[char]++
	}

	// Calculate entropy using simplified approximation
	entropy := 0.0
	length := float64(len(s))
	for _, count := range charCount {
		probability := float64(count) / length
		if probability > 0 {
			// Simplified entropy calculation (approximation)
			entropy += probability * (1.0 - probability)
		}
	}

	return entropy * 4.0 // Scale to approximate Shannon entropy
}

// validateWithSecurityContext cross-references with other security indicators
func (apd *AdvancedPatternDetector) validateWithSecurityContext(result types.PolymorphicMatchResult, content string) bool {
	// Check for security-related imports/libraries that might indicate intentional security testing
	securityTestingIndicators := []string{
		"import unittest",
		"import pytest",
		"from security",
		"import security",
		"penetration test",
		"security test",
		"vulnerability test",
		"exploit test",
		"attack simulation",
	}

	for _, indicator := range securityTestingIndicators {
		if strings.Contains(content, indicator) {
			// If this appears to be security testing code, require higher confidence
			return result.Confidence > 0.8
		}
	}

	return true
}

// isTestFile checks if content appears to be from a test file
func (apd *AdvancedPatternDetector) isTestFile(content string) bool {
	testIndicators := []string{
		"import unittest",
		"import pytest",
		"from unittest",
		"describe(",
		"it(",
		"test_",
		"Test",
		"@Test",
		"func Test",
	}

	for _, indicator := range testIndicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}
	return false
}

// isDocumentationContext checks if content appears to be documentation
func (apd *AdvancedPatternDetector) isDocumentationContext(content string) bool {
	docIndicators := []string{
		"# Example",
		"## Example",
		"* Example:",
		"For example:",
		"```",
		"<!-- ",
		"/**",
		"This is an example",
	}

	for _, indicator := range docIndicators {
		if strings.Contains(content, indicator) {
			return true
		}
	}
	return false
}

// validateInjectionPattern performs additional validation for injection patterns
func (apd *AdvancedPatternDetector) validateInjectionPattern(result types.PolymorphicMatchResult, content string) bool {
	// Check for sanitization functions nearby
	sanitizationFunctions := []string{
		"escape",
		"sanitize",
		"clean",
		"validate",
		"filter",
		"htmlspecialchars",
		"addslashes",
	}

	for _, evidence := range result.Evidence {
		evidenceIndex := strings.Index(content, evidence)
		if evidenceIndex > 0 {
			// Check surrounding 200 characters for sanitization
			start := evidenceIndex - 100
			end := evidenceIndex + len(evidence) + 100
			if start < 0 {
				start = 0
			}
			if end > len(content) {
				end = len(content)
			}

			surroundingCode := content[start:end]
			for _, sanitFunc := range sanitizationFunctions {
				if strings.Contains(surroundingCode, sanitFunc) {
					return false // Likely sanitized, reduce false positive
				}
			}
		}
	}

	return true
}

// detectPolymorphicAttacksLegacy contains the original hardcoded patterns for backward compatibility
func (apd *AdvancedPatternDetector) detectPolymorphicAttacksLegacy(content, filePath string, result *types.ScanResult) {
	// Define polymorphic patterns - attacks that can be expressed in multiple ways
	polymorphicPatterns := []struct {
		name        string
		variants    []string
		description string
		severity    string
	}{
		{
			name: "command_injection_variants",
			variants: []string{
				// Standard variants
				`exec\s*\(\s*["\'].*["\']`,
				`system\s*\(\s*["\'].*["\']`,
				`os\.system\s*\(`,
				`subprocess\.(run|call|Popen)`,

				// Obfuscated variants
				`eval\s*\(\s*["\'].*exec.*["\']`,
				`getattr\s*\(\s*__builtins__.*exec`,
				`compile\s*\(.*exec`,
				`__import__\s*\(\s*["\']os["\']`,

				// Encoded variants
				`eval\s*\(\s*base64\.b64decode`,
				`exec\s*\(\s*codecs\.decode`,
				`eval\s*\(\s*bytes\.fromhex`,

				// Dynamic construction variants
				`["\']ex["\'].*\+.*["\']ec["\']`,
				`chr\(101\).*chr\(120\).*chr\(101\).*chr\(99\)`, // exec in chr codes
				`\\x65\\x78\\x65\\x63`,                          // exec in hex
			},
			description: "Polymorphic command injection patterns",
			severity:    "Critical",
		},
		{
			name: "sql_injection_variants",
			variants: []string{
				// Standard SQL injection
				`UNION\s+SELECT`,
				`OR\s+1\s*=\s*1`,
				`AND\s+1\s*=\s*1`,
				`'\s*OR\s*'1'\s*=\s*'1`,

				// Obfuscated SQL injection
				`UN/\*\*/ION\s+SE/\*\*/LECT`,
				`OR\s+0x31\s*=\s*0x31`,
				`OR\s+CHAR\(49\)\s*=\s*CHAR\(49\)`,

				// Time-based blind SQL injection
				`WAITFOR\s+DELAY`,
				`SLEEP\s*\(\s*\d+\s*\)`,
				`pg_sleep\s*\(\s*\d+\s*\)`,

				// Boolean-based blind SQL injection
				`CASE\s+WHEN.*THEN.*ELSE`,
				`IF\s*\(.*,.*,.*\)`,
				`IIF\s*\(.*,.*,.*\)`,
			},
			description: "Polymorphic SQL injection patterns",
			severity:    "High",
		},
		{
			name: "xss_variants",
			variants: []string{
				// Standard XSS
				`<script.*>.*</script>`,
				`javascript:`,
				`on\w+\s*=\s*["\'].*["\']`,

				// Obfuscated XSS
				`<scr\+ipt>`,
				`<script/.*>`,
				`<script\s+.*>`,
				`&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;`, // javascript in hex entities

				// Event handler XSS
				`on(load|error|click|mouseover)\s*=`,
				`on\w+\s*=\s*alert`,
				`on\w+\s*=\s*confirm`,

				// Data URI XSS
				`data:text/html.*<script`,
				`data:application/javascript`,
				`data:text/javascript`,
			},
			description: "Polymorphic XSS patterns",
			severity:    "Medium",
		},
	}

	for _, pattern := range polymorphicPatterns {
		score := apd.calculateSimplePolymorphicScore(content, pattern.variants)

		// If multiple variants are detected, it's likely a polymorphic attack
		if score >= 2 {
			finding := types.Finding{
				ID:          fmt.Sprintf("POLYMORPHIC_%s_%d", strings.ToUpper(pattern.name), time.Now().UnixNano()),
				RuleID:      fmt.Sprintf("POLYMORPHIC_%s", strings.ToUpper(pattern.name)),
				Severity:    pattern.severity,
				Category:    "Advanced Threats",
				Title:       fmt.Sprintf("Polymorphic Attack Pattern: %s", pattern.name),
				Description: fmt.Sprintf("%s (Score: %d/10)", pattern.description, score),
				Evidence:    apd.extractPolymorphicEvidence(content, pattern.variants),
				Location:    filePath,
				Remediation: "Implement  input validation and output encoding. Use allowlists instead of blocklists.",
				Timestamp:   time.Now(),
			}
			result.Findings = append(result.Findings, finding)
		}
	}
}

// detectObfuscatedPayloads detects various obfuscation techniques
func (apd *AdvancedPatternDetector) detectObfuscatedPayloads(content, filePath string, result *types.ScanResult) {
	obfuscationPatterns := []struct {
		name        string
		pattern     string
		description string
		severity    string
	}{
		{
			name:        "base64_obfuscation",
			pattern:     `base64\.(b64decode|decode|decodebytes)\s*\(["\'][A-Za-z0-9+/=]{20,}["\']`,
			description: "Base64 encoded payload detected",
			severity:    "Medium",
		},
		{
			name:        "hex_obfuscation",
			pattern:     `(\\x[0-9a-fA-F]{2}){10,}`,
			description: "Hex encoded payload detected",
			severity:    "Medium",
		},
		{
			name:        "unicode_obfuscation",
			pattern:     `(\\u[0-9a-fA-F]{4}){5,}`,
			description: "Unicode encoded payload detected",
			severity:    "Medium",
		},
		{
			name:        "rot13_obfuscation",
			pattern:     `codecs\.decode\s*\(["\'].*["\'],\s*["\']rot_?13["\']`,
			description: "ROT13 encoded payload detected",
			severity:    "Low",
		},
		{
			name:        "string_concatenation_obfuscation",
			pattern:     `(["\'][a-zA-Z]{1,3}["\'](\s*\+\s*["\'][a-zA-Z]{1,3}["\']){5,})`,
			description: "String concatenation obfuscation detected",
			severity:    "Medium",
		},
		{
			name:        "chr_obfuscation",
			pattern:     `chr\s*\(\s*\d+\s*\)(\s*\+\s*chr\s*\(\s*\d+\s*\)){5,}`,
			description: "Character code obfuscation detected",
			severity:    "Medium",
		},
		{
			name:        "powershell_obfuscation",
			pattern:     `".*"\s*-[rR][eE][pP][lL][aA][cC][eE].*".*"`,
			description: "PowerShell string replacement obfuscation detected",
			severity:    "High",
		},
		{
			name:        "javascript_obfuscation",
			pattern:     `String\.fromCharCode\s*\(\s*\d+(\s*,\s*\d+){5,}\s*\)`,
			description: "JavaScript character code obfuscation detected",
			severity:    "Medium",
		},
	}

	for _, pattern := range obfuscationPatterns {
		if matched, _ := regexp.MatchString(pattern.pattern, content); matched {
			finding := types.Finding{
				ID:          fmt.Sprintf("OBFUSCATION_%s_%d", strings.ToUpper(pattern.name), time.Now().UnixNano()),
				RuleID:      fmt.Sprintf("OBFUSCATION_%s", strings.ToUpper(pattern.name)),
				Severity:    pattern.severity,
				Category:    "Obfuscation",
				Title:       fmt.Sprintf("Obfuscated Payload: %s", pattern.name),
				Description: pattern.description,
				Evidence:    apd.extractPatternEvidence(content, pattern.pattern),
				Location:    filePath,
				Remediation: "Implement payload decoding and analysis. Monitor for suspicious encoding patterns.",
				Timestamp:   time.Now(),
			}
			result.Findings = append(result.Findings, finding)
		}
	}
}

// detectBehavioralAnomalies detects unusual behavioral patterns using policy-defined patterns
func (apd *AdvancedPatternDetector) detectBehavioralAnomalies(content, filePath string, policy *types.SecurityPolicy, result *types.ScanResult) {
	if policy == nil {
		// Fallback to hardcoded patterns for backward compatibility when policy is nil
		apd.detectBehavioralAnomaliesLegacy(content, filePath, result)
		return
	}

	// Use policy-defined behavioral patterns if available
	if policy.BehavioralPatterns != nil && len(policy.BehavioralPatterns) > 0 {
		for _, behavior := range policy.BehavioralPatterns {
			count := 0
			evidence := []string{}

			for _, pattern := range behavior.Patterns {
				if matches := regexp.MustCompile(pattern).FindAllString(content, -1); len(matches) > 0 {
					count += len(matches)
					evidence = append(evidence, matches...)
				}
			}

			if count >= behavior.Threshold {
				finding := types.Finding{
					ID:          fmt.Sprintf("BEHAVIORAL_%s_%d", strings.ToUpper(behavior.Name), time.Now().UnixNano()),
					RuleID:      fmt.Sprintf("BEHAVIORAL_%s", strings.ToUpper(behavior.Name)),
					Severity:    behavior.Severity,
					Category:    behavior.Category,
					Title:       fmt.Sprintf("Behavioral Anomaly: %s", behavior.Name),
					Description: fmt.Sprintf("%s (Count: %d, Threshold: %d)", behavior.Description, count, behavior.Threshold),
					Evidence:    strings.Join(evidence[:min(len(evidence), 5)], ", "), // Limit evidence to 5 items
					Location:    filePath,
					Remediation: "Review code for legitimate use cases. Implement behavioral monitoring and anomaly detection.",
					Timestamp:   time.Now(),
				}
				result.Findings = append(result.Findings, finding)
			}
		}
		return
	}

	// Fallback to hardcoded patterns for backward compatibility
	apd.detectBehavioralAnomaliesLegacy(content, filePath, result)
}

// detectBehavioralAnomaliesLegacy contains the original hardcoded patterns for backward compatibility
func (apd *AdvancedPatternDetector) detectBehavioralAnomaliesLegacy(content, filePath string, result *types.ScanResult) {
	behavioralPatterns := []struct {
		name        string
		patterns    []string
		threshold   int
		description string
		severity    string
	}{
		{
			name: "excessive_network_activity",
			patterns: []string{
				`requests\.get\(`,
				`urllib\.request\.urlopen\(`,
				`http\.client\.HTTPConnection\(`,
				`socket\.socket\(`,
				`telnetlib\.Telnet\(`,
				`ftplib\.FTP\(`,
				`smtplib\.SMTP\(`,
			},
			threshold:   5,
			description: "Excessive network activity patterns detected",
			severity:    "Medium",
		},
		{
			name: "suspicious_file_operations",
			patterns: []string{
				`open\s*\(\s*["\']\/etc\/`,
				`open\s*\(\s*["\']\/var\/log\/`,
				`open\s*\(\s*["\']\/proc\/`,
				`os\.remove\(`,
				`shutil\.rmtree\(`,
				`os\.chmod\(.*777`,
				`os\.chown\(`,
			},
			threshold:   3,
			description: "Suspicious file operation patterns detected",
			severity:    "High",
		},
		{
			name: "crypto_mining_behavior",
			patterns: []string{
				`hashlib\.(sha256|md5|blake2b)`,
				`random\.randint\(.*100000`,
				`while\s+True:.*hash`,
				`multiprocessing\.Pool\(`,
				`threading\.Thread\(.*target=.*mine`,
				`gpu.*cuda`,
				`opencl`,
			},
			threshold:   3,
			description: "Potential cryptocurrency mining behavior detected",
			severity:    "Medium",
		},
		{
			name: "persistence_mechanisms",
			patterns: []string{
				`crontab\s+-e`,
				`\/etc\/rc\.local`,
				`\/etc\/init\.d\/`,
				`systemctl\s+enable`,
				`chkconfig\s+--add`,
				`HKEY_CURRENT_USER.*Run`,
				`HKEY_LOCAL_MACHINE.*Run`,
				`startup\s+folder`,
			},
			threshold:   2,
			description: "Persistence mechanism patterns detected",
			severity:    "High",
		},
	}

	for _, behavior := range behavioralPatterns {
		count := 0
		evidence := []string{}

		for _, pattern := range behavior.patterns {
			if matches := regexp.MustCompile(pattern).FindAllString(content, -1); len(matches) > 0 {
				count += len(matches)
				evidence = append(evidence, matches...)
			}
		}

		if count >= behavior.threshold {
			finding := types.Finding{
				ID:          fmt.Sprintf("BEHAVIORAL_%s_%d", strings.ToUpper(behavior.name), time.Now().UnixNano()),
				RuleID:      fmt.Sprintf("BEHAVIORAL_%s", strings.ToUpper(behavior.name)),
				Severity:    behavior.severity,
				Category:    "Behavioral Analysis",
				Title:       fmt.Sprintf("Behavioral Anomaly: %s", behavior.name),
				Description: fmt.Sprintf("%s (Count: %d, Threshold: %d)", behavior.description, count, behavior.threshold),
				Evidence:    strings.Join(evidence[:min(len(evidence), 5)], ", "), // Limit evidence to 5 items
				Location:    filePath,
				Remediation: "Review code for legitimate use cases. Implement behavioral monitoring and anomaly detection.",
				Timestamp:   time.Now(),
			}
			result.Findings = append(result.Findings, finding)
		}
	}
}

// detectSupplyChainAttacks detects potential supply chain attack indicators
func (apd *AdvancedPatternDetector) detectSupplyChainAttacks(content, filePath string, result *types.ScanResult) {
	supplyChainPatterns := []struct {
		name        string
		pattern     string
		description string
		severity    string
	}{
		{
			name:        "typosquatting_attempt",
			pattern:     `(import|from|require|include).*\b(reqeusts|beautifulsoup|pillov|numppy|pandass|mathplotlib)\b`,
			description: "Potential typosquatting dependency detected",
			severity:    "High",
		},
		{
			name:        "suspicious_repository",
			pattern:     `(git\s+clone|pip\s+install.*git\+|npm\s+install.*git\+).*\b(github\.io|gitlab\.io|bitbucket\.io|pastebin\.com)\b`,
			description: "Installation from suspicious repository detected",
			severity:    "Medium",
		},
		{
			name:        "dynamic_import",
			pattern:     `__import__\s*\(\s*input\(|importlib\.import_module\s*\(\s*input\(|eval\s*\(.*import`,
			description: "Dynamic import from user input detected",
			severity:    "Critical",
		},
		{
			name:        "package_download",
			pattern:     `(urllib|requests).*download.*\.(whl|tar\.gz|zip).*install`,
			description: "Direct package download and installation detected",
			severity:    "Medium",
		},
		{
			name:        "setup_py_manipulation",
			pattern:     `setup\s*\(\s*.*cmdclass.*\{.*\}`,
			description: "Setup.py command class manipulation detected",
			severity:    "High",
		},
	}

	for _, pattern := range supplyChainPatterns {
		if matched, _ := regexp.MatchString(pattern.pattern, content); matched {
			finding := types.Finding{
				ID:          fmt.Sprintf("SUPPLY_CHAIN_%s_%d", strings.ToUpper(pattern.name), time.Now().UnixNano()),
				RuleID:      fmt.Sprintf("SUPPLY_CHAIN_%s", strings.ToUpper(pattern.name)),
				Severity:    pattern.severity,
				Category:    "Supply Chain Security",
				Title:       fmt.Sprintf("Supply Chain Risk: %s", pattern.name),
				Description: pattern.description,
				Evidence:    apd.extractPatternEvidence(content, pattern.pattern),
				Location:    filePath,
				Remediation: "Verify package integrity and sources. Use dependency scanning tools and package registries.",
				Timestamp:   time.Now(),
			}
			result.Findings = append(result.Findings, finding)
		}
	}
}

// detectZeroDayPatterns detects potential zero-day exploit patterns
func (apd *AdvancedPatternDetector) detectZeroDayPatterns(content, filePath string, result *types.ScanResult) {
	zeroDayPatterns := []struct {
		name        string
		pattern     string
		description string
		severity    string
	}{
		{
			name:        "memory_corruption",
			pattern:     `(buffer\s+overflow|stack\s+overflow|heap\s+overflow|use.*after.*free|double.*free)`,
			description: "Memory corruption pattern detected",
			severity:    "Critical",
		},
		{
			name:        "prototype_pollution",
			pattern:     `__proto__.*=|constructor\[.*\].*=|prototype.*=.*function`,
			description: "JavaScript prototype pollution pattern detected",
			severity:    "High",
		},
		{
			name:        "deserialization_attack",
			pattern:     `(pickle\.loads|yaml\.load|json\.loads|marshal\.loads).*untrusted`,
			description: "Unsafe deserialization pattern detected",
			severity:    "Critical",
		},
		{
			name:        "race_condition",
			pattern:     `(threading.*lock|multiprocessing.*lock).*time\.sleep\(0\.0*1\)`,
			description: "Potential race condition exploitation detected",
			severity:    "Medium",
		},
		{
			name:        "integer_overflow",
			pattern:     `(sys\.maxsize|2\*\*63|2\*\*31).*(\+|\*|\-|\/)`,
			description: "Potential integer overflow pattern detected",
			severity:    "Medium",
		},
		{
			name:        "vm_escape",
			pattern:     `(virtualbox|vmware|qemu|hyperv).*escape|guest.*host.*breakout`,
			description: "Virtual machine escape pattern detected",
			severity:    "Critical",
		},
	}

	for _, pattern := range zeroDayPatterns {
		if matched, _ := regexp.MatchString(pattern.pattern, content); matched {
			finding := types.Finding{
				ID:          fmt.Sprintf("ZERO_DAY_%s_%d", strings.ToUpper(pattern.name), time.Now().UnixNano()),
				RuleID:      fmt.Sprintf("ZERO_DAY_%s", strings.ToUpper(pattern.name)),
				Severity:    pattern.severity,
				Category:    "Zero-Day Threats",
				Title:       fmt.Sprintf("Potential Zero-Day Pattern: %s", pattern.name),
				Description: pattern.description,
				Evidence:    apd.extractPatternEvidence(content, pattern.pattern),
				Location:    filePath,
				Remediation: "Implement advanced threat detection and monitoring. Review for legitimate use cases.",
				Timestamp:   time.Now(),
			}
			result.Findings = append(result.Findings, finding)
		}
	}
}

// Helper methods

// getCompiledPattern retrieves or compiles a regex pattern with caching for performance
func (apd *AdvancedPatternDetector) getCompiledPattern(pattern string) (*regexp.Regexp, error) {
	apd.cacheMutex.RLock()
	if compiled, exists := apd.patternCache.CompiledPatterns[pattern]; exists {
		apd.cacheMutex.RUnlock()
		apd.cacheMutex.Lock()
		apd.patternCache.CacheHits++
		apd.cacheMutex.Unlock()
		return compiled, nil
	}
	apd.cacheMutex.RUnlock()

	// Compile the pattern
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex pattern '%s': %w", pattern, err)
	}

	// Cache the compiled pattern
	apd.cacheMutex.Lock()
	apd.patternCache.CompiledPatterns[pattern] = compiled
	apd.patternCache.CacheMisses++
	apd.cacheMutex.Unlock()

	return compiled, nil
}

// calculatePolymorphicScore performs advanced weighted scoring with context analysis
func (apd *AdvancedPatternDetector) calculatePolymorphicScore(content string, pattern types.PolymorphicPattern) types.PolymorphicMatchResult {
	// Process weighted variants if available
	if len(pattern.WeightedVariants) > 0 {
		return apd.processWeightedVariants(content, pattern)
	}

	// Fallback to legacy string variants with default weights
	return apd.processLegacyVariants(content, pattern)
}

// processWeightedVariants handles patterns with explicit weights and contexts
func (apd *AdvancedPatternDetector) processWeightedVariants(content string, pattern types.PolymorphicPattern) types.PolymorphicMatchResult {
	result := types.PolymorphicMatchResult{
		PatternName:     pattern.Name,
		MatchedVariants: make([]types.VariantMatch, 0),
		Evidence:        make([]string, 0),
	}

	maxMatches := pattern.MaxMatches
	if maxMatches == 0 {
		maxMatches = 50 // Default limit for performance
	}

	for _, variant := range pattern.WeightedVariants {
		if len(result.MatchedVariants) >= maxMatches {
			break
		}

		weight := variant.Weight
		if weight == 0 {
			weight = 1.0 // Default weight
		}

		compiled, err := apd.getCompiledPattern(variant.Pattern)
		if err != nil {
			continue // Skip invalid patterns
		}

		matches := compiled.FindAllString(content, 5) // Limit matches per pattern
		if len(matches) > 0 {
			// Apply context-based weight adjustment
			adjustedWeight := apd.calculateContextWeight(content, variant, matches)

			variantMatch := types.VariantMatch{
				Pattern:  variant.Pattern,
				Weight:   adjustedWeight,
				Matches:  matches,
				Context:  variant.Context,
				Severity: variant.Severity,
			}

			result.MatchedVariants = append(result.MatchedVariants, variantMatch)
			result.WeightedScore += adjustedWeight * float64(len(matches))
			result.MatchCount += len(matches)

			// Collect evidence
			for _, match := range matches {
				if len(result.Evidence) < 10 { // Limit evidence
					result.Evidence = append(result.Evidence, match)
				}
			}
		}
	}

	result.TotalScore = float64(len(result.MatchedVariants))
	result.Confidence = apd.calculateConfidence(result, pattern)

	return result
}

// processLegacyVariants handles legacy string array patterns with default weights
func (apd *AdvancedPatternDetector) processLegacyVariants(content string, pattern types.PolymorphicPattern) types.PolymorphicMatchResult {
	result := types.PolymorphicMatchResult{
		PatternName:     pattern.Name,
		MatchedVariants: make([]types.VariantMatch, 0),
		Evidence:        make([]string, 0),
	}

	for _, variant := range pattern.Variants {
		compiled, err := apd.getCompiledPattern(variant)
		if err != nil {
			continue
		}

		matches := compiled.FindAllString(content, 3)
		if len(matches) > 0 {
			variantMatch := types.VariantMatch{
				Pattern: variant,
				Weight:  1.0, // Default weight for legacy patterns
				Matches: matches,
			}

			result.MatchedVariants = append(result.MatchedVariants, variantMatch)
			result.WeightedScore += 1.0 * float64(len(matches))
			result.MatchCount += len(matches)

			for _, match := range matches {
				if len(result.Evidence) < 10 {
					result.Evidence = append(result.Evidence, match)
				}
			}
		}
	}

	result.TotalScore = float64(len(result.MatchedVariants))
	result.Confidence = apd.calculateConfidence(result, pattern)

	return result
}

// calculateContextWeight adjusts pattern weight based on code context
func (apd *AdvancedPatternDetector) calculateContextWeight(content string, variant types.PatternVariant, matches []string) float64 {
	baseWeight := variant.Weight
	if baseWeight == 0 {
		baseWeight = 1.0
	}

	// Context-based adjustments
	contextMultiplier := 1.0

	// Reduce weight if found in comments
	for _, match := range matches {
		matchIndex := strings.Index(content, match)
		if matchIndex > 0 {
			// Check if match is in a comment (simple heuristic)
			lineStart := strings.LastIndex(content[:matchIndex], "\n") + 1
			lineEnd := strings.Index(content[matchIndex:], "\n")
			if lineEnd == -1 {
				lineEnd = len(content) - matchIndex
			}
			line := content[lineStart : matchIndex+lineEnd]

			if strings.Contains(line, "//") || strings.Contains(line, "#") || strings.Contains(line, "/*") {
				contextMultiplier *= 0.3 // Significantly reduce weight for comments
			}

			// Check if in string literal (basic detection)
			if strings.Count(line[:matchIndex-lineStart], `"`)%2 == 1 || strings.Count(line[:matchIndex-lineStart], `'`)%2 == 1 {
				contextMultiplier *= 0.5 // Reduce weight for string literals
			}
		}
	}

	// Apply severity-based weight boost
	switch variant.Severity {
	case "Critical":
		contextMultiplier *= 1.5
	case "High":
		contextMultiplier *= 1.2
	case "Low":
		contextMultiplier *= 0.8
	}

	return baseWeight * contextMultiplier
}

// calculateConfidence computes confidence score based on pattern matches and context
func (apd *AdvancedPatternDetector) calculateConfidence(result types.PolymorphicMatchResult, pattern types.PolymorphicPattern) float64 {
	if len(result.MatchedVariants) == 0 {
		return 0.0
	}

	// Base confidence from match ratio
	totalVariants := len(pattern.WeightedVariants)
	if totalVariants == 0 {
		totalVariants = len(pattern.Variants)
	}

	if totalVariants == 0 {
		return 0.0
	}

	matchRatio := float64(len(result.MatchedVariants)) / float64(totalVariants)

	// Weight-based confidence boost
	weightBoost := result.WeightedScore / (result.TotalScore + 1.0) // Avoid division by zero

	// Confidence based on evidence quality
	evidenceQuality := float64(len(result.Evidence)) / 10.0 // Normalize to 0-1
	if evidenceQuality > 1.0 {
		evidenceQuality = 1.0
	}

	confidence := (matchRatio*0.5 + weightBoost*0.3 + evidenceQuality*0.2)

	// Cap confidence at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// calculateSimplePolymorphicScore provides simple variant counting for legacy patterns
func (apd *AdvancedPatternDetector) calculateSimplePolymorphicScore(content string, variants []string) int {
	score := 0
	for _, variant := range variants {
		if compiled, err := apd.getCompiledPattern(variant); err == nil {
			if compiled.MatchString(content) {
				score++
			}
		}
	}
	// Cap the score at 10
	if score > 10 {
		return 10
	}
	return score
}

func (apd *AdvancedPatternDetector) extractPolymorphicEvidence(content string, variants []string) string {
	evidence := []string{}
	for _, variant := range variants {
		if matches := regexp.MustCompile(variant).FindAllString(content, 3); len(matches) > 0 {
			evidence = append(evidence, matches...)
		}
		if len(evidence) >= 5 { // Limit evidence
			break
		}
	}
	return strings.Join(evidence, ", ")
}

func (apd *AdvancedPatternDetector) extractPatternEvidence(content, pattern string) string {
	matches := regexp.MustCompile(pattern).FindAllString(content, 3)
	if len(matches) > 0 {
		return strings.Join(matches, ", ")
	}
	return "Pattern matched but no specific evidence extracted"
}
