package scanner

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/syphon1c/mcp-security-scanner/internal/policy"
	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

// isSourceFile determines if a given file path represents a source code file based on its extension.
// The function maintains a comprehensive list of common source code file extensions and performs
// case-insensitive matching to accommodate various naming conventions.
//
// Parameters:
//   - path: Complete file path including filename and extension
//
// Returns:
//   - bool: True if the file is identified as source code, false otherwise
//
// Supported source code extensions include: .js, .ts, .py, .go, .java, .php, .rb, .cpp, .c,
// .sh, .ps1, .rs, .cs, .scala, .kt and others commonly used in enterprise development.
func (s *Scanner) isSourceFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	sourceExtensions := []string{".js", ".ts", ".py", ".go", ".java", ".php", ".rb", ".cpp", ".c", ".sh", ".ps1", ".rs", ".cs", ".scala", ".kt", ".yaml", ".yml", ".json", ".xml"}

	for _, srcExt := range sourceExtensions {
		if ext == srcExt {
			return true
		}
	}
	return false
}

// applyRuleToContent applies security rule patterns to content and creates vulnerability findings.
// The function performs regex pattern matching against the provided content and extracts detailed
// evidence including line numbers, code context, and surrounding lines for analysis. Each match
// generates a comprehensive finding with unique identification and timestamp.
//
// Parameters:
//   - content: Source code or configuration content to analyze
//   - rule: Security rule containing patterns, severity, and metadata
//   - location: File path or identifier where the content originates
//   - result: Scan result struct that will be populated with new findings
//
// The function handles regex compilation errors gracefully and extracts rich evidence
// including line numbers, matched code lines, and surrounding context for security analysis.
// Each finding receives a unique ID based on rule ID and nanosecond timestamp.
func (s *Scanner) applyRuleToContent(content string, rule types.SecurityRule, location string, result *types.ScanResult) {
	for _, pattern := range rule.Patterns {
		matched, err := regexp.MatchString(pattern, content)
		if err != nil {
			continue
		}

		if matched {
			evidence, lineNumber, codeLine, codeContext := s.extractEvidenceWithLineInfo(content, pattern)
			finding := types.Finding{
				ID:          fmt.Sprintf("%s-%d", rule.ID, time.Now().UnixNano()),
				RuleID:      rule.ID,
				Severity:    rule.Severity,
				Category:    rule.Category,
				Title:       rule.Name,
				Description: rule.Description,
				Evidence:    evidence,
				Location:    location,
				LineNumber:  lineNumber,
				CodeLine:    codeLine,
				CodeContext: codeContext,
				Remediation: "Review and remediate based on security policy",
				Timestamp:   time.Now(),
			}
			result.Findings = append(result.Findings, finding)
		}
	}
}

// checkBlockedPattern checks content against blocked patterns
func (s *Scanner) checkBlockedPattern(content string, pattern types.BlockedPattern, location string, result *types.ScanResult) {
	var matched bool
	var err error

	switch pattern.Type {
	case "regex":
		matched, err = regexp.MatchString(pattern.Pattern, content)
	case "exact":
		matched = strings.Contains(content, pattern.Pattern)
	case "contains":
		matched = strings.Contains(strings.ToLower(content), strings.ToLower(pattern.Pattern))
	default:
		return // Unknown pattern type
	}

	if err != nil {
		return
	}

	if matched {
		evidence, lineNumber, codeLine, codeContext := s.extractEvidenceForPatternWithLineInfo(content, pattern)
		finding := types.Finding{
			ID:          fmt.Sprintf("blocked-pattern-%d", time.Now().UnixNano()),
			RuleID:      "BLOCKED_PATTERN_001",
			Severity:    "High",
			Category:    pattern.Category,
			Title:       "Blocked Pattern Detected",
			Description: pattern.Description,
			Evidence:    evidence,
			Location:    location,
			LineNumber:  lineNumber,
			CodeLine:    codeLine,
			CodeContext: codeContext,
			Remediation: "Remove or replace blocked pattern",
			Timestamp:   time.Now(),
		}
		result.Findings = append(result.Findings, finding)
	}
}

// checkForSensitiveDataInConfig checks configuration files for sensitive data
func (s *Scanner) checkForSensitiveDataInConfig(content string, location string, result *types.ScanResult) {
	sensitivePatterns := map[string]string{
		`password\s*[=:]\s*[^\s]+`:        "Hardcoded password",
		`api[_-]?key\s*[=:]\s*[^\s]+`:     "API key exposure",
		`secret\s*[=:]\s*[^\s]+`:          "Secret exposure",
		`token\s*[=:]\s*[^\s]+`:           "Token exposure",
		`private[_-]?key\s*[=:]\s*[^\s]+`: "Private key exposure",
		`mongodb://[^\\s]+`:               "Database connection string",
		`mysql://[^\\s]+`:                 "Database connection string",
		`postgres://[^\\s]+`:              "Database connection string",
	}

	for pattern, description := range sensitivePatterns {
		matched, err := regexp.MatchString("(?i)"+pattern, content)
		if err != nil {
			continue
		}

		if matched {
			evidence, lineNumber, codeLine, codeContext := s.extractEvidenceWithLineInfo(content, pattern)
			finding := types.Finding{
				ID:          fmt.Sprintf("sensitive-config-%d", time.Now().UnixNano()),
				RuleID:      "SENSITIVE_CONFIG_001",
				Severity:    "High",
				Category:    "Configuration Security",
				Title:       "Sensitive Data in Configuration",
				Description: description,
				Evidence:    evidence,
				Location:    location,
				LineNumber:  lineNumber,
				CodeLine:    codeLine,
				CodeContext: codeContext,
				Remediation: "Move sensitive data to environment variables or secure storage",
				Timestamp:   time.Now(),
			}
			result.Findings = append(result.Findings, finding)
		}
	}
}

// detectInjectionSuccess analyzes response to detect successful injection
func (s *Scanner) detectInjectionSuccess(responseBody []byte, payload string) bool {
	response := string(responseBody)

	// Indicators of successful command injection
	successIndicators := []string{
		"uid=", "gid=", // Unix user info
		"root:", "admin:", // Password file entries
		"Volume in drive", "Directory of", // Windows dir command
		"total ", "drwx", // Unix ls command
		"Microsoft Windows",         // Windows version
		"Linux version",             // Linux version
		"Permission denied",         // File access errors
		"No such file or directory", // File not found
	}

	// Template injection indicators
	templateIndicators := []string{
		"49", "7777", // Common template injection results (7*7=49, 7777)
		"<script>", "alert(", // XSS success
	}

	// SQL injection indicators
	sqlIndicators := []string{
		"SQL syntax", "mysql_", "ORA-", "PostgreSQL",
		"syntax error", "database error",
	}

	allIndicators := append(successIndicators, templateIndicators...)
	allIndicators = append(allIndicators, sqlIndicators...)

	for _, indicator := range allIndicators {
		if strings.Contains(strings.ToLower(response), strings.ToLower(indicator)) {
			return true
		}
	}

	// Check if payload is reflected in response (potential for further exploitation)
	if strings.Contains(response, payload) {
		return true
	}

	return false
}

// extractEvidence extracts evidence from content based on pattern
func (s *Scanner) extractEvidence(content, pattern string) string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "Pattern match found"
	}

	matches := re.FindAllString(content, 3) // Limit to 3 matches
	if len(matches) > 0 {
		return fmt.Sprintf("Matches found: %v", matches)
	}
	return "Pattern match detected"
}

// extractEvidenceWithLineInfo extracts evidence with line number and code context
func (s *Scanner) extractEvidenceWithLineInfo(content, pattern string) (string, int, string, []string) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "Pattern match found", 0, "", nil
	}

	lines := strings.Split(content, "\n")
	for lineNum, line := range lines {
		if re.MatchString(line) {
			// Found a match
			evidence := s.extractEvidence(content, pattern)
			lineNumber := lineNum + 1 // 1-indexed
			codeLine := strings.TrimSpace(line)

			// Extract context lines (2 before, 2 after)
			context := s.extractCodeContext(lines, lineNum, 2)

			return evidence, lineNumber, codeLine, context
		}
	}

	// Fallback to original extraction if no line match found
	evidence := s.extractEvidence(content, pattern)
	return evidence, 0, "", nil
}

// extractCodeContext extracts surrounding lines for context
func (s *Scanner) extractCodeContext(lines []string, centerLine, contextSize int) []string {
	start := centerLine - contextSize
	if start < 0 {
		start = 0
	}

	end := centerLine + contextSize + 1
	if end > len(lines) {
		end = len(lines)
	}

	context := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		prefix := "   "
		if i == centerLine {
			prefix = ">> " // Mark the actual line with the issue
		}
		context = append(context, fmt.Sprintf("%s%d: %s", prefix, i+1, lines[i]))
	}

	return context
}

// extractEvidenceForPattern extracts evidence for blocked patterns
func (s *Scanner) extractEvidenceForPattern(content string, pattern types.BlockedPattern) string {
	switch pattern.Type {
	case "regex":
		return s.extractEvidence(content, pattern.Pattern)
	case "exact", "contains":
		// Find the exact match with some context
		index := strings.Index(strings.ToLower(content), strings.ToLower(pattern.Pattern))
		if index >= 0 {
			start := index - 20
			if start < 0 {
				start = 0
			}
			end := index + len(pattern.Pattern) + 20
			if end > len(content) {
				end = len(content)
			}
			return fmt.Sprintf("Found at position %d: ...%s...", index, content[start:end])
		}
	}
	return "Pattern match detected"
}

// extractEvidenceForPatternWithLineInfo extracts evidence with line info for blocked patterns
func (s *Scanner) extractEvidenceForPatternWithLineInfo(content string, pattern types.BlockedPattern) (string, int, string, []string) {
	switch pattern.Type {
	case "regex":
		return s.extractEvidenceWithLineInfo(content, pattern.Pattern)
	case "exact", "contains":
		lines := strings.Split(content, "\n")
		searchPattern := strings.ToLower(pattern.Pattern)

		for lineNum, line := range lines {
			if strings.Contains(strings.ToLower(line), searchPattern) {
				// Found a match
				evidence := s.extractEvidenceForPattern(content, pattern)
				lineNumber := lineNum + 1 // 1-indexed
				codeLine := strings.TrimSpace(line)

				// Extract context lines
				context := s.extractCodeContext(lines, lineNum, 2)

				return evidence, lineNumber, codeLine, context
			}
		}
	}

	// Fallback
	evidence := s.extractEvidenceForPattern(content, pattern)
	return evidence, 0, "", nil
}

// CalculateRiskScore calculates the overall risk score for scan results
func (s *Scanner) CalculateRiskScore(result *types.ScanResult) {
	score := 0
	for _, finding := range result.Findings {
		switch finding.Severity {
		case "Critical":
			score += 10
		case "High":
			score += 7
		case "Medium":
			score += 4
		case "Low":
			score += 1
		}
	}

	// Cap the score at 100 to match documentation (0-100 range)
	if score > 100 {
		score = 100
	}

	result.RiskScore = score

	// Determine overall risk level
	if score >= 50 {
		result.OverallRisk = "Critical"
	} else if score >= 30 {
		result.OverallRisk = "High"
	} else if score >= 15 {
		result.OverallRisk = "Medium"
	} else if score > 0 {
		result.OverallRisk = "Low"
	} else {
		result.OverallRisk = "Minimal"
	}
}

// generateSummary generates a summary of scan findings
func (s *Scanner) generateSummary(result *types.ScanResult) {
	summary := types.ScanSummary{
		TotalFindings: len(result.Findings),
	}

	for _, finding := range result.Findings {
		switch finding.Severity {
		case "Critical":
			summary.CriticalFindings++
		case "High":
			summary.HighFindings++
		case "Medium":
			summary.MediumFindings++
		case "Low":
			summary.LowFindings++
		}
	}

	result.Summary = summary
}

// GetPolicyEngine returns the policy engine for external access
func (s *Scanner) GetPolicyEngine() *policy.Engine {
	return s.policyEngine
}
