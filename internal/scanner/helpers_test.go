package scanner

import (
	"testing"

	"github.com/syphon1c/mcp-security-scanner/internal/policy"
	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

func TestScannerCalculateRiskScore(t *testing.T) {
	// Initialize scanner with policy engine
	engine := policy.NewEngine()
	scanner := &Scanner{
		policyEngine: engine,
	}

	tests := []struct {
		name         string
		findings     []types.Finding
		expectedRisk string
		description  string
	}{
		{
			name: "CriticalRisk",
			findings: []types.Finding{
				{ID: "1", Severity: "Critical"},
				{ID: "2", Severity: "Critical"},
				{ID: "3", Severity: "Critical"},
				{ID: "4", Severity: "Critical"},
				{ID: "5", Severity: "Critical"},
			},
			expectedRisk: "Critical",
			description:  "Should calculate critical risk for multiple critical findings",
		},
		{
			name: "HighRisk",
			findings: []types.Finding{
				{ID: "1", Severity: "High"},
				{ID: "2", Severity: "High"},
				{ID: "3", Severity: "High"},
				{ID: "4", Severity: "High"},
				{ID: "5", Severity: "Medium"},
			},
			expectedRisk: "High",
			description:  "Should calculate high risk for multiple high findings",
		},
		{
			name: "MediumRisk",
			findings: []types.Finding{
				{ID: "1", Severity: "Medium"},
				{ID: "2", Severity: "Medium"},
				{ID: "3", Severity: "Medium"},
				{ID: "4", Severity: "Medium"},
			},
			expectedRisk: "Medium",
			description:  "Should calculate medium risk for medium findings",
		},
		{
			name: "LowRisk",
			findings: []types.Finding{
				{ID: "1", Severity: "Low"},
			},
			expectedRisk: "Low",
			description:  "Should calculate low risk for low findings",
		},
		{
			name:         "MinimalRisk",
			findings:     []types.Finding{},
			expectedRisk: "Minimal",
			description:  "Should calculate minimal risk for no findings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &types.ScanResult{
				Findings: tt.findings,
			}

			// Call the scanner's CalculateRiskScore method
			scanner.CalculateRiskScore(result)

			if result.OverallRisk != tt.expectedRisk {
				t.Errorf("Expected risk level '%s', got '%s'. Description: %s",
					tt.expectedRisk, result.OverallRisk, tt.description)
			}

			// Verify score is set
			if result.RiskScore == 0 && len(tt.findings) > 0 {
				t.Errorf("Expected non-zero risk score for findings, got 0")
			}
		})
	}
}

func TestScannerIsSourceFile(t *testing.T) {
	scanner := &Scanner{}

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "PythonFile",
			path:     "test.py",
			expected: true,
		},
		{
			name:     "GoFile",
			path:     "test.go",
			expected: true,
		},
		{
			name:     "JavaScriptFile",
			path:     "test.js",
			expected: true,
		},
		{
			name:     "TypeScriptFile",
			path:     "test.ts",
			expected: true,
		},
		{
			name:     "JavaFile",
			path:     "test.java",
			expected: true,
		},
		{
			name:     "ConfigFile",
			path:     "config.yaml",
			expected: true,
		},
		{
			name:     "BinaryFile",
			path:     "test.exe",
			expected: false,
		},
		{
			name:     "ImageFile",
			path:     "image.png",
			expected: false,
		},
		{
			name:     "EmptyPath",
			path:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.isSourceFile(tt.path)
			if result != tt.expected {
				t.Errorf("Expected isSourceFile('%s') to be %v, got %v",
					tt.path, tt.expected, result)
			}
		})
	}
}

func TestScannerExtractEvidence(t *testing.T) {
	scanner := &Scanner{}

	tests := []struct {
		name     string
		content  string
		pattern  string
		expected string
	}{
		{
			name:     "SimpleMatch",
			content:  "This is a test string with password123 in it",
			pattern:  "password\\d+",
			expected: "Matches found: [password123]",
		},
		{
			name:     "NoMatch",
			content:  "This is a clean string",
			pattern:  "suspicious",
			expected: "Pattern match detected",
		},
		{
			name:     "MultipleMatches",
			content:  "secret1 and secret2 are here",
			pattern:  "secret\\d+",
			expected: "Matches found: [secret1 secret2]", // Returns all matches
		},
		{
			name:     "EmptyContent",
			content:  "",
			pattern:  "test",
			expected: "Pattern match detected",
		},
		{
			name:     "EmptyPattern",
			content:  "test content",
			pattern:  "",
			expected: "Matches found: [  ]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.extractEvidence(tt.content, tt.pattern)
			if result != tt.expected {
				t.Errorf("Expected extractEvidence to return '%s', got '%s'",
					tt.expected, result)
			}
		})
	}
}

func TestScannerExtractEvidenceWithLineInfo(t *testing.T) {
	scanner := &Scanner{}

	content := `line 1
line 2 with password123
line 3
line 4 with secret456
line 5`

	tests := []struct {
		name             string
		pattern          string
		expectedEvidence string
		expectedLine     int
		expectedCodeLine string
	}{
		{
			name:             "FirstMatch",
			pattern:          "password\\d+",
			expectedEvidence: "Matches found: [password123]",
			expectedLine:     2,
			expectedCodeLine: "line 2 with password123",
		},
		{
			name:             "SecondMatch",
			pattern:          "secret\\d+",
			expectedEvidence: "Matches found: [secret456]",
			expectedLine:     4,
			expectedCodeLine: "line 4 with secret456",
		},
		{
			name:             "NoMatch",
			pattern:          "nonexistent",
			expectedEvidence: "Pattern match detected",
			expectedLine:     0,
			expectedCodeLine: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evidence, lineNum, codeLine, context := scanner.extractEvidenceWithLineInfo(content, tt.pattern)

			if evidence != tt.expectedEvidence {
				t.Errorf("Expected evidence '%s', got '%s'", tt.expectedEvidence, evidence)
			}

			if lineNum != tt.expectedLine {
				t.Errorf("Expected line number %d, got %d", tt.expectedLine, lineNum)
			}

			if codeLine != tt.expectedCodeLine {
				t.Errorf("Expected code line '%s', got '%s'", tt.expectedCodeLine, codeLine)
			}

			// Verify context is provided when there's a match
			if tt.expectedLine > 0 && len(context) == 0 {
				t.Error("Expected code context to be provided for matches")
			}
		})
	}
}

func TestScannerGetPolicyEngine(t *testing.T) {
	engine := policy.NewEngine()
	scanner := &Scanner{
		policyEngine: engine,
	}

	result := scanner.GetPolicyEngine()

	if result != engine {
		t.Error("GetPolicyEngine should return the same policy engine instance")
	}

	if result == nil {
		t.Error("GetPolicyEngine should not return nil")
	}
}

func TestScannerExtractCodeContext(t *testing.T) {
	scanner := &Scanner{}

	lines := []string{
		"line 1",
		"line 2",
		"line 3",
		"line 4",
		"line 5",
		"line 6",
		"line 7",
	}

	tests := []struct {
		name           string
		centerLine     int
		contextSize    int
		expectedLength int
		expectedStart  string
		expectedEnd    string
	}{
		{
			name:           "MiddleLineWithContext",
			centerLine:     4, // line 4 (0-indexed would be 3)
			contextSize:    2,
			expectedLength: 5, // 2 before + center + 2 after
			expectedStart:  "   2: line 2",
			expectedEnd:    "   6: line 6",
		},
		{
			name:           "FirstLineWithContext",
			centerLine:     1, // line 1
			contextSize:    2,
			expectedLength: 3, // can't go before line 1
			expectedStart:  ">> 1: line 1",
			expectedEnd:    "   3: line 3",
		},
		{
			name:           "LastLineWithContext",
			centerLine:     7, // line 7
			contextSize:    2,
			expectedLength: 3, // can't go after line 7
			expectedStart:  "   5: line 5",
			expectedEnd:    ">> 7: line 7",
		},
		{
			name:           "SingleLineContext",
			centerLine:     3,
			contextSize:    0,
			expectedLength: 1,
			expectedStart:  ">> 3: line 3",
			expectedEnd:    ">> 3: line 3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert to 0-indexed for the method call
			context := scanner.extractCodeContext(lines, tt.centerLine-1, tt.contextSize)

			if len(context) != tt.expectedLength {
				t.Errorf("Expected context length %d, got %d", tt.expectedLength, len(context))
			}

			if len(context) > 0 {
				if context[0] != tt.expectedStart {
					t.Errorf("Expected context to start with '%s', got '%s'", tt.expectedStart, context[0])
				}

				if context[len(context)-1] != tt.expectedEnd {
					t.Errorf("Expected context to end with '%s', got '%s'", tt.expectedEnd, context[len(context)-1])
				}
			}
		})
	}
}
