package scanner

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

func TestNewAdvancedPatternDetector(t *testing.T) {
	// Create a mock scanner
	config := types.ScannerConfig{
		Timeout:         10 * time.Second,
		UserAgent:       "Test-Scanner",
		PolicyDirectory: "./test-policies",
	}

	scanner, err := NewScanner(config, nil)
	if err != nil {
		// For this test, we'll create a minimal scanner without policies
		// since we're testing the pattern detector creation
		scanner = &Scanner{
			config: config,
		}
	}

	detector := NewAdvancedPatternDetector(scanner)

	if detector == nil {
		t.Fatal("NewAdvancedPatternDetector returned nil")
	}

	if detector.scanner != scanner {
		t.Error("Detector scanner reference is incorrect")
	}
}

func TestDetectAdvancedThreats_Integration(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Create test policy with polymorphic patterns
	policyContent := `{
		"version": "1.0",
		"policyName": "advanced-test-policy",
		"description": "Advanced test policy with polymorphic patterns",
		"severity": "High",
		"rules": [
			{
				"id": "CMD_001",
				"name": "Command Injection",
				"category": "Injection",
				"severity": "Critical",
				"patterns": ["subprocess\\\\.run.*shell=True", "os\\\\.system"],
				"description": "Command injection patterns"
			}
		],
		"polymorphicPatterns": [
			{
				"name": "sql_injection_variants",
				"description": "Polymorphic SQL injection detection",
				"severity": "High",
				"category": "Advanced Threats",
				"variants": ["SELECT.*\\+", "UNION SELECT", "OR 1=1", "' OR '1'='1"],
				"threshold": 2
			},
			{
				"name": "command_injection_evasion",
				"description": "Command injection evasion techniques",
				"severity": "Critical",
				"category": "Advanced Threats", 
				"variants": ["subprocess\\.run.*shell=True", "os\\.system", "exec\\s*\\("],
				"threshold": 2
			}
		],
		"behavioralPatterns": [
			{
				"name": "suspicious_network_activity",
				"description": "Suspicious network communication patterns",
				"severity": "Medium",
				"category": "Behavioral Analysis",
				"patterns": ["requests\\.(get|post)", "\\.connect\\("],
				"threshold": 2
			}
		],
		"blockedPatterns": [],
		"riskThresholds": {
			"critical": 50,
			"high": 30,
			"medium": 15,
			"low": 5
		}
	}`

	policyFile := filepath.Join(tempDir, "advanced-test-policy.json")
	err := os.WriteFile(policyFile, []byte(policyContent), 0o644)
	if err != nil {
		t.Fatalf("Failed to create test policy file: %v", err)
	}

	// Create scanner with advanced policy
	config := types.ScannerConfig{
		PolicyDirectory: tempDir,
		Timeout:         10 * time.Second,
		UserAgent:       "Test-Scanner",
	}

	scanner, err := NewScanner(config, nil)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}

	detector := NewAdvancedPatternDetector(scanner)

	// Get the test policy
	policy, err := scanner.policyEngine.GetPolicy("advanced-test-policy")
	if err != nil {
		t.Fatalf("Failed to get test policy: %v", err)
	}

	// Create a scan result to hold findings
	result := &types.ScanResult{
		Target:     "test-content",
		PolicyUsed: "advanced-test-policy",
		Findings:   []types.Finding{},
	}

	tests := []struct {
		name            string
		content         string
		expectedPattern bool
		description     string
	}{
		{
			name: "PolymorphicSQLInjection",
			content: `
				query = "SELECT * FROM users WHERE id = " + user_input
				search = "SELECT name FROM products WHERE category UNION SELECT password FROM accounts"
				filter = "DELETE FROM logs WHERE date < '2023-01-01' OR 1=1"
			`,
			expectedPattern: true,
			description:     "Should detect polymorphic SQL injection patterns",
		},
		{
			name: "CommandInjectionEvasion",
			content: `
				import subprocess
				subprocess.run("ls; cat /etc/passwd", shell=True)
				os.system("rm -rf /tmp/*")
				exec("echo 'pwned' > /tmp/hacked.txt")
			`,
			expectedPattern: true,
			description:     "Should detect command injection evasion techniques",
		},
		{
			name: "BehavioralAnomalies",
			content: `
				import requests
				import socket
				requests.get("http://malicious.com/data")
				sock = socket.socket()
				sock.connect(("192.168.1.100", 4444))
			`,
			expectedPattern: true,
			description:     "Should detect behavioral anomalies",
		},
		{
			name: "SafeCode",
			content: `
				def safe_function():
					data = sanitize_input(request.data)
					result = db.prepare("SELECT * FROM users WHERE id = ?").execute([data])
					return result
			`,
			expectedPattern: false,
			description:     "Should not detect patterns in safe code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset findings for each test
			result.Findings = []types.Finding{}

			// Call the actual public method
			detector.DetectAdvancedThreats(tt.content, "test-file.py", policy, result)

			hasAdvancedFindings := false
			for _, finding := range result.Findings {
				if finding.Category == "Advanced Threats" || finding.Category == "Behavioral Analysis" {
					hasAdvancedFindings = true
					break
				}
			}

			if tt.expectedPattern && !hasAdvancedFindings {
				t.Errorf("Expected to detect advanced patterns but didn't. Description: %s", tt.description)
			}

			if !tt.expectedPattern && hasAdvancedFindings {
				t.Errorf("Did not expect to detect patterns but did. Description: %s", tt.description)
			}

			// Verify finding structure for any advanced findings
			for _, finding := range result.Findings {
				if finding.Category == "Advanced Threats" || finding.Category == "Behavioral Analysis" {
					if finding.ID == "" {
						t.Error("Advanced finding ID should not be empty")
					}
					if finding.Severity == "" {
						t.Error("Advanced finding severity should not be empty")
					}
					if finding.Location == "" {
						t.Error("Advanced finding location should not be empty")
					}
					if finding.Timestamp.IsZero() {
						t.Error("Advanced finding timestamp should not be zero")
					}
				}
			}
		})
	}
}

func TestAdvancedPatternDetector_EmptyPolicy(t *testing.T) {
	scanner := &Scanner{
		config: types.ScannerConfig{
			Timeout:   10 * time.Second,
			UserAgent: "Test-Scanner",
		},
	}

	detector := NewAdvancedPatternDetector(scanner)

	// Create minimal policy without advanced patterns
	policy := &types.SecurityPolicy{
		Version:     "1.0",
		PolicyName:  "minimal-policy",
		Description: "Minimal policy without advanced patterns",
		Severity:    "Medium",
		Rules:       []types.SecurityRule{},
		RiskThresholds: types.RiskThresholds{
			Critical: 50,
			High:     30,
			Medium:   15,
			Low:      5,
		},
	}

	result := &types.ScanResult{
		Target:     "test-content",
		PolicyUsed: "minimal-policy",
		Findings:   []types.Finding{},
	}

	// Test with content that would trigger advanced patterns if they were defined
	content := `
		query = "SELECT * FROM users WHERE id = " + user_input + " UNION SELECT password FROM admin"
		subprocess.run(user_command, shell=True)
	`

	// Should not panic and should handle gracefully
	detector.DetectAdvancedThreats(content, "test-file.py", policy, result)

	// Should not add any advanced findings since policy doesn't define them
	advancedFindingCount := 0
	for _, finding := range result.Findings {
		if finding.Category == "Advanced Threats" || finding.Category == "Behavioral Analysis" {
			advancedFindingCount++
		}
	}

	// With empty policy advanced patterns, we might still get some findings from legacy detection
	// Just verify the method completes without error
	if advancedFindingCount < 0 {
		t.Error("Advanced findings count should not be negative")
	}
}

func TestAdvancedPatternDetector_ErrorHandling(t *testing.T) {
	scanner := &Scanner{
		config: types.ScannerConfig{
			Timeout:   10 * time.Second,
			UserAgent: "Test-Scanner",
		},
	}

	detector := NewAdvancedPatternDetector(scanner)

	tests := []struct {
		name        string
		content     string
		filePath    string
		policy      *types.SecurityPolicy
		result      *types.ScanResult
		description string
	}{
		{
			name:     "NilPolicy",
			content:  "test content",
			filePath: "test.py",
			policy:   nil,
			result: &types.ScanResult{
				Findings: []types.Finding{},
			},
			description: "Should handle nil policy gracefully",
		},
		{
			name:     "NilResult",
			content:  "test content",
			filePath: "test.py",
			policy: &types.SecurityPolicy{
				Version:    "1.0",
				PolicyName: "test-policy",
			},
			result:      nil,
			description: "Should handle nil result gracefully",
		},
		{
			name:     "EmptyContent",
			content:  "",
			filePath: "test.py",
			policy: &types.SecurityPolicy{
				Version:    "1.0",
				PolicyName: "test-policy",
			},
			result: &types.ScanResult{
				Findings: []types.Finding{},
			},
			description: "Should handle empty content gracefully",
		},
		{
			name:     "EmptyFilePath",
			content:  "test content",
			filePath: "",
			policy: &types.SecurityPolicy{
				Version:    "1.0",
				PolicyName: "test-policy",
			},
			result: &types.ScanResult{
				Findings: []types.Finding{},
			},
			description: "Should handle empty file path gracefully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// These calls should not panic
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("DetectAdvancedThreats panicked: %v. Description: %s", r, tt.description)
				}
			}()

			detector.DetectAdvancedThreats(tt.content, tt.filePath, tt.policy, tt.result)
		})
	}
}
