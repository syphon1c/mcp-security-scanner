package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

func TestNewEngine(t *testing.T) {
	engine := NewEngine()

	if engine == nil {
		t.Fatal("NewEngine() returned nil")
	}

	if engine.policies == nil {
		t.Fatal("Engine policies map is nil")
	}

	if len(engine.policies) != 0 {
		t.Errorf("Expected empty policies map, got %d policies", len(engine.policies))
	}
}

func TestLoadPoliciesFromDirectory(t *testing.T) {
	tests := []struct {
		name           string
		setupFiles     map[string]string
		expectedErr    bool
		expectedCount  int
		expectSpecific []string
	}{
		{
			name: "ValidSinglePolicy",
			setupFiles: map[string]string{
				"test-policy.json": `{
					"version": "1.0",
					"policyName": "test-policy",
					"description": "Test policy",
					"severity": "High",
					"rules": [
						{
							"id": "TEST_001",
							"title": "Test Rule",
							"category": "Testing",
							"severity": "Medium",
							"patterns": ["test.*pattern"],
							"description": "A test rule",
							"remediation": "Fix the test issue"
						}
					],
					"blockedPatterns": [],
					"riskThresholds": {
						"critical": 50,
						"high": 30,
						"medium": 15,
						"low": 5
					}
				}`,
			},
			expectedErr:    false,
			expectedCount:  1,
			expectSpecific: []string{"test-policy"},
		},
		{
			name: "MultiplePolicies",
			setupFiles: map[string]string{
				"policy1.json": `{
					"version": "1.0",
					"policyName": "policy-one",
					"description": "First policy",
					"severity": "High",
					"rules": [],
					"blockedPatterns": [],
					"riskThresholds": {"critical": 50, "high": 30, "medium": 15, "low": 5}
				}`,
				"policy2.json": `{
					"version": "1.0",
					"policyName": "policy-two",
					"description": "Second policy",
					"severity": "Medium",
					"rules": [],
					"blockedPatterns": [],
					"riskThresholds": {"critical": 50, "high": 30, "medium": 15, "low": 5}
				}`,
			},
			expectedErr:    false,
			expectedCount:  2,
			expectSpecific: []string{"policy-one", "policy-two"},
		},
		{
			name: "InvalidJSONPolicy",
			setupFiles: map[string]string{
				"invalid.json": `{
					"version": "1.0",
					"policyName": "invalid-policy",
					"description": "Invalid policy"
					// Missing closing bracket and other required fields
				`,
			},
			expectedErr:    true,
			expectedCount:  0,
			expectSpecific: []string{},
		},
		{
			name: "EmptyDirectory",
			setupFiles: map[string]string{
				"readme.txt": "This is not a JSON file",
			},
			expectedErr:    false,
			expectedCount:  0,
			expectSpecific: []string{},
		},
		{
			name: "MixedValidInvalid",
			setupFiles: map[string]string{
				"valid.json": `{
					"version": "1.0",
					"policyName": "valid-policy",
					"description": "Valid policy",
					"severity": "High",
					"rules": [],
					"blockedPatterns": [],
					"riskThresholds": {"critical": 50, "high": 30, "medium": 15, "low": 5}
				}`,
				"invalid.json": `{"invalid": "json"`,
				"not-json.txt": "This is not JSON",
			},
			expectedErr:    false,
			expectedCount:  1,
			expectSpecific: []string{"valid-policy"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary directory
			tempDir := t.TempDir()

			// Setup test files
			for filename, content := range tt.setupFiles {
				filePath := filepath.Join(tempDir, filename)
				err := os.WriteFile(filePath, []byte(content), 0644)
				if err != nil {
					t.Fatalf("Failed to create test file %s: %v", filename, err)
				}
			}

			// Test loading policies
			engine := NewEngine()
			err := engine.LoadPoliciesFromDirectory(tempDir)

			// Check error expectation
			if tt.expectedErr && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectedErr && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// Check policy count
			if len(engine.policies) != tt.expectedCount {
				t.Errorf("Expected %d policies, got %d", tt.expectedCount, len(engine.policies))
			}

			// Check specific policies exist
			for _, policyName := range tt.expectSpecific {
				if _, exists := engine.policies[policyName]; !exists {
					t.Errorf("Expected policy '%s' to be loaded", policyName)
				}
			}
		})
	}
}

func TestLoadPoliciesFromDirectory_NonexistentDirectory(t *testing.T) {
	engine := NewEngine()
	err := engine.LoadPoliciesFromDirectory("/nonexistent/directory/path")

	if err == nil {
		t.Error("Expected error for nonexistent directory, got nil")
	}
}

func TestGetPolicy(t *testing.T) {
	engine := NewEngine()

	// Create a test policy
	testPolicy := &types.SecurityPolicy{
		Version:     "1.0",
		PolicyName:  "test-policy",
		Description: "Test policy for unit tests",
		Severity:    "High",
		Rules: []types.SecurityRule{
			{
				ID:          "TEST_001",
				Name:        "Test Rule",
				Category:    "Testing",
				Severity:    "Medium",
				Patterns:    []string{"test.*pattern"},
				Description: "A test rule",
			},
		},
		BlockedPatterns: []types.BlockedPattern{},
		RiskThresholds: types.RiskThresholds{
			Critical: 50,
			High:     30,
			Medium:   15,
			Low:      5,
		},
	}

	// Add policy to engine manually
	engine.policies["test-policy"] = testPolicy

	tests := []struct {
		name        string
		policyName  string
		expectError bool
		expectNil   bool
	}{
		{
			name:        "ExistingPolicy",
			policyName:  "test-policy",
			expectError: false,
			expectNil:   false,
		},
		{
			name:        "NonexistentPolicy",
			policyName:  "nonexistent-policy",
			expectError: true,
			expectNil:   true,
		},
		{
			name:        "EmptyPolicyName",
			policyName:  "",
			expectError: true,
			expectNil:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy, err := engine.GetPolicy(tt.policyName)

			if tt.expectError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if tt.expectNil && policy != nil {
				t.Error("Expected nil policy but got non-nil")
			}
			if !tt.expectNil && policy == nil {
				t.Error("Expected non-nil policy but got nil")
			}

			// If we expect a valid policy, verify its contents
			if !tt.expectError && !tt.expectNil {
				if policy.PolicyName != tt.policyName {
					t.Errorf("Expected policy name '%s', got '%s'", tt.policyName, policy.PolicyName)
				}
				if policy.Version != "1.0" {
					t.Errorf("Expected version '1.0', got '%s'", policy.Version)
				}
			}
		})
	}
}

func TestListPolicies(t *testing.T) {
	engine := NewEngine()

	// Test empty engine
	policies := engine.ListPolicies()
	if len(policies) != 0 {
		t.Errorf("Expected 0 policies from empty engine, got %d", len(policies))
	}

	// Add test policies
	testPolicies := map[string]*types.SecurityPolicy{
		"policy1": {
			PolicyName:  "policy1",
			Version:     "1.0",
			Description: "First test policy",
			Severity:    "High",
		},
		"policy2": {
			PolicyName:  "policy2",
			Version:     "1.1",
			Description: "Second test policy",
			Severity:    "Medium",
		},
		"policy3": {
			PolicyName:  "policy3",
			Version:     "2.0",
			Description: "Third test policy",
			Severity:    "Critical",
		},
	}

	for name, policy := range testPolicies {
		engine.policies[name] = policy
	}

	// Test populated engine
	policies = engine.ListPolicies()
	if len(policies) != 3 {
		t.Errorf("Expected 3 policies, got %d", len(policies))
	}

	// Verify all expected policies are present
	for expectedName, expectedPolicy := range testPolicies {
		description, exists := policies[expectedName]
		if !exists {
			t.Errorf("Expected policy '%s' not found in results", expectedName)
		}

		expectedDescription := expectedPolicy.Description + " (" + expectedPolicy.Severity + ")"
		if description != expectedDescription {
			t.Errorf("Expected description '%s', got '%s'", expectedDescription, description)
		}
	}
}

func TestPolicyValidation(t *testing.T) {
	tests := []struct {
		name        string
		policyJSON  string
		expectError bool
		description string
	}{
		{
			name: "ValidMinimalPolicy",
			policyJSON: `{
				"version": "1.0",
				"policyName": "minimal-policy",
				"description": "Minimal valid policy",
				"severity": "Medium",
				"rules": [],
				"blockedPatterns": [],
				"riskThresholds": {
					"critical": 50,
					"high": 30,
					"medium": 15,
					"low": 5
				}
			}`,
			expectError: false,
			description: "Should accept minimal valid policy",
		},
		{
			name: "ValidComplexPolicy",
			policyJSON: `{
				"version": "1.0",
				"policyName": "complex-policy",
				"description": "Complex policy with multiple rules",
				"severity": "High",
				"rules": [
					{
						"id": "CMD_001",
						"title": "Command Injection",
						"category": "Injection",
						"severity": "Critical",
						"patterns": ["exec\\\\s*\\\\(", "system\\\\s*\\\\("],
						"description": "Command injection patterns",
						"remediation": "Use parameterized commands"
					},
					{
						"id": "SQL_001",
						"title": "SQL Injection",
						"category": "Injection", 
						"severity": "High",
						"patterns": ["SELECT.*\\\\+.*", "INSERT.*\\\\+.*"],
						"description": "SQL injection patterns",
						"remediation": "Use parameterized queries"
					}
				],
				"blockedPatterns": [
					{
						"pattern": "rm\\\\s+-rf",
						"type": "regex",
						"category": "command",
						"description": "Dangerous file deletion command"
					},
					{
						"pattern": "DROP\\\\s+TABLE",
						"type": "regex", 
						"category": "sql",
						"description": "SQL table deletion command"
					}
				],
				"riskThresholds": {
					"critical": 80,
					"high": 60,
					"medium": 30,
					"low": 10
				}
			}`,
			expectError: false,
			description: "Should accept complex policy with multiple rules",
		},
		{
			name: "MissingRequiredFields",
			policyJSON: `{
				"version": "1.0",
				"description": "Policy missing policyName"
			}`,
			expectError: true,
			description: "Should reject policy missing required fields",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			policyFile := filepath.Join(tempDir, "test-policy.json")

			err := os.WriteFile(policyFile, []byte(tt.policyJSON), 0644)
			if err != nil {
				t.Fatalf("Failed to create test policy file: %v", err)
			}

			engine := NewEngine()
			err = engine.LoadPoliciesFromDirectory(tempDir)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got nil: %s", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got %v: %s", err, tt.description)
			}
		})
	}
}
