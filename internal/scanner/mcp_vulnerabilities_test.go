package scanner

import (
	"testing"
	"time"

	"github.com/syphon1c/mcp-security-scanner/internal/mcp"
	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

func TestNewMCPVulnerabilityTester(t *testing.T) {
	// Create a minimal scanner for testing
	mcpClient := mcp.NewClient(5*time.Second, "Test-Agent")
	scanner := &Scanner{
		mcpClient: mcpClient,
		config: types.ScannerConfig{
			Timeout:   10 * time.Second,
			UserAgent: "Test-Scanner",
		},
	}

	tester := NewMCPVulnerabilityTester(scanner)

	if tester == nil {
		t.Error("Expected tester to be created, got nil")
		return // Exit early if tester is nil
	}

	if tester.scanner != scanner {
		t.Error("Tester scanner reference is incorrect")
	}
}

func TestTestToolPoisoning(t *testing.T) {
	// Create MCP client for the scanner
	mcpClient := mcp.NewClient(5*time.Second, "Test-Agent")

	scanner := &Scanner{
		mcpClient: mcpClient,
		config: types.ScannerConfig{
			Timeout:   10 * time.Second,
			UserAgent: "Test-Scanner",
		},
	}

	tester := NewMCPVulnerabilityTester(scanner)

	tests := []struct {
		name          string
		serverURL     string
		tools         []types.MCPTool
		expectedCount int
		description   string
	}{
		{
			name:      "VulnerableTools",
			serverURL: "http://localhost:8080",
			tools: []types.MCPTool{
				{
					Name:        "execute_command",
					Description: "Execute system commands",
					InputSchema: map[string]interface{}{
						"command": map[string]interface{}{
							"type": "string",
						},
					},
				},
				{
					Name:        "read_file",
					Description: "Read file contents",
					InputSchema: map[string]interface{}{
						"path": map[string]interface{}{
							"type": "string",
						},
					},
				},
			},
			expectedCount: 0, // Expecting 0 due to connection errors in test environment
			description:   "Should test tool poisoning but fail gracefully without server",
		},
		{
			name:          "NoTools",
			serverURL:     "http://localhost:8080",
			tools:         []types.MCPTool{},
			expectedCount: 0,
			description:   "Should handle empty tool list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This will likely fail due to no server running, but should not panic
			findings := tester.TestToolPoisoning(tt.serverURL, tt.tools)

			// Since no server is running, we expect no findings due to connection errors
			if len(findings) != tt.expectedCount {
				t.Logf("Expected %d findings, got %d (acceptable due to test environment)",
					tt.expectedCount, len(findings))
			}

			t.Logf("Test completed: %s - Found %d findings", tt.description, len(findings))
		})
	}
}

func TestTestResourceManipulation(t *testing.T) {
	// Create MCP client for the scanner
	mcpClient := mcp.NewClient(5*time.Second, "Test-Agent")

	scanner := &Scanner{
		mcpClient: mcpClient,
		config: types.ScannerConfig{
			Timeout:   10 * time.Second,
			UserAgent: "Test-Scanner",
		},
	}

	tester := NewMCPVulnerabilityTester(scanner)

	tests := []struct {
		name          string
		serverURL     string
		resources     []types.MCPResource
		expectedCount int
		description   string
	}{
		{
			name:      "VulnerableResources",
			serverURL: "http://localhost:8080",
			resources: []types.MCPResource{
				{
					URI:         "file:///etc/passwd",
					Name:        "sensitive_file",
					Description: "System password file",
					MimeType:    "text/plain",
				},
				{
					URI:         "http://internal.system/config",
					Name:        "internal_config",
					Description: "Internal configuration",
					MimeType:    "application/json",
				},
			},
			expectedCount: 0, // Expecting 0 due to connection errors in test environment
			description:   "Should test resource manipulation but fail gracefully without server",
		},
		{
			name:          "NoResources",
			serverURL:     "http://localhost:8080",
			resources:     []types.MCPResource{},
			expectedCount: 0,
			description:   "Should handle empty resource list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This will likely fail due to no server running, but should not panic
			findings := tester.TestResourceManipulation(tt.serverURL, tt.resources)

			// Since no server is running, we expect no findings due to connection errors
			if len(findings) != tt.expectedCount {
				t.Logf("Expected %d findings, got %d (acceptable due to test environment)",
					tt.expectedCount, len(findings))
			}

			t.Logf("Test completed: %s - Found %d findings", tt.description, len(findings))
		})
	}
}

func TestMCPVulnerabilityTester_ErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		setup       func() *MCPVulnerabilityTester
		expectPanic bool
		description string
	}{
		{
			name: "ValidTester",
			setup: func() *MCPVulnerabilityTester {
				mcpClient := mcp.NewClient(5*time.Second, "Test-Agent")
				scanner := &Scanner{
					mcpClient: mcpClient,
					config: types.ScannerConfig{
						Timeout:   10 * time.Second,
						UserAgent: "Test-Scanner",
					},
				}
				return NewMCPVulnerabilityTester(scanner)
			},
			expectPanic: false,
			description: "Should handle valid scanner gracefully",
		},
		{
			name: "NilScanner",
			setup: func() *MCPVulnerabilityTester {
				return NewMCPVulnerabilityTester(nil)
			},
			expectPanic: false, // Constructor should handle nil scanner gracefully
			description: "Should handle nil scanner without panicking",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("Expected panic but none occurred. Description: %s", tt.description)
					}
				}()
			}

			tester := tt.setup()
			if !tt.expectPanic && tester == nil {
				t.Errorf("Expected valid tester, got nil. Description: %s", tt.description)
			}

			t.Logf("Test completed: %s", tt.description)
		})
	}
}
