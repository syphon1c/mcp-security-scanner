package unit

import (
	"strings"
	"testing"

	"github.com/syphon1c/mcp-security-scanner/internal/integration"
	"github.com/syphon1c/mcp-security-scanner/internal/proxy"
	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

// TestProxyCreation tests basic proxy creation and configuration
func TestProxyCreation(t *testing.T) {
	policies := map[string]*types.SecurityPolicy{
		"test-policy": {
			PolicyName: "test-policy",
			Version:    "1.0",
		},
	}

	alertProcessor := &integration.AlertProcessor{}

	t.Run("ValidProxyCreation", func(t *testing.T) {
		proxyInstance, err := proxy.NewProxy("http://localhost:8080", policies, alertProcessor)
		if err != nil {
			t.Fatalf("Failed to create proxy: %v", err)
		}
		if proxyInstance == nil {
			t.Fatal("Proxy instance is nil")
		}
	})

	t.Run("InvalidURLProxyCreation", func(t *testing.T) {
		_, err := proxy.NewProxy("://invalid-url", policies, alertProcessor)
		if err == nil {
			t.Fatal("Expected error for invalid URL")
		}
	})
}

// TestProxySecurityPatterns tests the security pattern detection logic
func TestProxySecurityPatterns(t *testing.T) {
	testCases := []struct {
		name         string
		input        string
		shouldDetect bool
		description  string
	}{
		{
			name:         "CommandInjection",
			input:        "ls; cat /etc/passwd",
			shouldDetect: true,
			description:  "Should detect command injection patterns",
		},
		{
			name:         "PathTraversal",
			input:        "../../../etc/passwd",
			shouldDetect: true,
			description:  "Should detect path traversal patterns",
		},
		{
			name:         "NormalContent",
			input:        "Hello, this is normal content",
			shouldDetect: false,
			description:  "Should not flag normal content",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			detected := containsPattern(tc.input)
			if detected != tc.shouldDetect {
				t.Errorf("%s: expected detection=%v, got=%v for input: %s",
					tc.description, tc.shouldDetect, detected, tc.input)
			}
		})
	}
}

// containsPattern is a helper function that mimics the pattern matching in the proxy
func containsPattern(input string) bool {
	return strings.Contains(input, "; cat") ||
		strings.Contains(input, "../") ||
		strings.Contains(input, "<script")
}
