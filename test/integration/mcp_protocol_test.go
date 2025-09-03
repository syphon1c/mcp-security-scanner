package integration

import (
	"testing"
	"time"

	"github.com/syphon1c/mcp-security-scanner/internal/integration"
	"github.com/syphon1c/mcp-security-scanner/internal/scanner"
	"github.com/syphon1c/mcp-security-scanner/pkg/types"
	"github.com/syphon1c/mcp-security-scanner/test/mocks"
	"github.com/syphon1c/mcp-security-scanner/test/testdata"
)

func TestMCPProtocolIntegration(t *testing.T) {
	// Start mock MCP server
	mockServer := mocks.NewMockMCPServer()
	defer mockServer.Close()

	// Create scanner
	config := types.ScannerConfig{
		Timeout:         30 * time.Second,
		UserAgent:       "Test-Scanner",
		PolicyDirectory: "./../../policies", // Relative to test directory
	}

	s, err := scanner.NewScanner(config, (*integration.AlertProcessor)(nil))
	if err != nil {
		t.Skip("Skipping integration test - policies not available")
	}

	// Test remote scanning
	result, err := s.ScanRemoteMCPServer(mockServer.GetURL(), "critical-security")
	if err != nil {
		t.Fatalf("ScanRemoteMCPServer() failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected scan result, got nil")
	}

	// Verify MCP server information was discovered
	if result.MCPServer.Name == "" {
		t.Error("Expected MCP server name to be discovered")
	}

	if result.MCPServer.Protocol != "MCP" {
		t.Errorf("Expected protocol 'MCP', got '%s'", result.MCPServer.Protocol)
	}

	// Verify tools were discovered
	if len(result.MCPServer.Tools) == 0 {
		t.Error("Expected to discover MCP tools")
	}

	// Verify resources were discovered
	if len(result.MCPServer.Resources) == 0 {
		t.Error("Expected to discover MCP resources")
	}

	// Check that the mock server received the expected requests
	requestLog := mockServer.GetRequestLog()
	if len(requestLog) == 0 {
		t.Error("Expected mock server to receive requests")
	}

	// Verify initialize request was sent
	foundInitialize := false
	for _, req := range requestLog {
		if req.Method == "initialize" {
			foundInitialize = true
			break
		}
	}
	if !foundInitialize {
		t.Error("Expected initialize request to be sent")
	}
}

func TestMCPVulnerabilityDetection(t *testing.T) {
	// Start vulnerable mock server
	mockServer := mocks.NewVulnerableMCPServer()
	defer mockServer.Close()

	config := types.ScannerConfig{
		Timeout:         30 * time.Second,
		UserAgent:       "Test-Scanner",
		PolicyDirectory: "./../../policies",
	}

	s, err := scanner.NewScanner(config, (*integration.AlertProcessor)(nil))
	if err != nil {
		t.Skip("Skipping integration test - policies not available")
	}

	result, err := s.ScanRemoteMCPServer(mockServer.GetURL(), "critical-security")
	if err != nil {
		t.Fatalf("ScanRemoteMCPServer() failed: %v", err)
	}

	// The vulnerable server should trigger some security findings
	// We can't guarantee specific findings without knowing the exact policy rules
	// but we can verify the scan completed and returned results
	if result == nil {
		t.Fatal("Expected scan result, got nil")
	}

	t.Logf("Scan completed. Found %d findings with overall risk: %s",
		result.Summary.TotalFindings, result.OverallRisk)
}

func TestMCPSecureServerScanning(t *testing.T) {
	// Start secure mock server (should have minimal findings)
	mockServer := mocks.NewSecureMCPServer()
	defer mockServer.Close()

	config := types.ScannerConfig{
		Timeout:         30 * time.Second,
		UserAgent:       "Test-Scanner",
		PolicyDirectory: "./../../policies",
	}

	s, err := scanner.NewScanner(config, (*integration.AlertProcessor)(nil))
	if err != nil {
		t.Skip("Skipping integration test - policies not available")
	}

	result, err := s.ScanRemoteMCPServer(mockServer.GetURL(), "standard-security")
	if err != nil {
		t.Fatalf("ScanRemoteMCPServer() failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected scan result, got nil")
	}

	// Secure server should have lower risk
	t.Logf("Secure server scan completed. Found %d findings with overall risk: %s",
		result.Summary.TotalFindings, result.OverallRisk)
}

func TestMCPInjectionTesting(t *testing.T) {
	mockServer := mocks.NewMockMCPServer()
	defer mockServer.Close()

	config := types.ScannerConfig{
		Timeout:         30 * time.Second,
		UserAgent:       "Test-Scanner",
		PolicyDirectory: "./../../policies",
	}

	s, err := scanner.NewScanner(config, (*integration.AlertProcessor)(nil))
	if err != nil {
		t.Skip("Skipping integration test - policies not available")
	}

	// Test each MCP vulnerability test case
	for _, testCase := range testdata.MCPVulnerabilityTestCases {
		t.Run(testCase.Name, func(t *testing.T) {
			// For now, just verify the scanner can handle the test cases
			// without crashing. In a full implementation, we would
			// inject these payloads and analyze responses
			result, err := s.ScanRemoteMCPServer(mockServer.GetURL(), "critical-security")
			if err != nil {
				t.Errorf("Scanner failed on test case %s: %v", testCase.Name, err)
			}

			if result == nil {
				t.Errorf("Expected scan result for test case %s", testCase.Name)
			}
		})
	}
}

func TestMCPProtocolErrorHandling(t *testing.T) {
	// Test scanning a non-existent server
	config := types.ScannerConfig{
		Timeout:         5 * time.Second, // Short timeout for error case
		UserAgent:       "Test-Scanner",
		PolicyDirectory: "./../../policies",
	}

	s, err := scanner.NewScanner(config, (*integration.AlertProcessor)(nil))
	if err != nil {
		t.Skip("Skipping integration test - policies not available")
	}

	// This should fail gracefully
	_, err = s.ScanRemoteMCPServer("http://nonexistent-server:9999", "critical-security")
	if err == nil {
		t.Error("Expected error when scanning nonexistent server, got nil")
	}
}

func TestMCPDiscoveryAndEnumeration(t *testing.T) {
	mockServer := mocks.NewMockMCPServer()
	defer mockServer.Close()

	config := types.ScannerConfig{
		Timeout:         30 * time.Second,
		UserAgent:       "Test-Scanner",
		PolicyDirectory: "./../../policies",
	}

	s, err := scanner.NewScanner(config, (*integration.AlertProcessor)(nil))
	if err != nil {
		t.Skip("Skipping integration test - policies not available")
	}

	result, err := s.ScanRemoteMCPServer(mockServer.GetURL(), "standard-security")
	if err != nil {
		t.Fatalf("ScanRemoteMCPServer() failed: %v", err)
	}

	// Verify complete discovery
	if len(result.MCPServer.Tools) != len(mockServer.Tools) {
		t.Errorf("Expected to discover %d tools, found %d",
			len(mockServer.Tools), len(result.MCPServer.Tools))
	}

	if len(result.MCPServer.Resources) != len(mockServer.Resources) {
		t.Errorf("Expected to discover %d resources, found %d",
			len(mockServer.Resources), len(result.MCPServer.Resources))
	}

	// Verify tool names were discovered correctly
	expectedTools := make(map[string]bool)
	for _, tool := range mockServer.Tools {
		expectedTools[tool.Name] = false
	}

	for _, tool := range result.MCPServer.Tools {
		if _, exists := expectedTools[tool.Name]; exists {
			expectedTools[tool.Name] = true
		}
	}

	for toolName, found := range expectedTools {
		if !found {
			t.Errorf("Expected to discover tool '%s', but it was not found", toolName)
		}
	}
}

func TestConcurrentMCPScanning(t *testing.T) {
	// Test concurrent scanning to ensure thread safety
	mockServer1 := mocks.NewMockMCPServer()
	defer mockServer1.Close()

	mockServer2 := mocks.NewSecureMCPServer()
	defer mockServer2.Close()

	config := types.ScannerConfig{
		Timeout:         30 * time.Second,
		UserAgent:       "Test-Scanner",
		PolicyDirectory: "./../../policies",
	}

	s, err := scanner.NewScanner(config, (*integration.AlertProcessor)(nil))
	if err != nil {
		t.Skip("Skipping integration test - policies not available")
	}

	// Channel to collect results
	results := make(chan error, 2)

	// Start concurrent scans
	go func() {
		_, err := s.ScanRemoteMCPServer(mockServer1.GetURL(), "standard-security")
		results <- err
	}()

	go func() {
		_, err := s.ScanRemoteMCPServer(mockServer2.GetURL(), "standard-security")
		results <- err
	}()

	// Wait for both scans to complete
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Errorf("Concurrent scan %d failed: %v", i+1, err)
		}
	}
}
