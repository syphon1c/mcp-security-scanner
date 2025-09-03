package reporting

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

func TestNewReportManager(t *testing.T) {
	manager := NewReportManager()

	if manager == nil {
		t.Fatal("NewReportManager() should not return nil")
	}

	// Test that manager can be used immediately
	if manager.htmlReporter != nil || manager.pdfReporter != nil {
		t.Log("Reporters may be lazily initialized")
	}
}

func TestReportManager_GenerateJSONReport(t *testing.T) {
	manager := NewReportManager()
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "test_report.json")

	scanResult := createTestScanResult()

	err := manager.GenerateReport(scanResult, outputPath, FormatJSON)
	if err != nil {
		t.Fatalf("GenerateReport() failed: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("JSON report file was not created")
	}

	// Verify file content
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read report file: %v", err)
	}

	var result types.ScanResult
	err = json.Unmarshal(data, &result)
	if err != nil {
		t.Fatalf("Failed to parse JSON report: %v", err)
	}

	// Verify content
	if result.Target != scanResult.Target {
		t.Errorf("Expected target %s, got %s", scanResult.Target, result.Target)
	}

	if len(result.Findings) != len(scanResult.Findings) {
		t.Errorf("Expected %d findings, got %d", len(scanResult.Findings), len(result.Findings))
	}
}

func TestReportManager_GenerateTextReport(t *testing.T) {
	manager := NewReportManager()
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "test_report.txt")

	scanResult := createTestScanResult()

	err := manager.GenerateReport(scanResult, outputPath, FormatText)
	if err != nil {
		t.Fatalf("GenerateReport() failed: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("Text report file was not created")
	}

	// Verify file content
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read report file: %v", err)
	}

	content := string(data)

	// Check for expected content
	expectedContent := []string{
		"MCP Security Scanner Report",
		scanResult.Target,
		scanResult.OverallRisk,
		"Critical: 1",
		"High: 1",
		"Medium: 1",
		"Low: 1",
	}

	for _, expected := range expectedContent {
		if !strings.Contains(content, expected) {
			t.Errorf("Text report should contain '%s'", expected)
		}
	}
}

func TestReportManager_GenerateHTMLReport(t *testing.T) {
	manager := NewReportManager()
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "test_report.html")

	scanResult := createTestScanResult()

	err := manager.GenerateReport(scanResult, outputPath, FormatHTML)
	if err != nil {
		t.Fatalf("GenerateReport() failed: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("HTML report file was not created")
	}

	// Verify file content
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read report file: %v", err)
	}

	content := string(data)

	// Check for HTML structure
	expectedHTMLElements := []string{
		"<html",
		"<head>",
		"<body>",
		"MCP Security Scanner Report",
		scanResult.Target,
	}

	for _, expected := range expectedHTMLElements {
		if !strings.Contains(content, expected) {
			t.Errorf("HTML report should contain '%s'", expected)
		}
	}
}

func TestReportManager_GeneratePDFReport(t *testing.T) {
	manager := NewReportManager()
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "test_report.pdf")

	scanResult := createTestScanResult()

	err := manager.GenerateReport(scanResult, outputPath, FormatPDF)
	if err != nil {
		t.Fatalf("GenerateReport() failed: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("PDF report file was not created")
	}

	// Verify it's a PDF file (check magic bytes)
	file, err := os.Open(outputPath)
	if err != nil {
		t.Fatalf("Failed to open PDF file: %v", err)
	}
	defer file.Close()

	header := make([]byte, 4)
	_, err = file.Read(header)
	if err != nil {
		t.Fatalf("Failed to read PDF header: %v", err)
	}

	if string(header) != "%PDF" {
		t.Error("Generated file is not a valid PDF")
	}
}

func TestReportManager_UnsupportedFormat(t *testing.T) {
	manager := NewReportManager()
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "test_report.unknown")

	scanResult := createTestScanResult()

	err := manager.GenerateReport(scanResult, outputPath, OutputFormat("unknown"))
	if err == nil {
		t.Error("Expected error for unsupported format")
	}

	// Verify file was not created
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Error("Report file should not be created for unsupported format")
	}
}

func TestReportManager_InvalidOutputPath(t *testing.T) {
	manager := NewReportManager()
	invalidPath := "/invalid/path/that/does/not/exist/report.json"

	scanResult := createTestScanResult()

	err := manager.GenerateReport(scanResult, invalidPath, FormatJSON)
	if err == nil {
		t.Error("Expected error for invalid output path")
	}
}

func TestOutputFormat_String(t *testing.T) {
	tests := []struct {
		format   OutputFormat
		expected string
	}{
		{FormatJSON, "json"},
		{FormatHTML, "html"},
		{FormatPDF, "pdf"},
		{FormatText, "text"},
	}

	for _, tt := range tests {
		if string(tt.format) != tt.expected {
			t.Errorf("OutputFormat string representation: got %s, want %s", string(tt.format), tt.expected)
		}
	}
}

func TestReportManager_MultipleReports(t *testing.T) {
	manager := NewReportManager()
	tempDir := t.TempDir()

	scanResult := createTestScanResult()

	formats := []OutputFormat{FormatJSON, FormatText, FormatHTML, FormatPDF}

	for _, format := range formats {
		outputPath := filepath.Join(tempDir, "test_report."+string(format))

		err := manager.GenerateReport(scanResult, outputPath, format)
		if err != nil {
			t.Errorf("Failed to generate %s report: %v", format, err)
			continue
		}

		// Verify file was created
		if _, err := os.Stat(outputPath); os.IsNotExist(err) {
			t.Errorf("%s report file was not created", format)
		}
	}
}

func TestReportManager_EmptyFindings(t *testing.T) {
	manager := NewReportManager()
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "empty_report.json")

	scanResult := &types.ScanResult{
		Timestamp:   time.Now(),
		Target:      "https://test-server.com",
		PolicyUsed:  "test-policy",
		OverallRisk: "Low",
		RiskScore:   5,
		Findings:    []types.Finding{}, // Empty findings
		MCPServer: types.MCPServerInfo{
			Name:    "Test Server",
			Version: "1.0.0",
		},
		Summary: types.ScanSummary{
			TotalFindings:    0,
			CriticalFindings: 0,
			HighFindings:     0,
			MediumFindings:   0,
			LowFindings:      0,
		},
	}

	err := manager.GenerateReport(scanResult, outputPath, FormatJSON)
	if err != nil {
		t.Fatalf("GenerateReport() should handle empty findings: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("Report file should be created even with empty findings")
	}
}

func TestReportManager_ConcurrentGeneration(t *testing.T) {
	manager := NewReportManager()
	tempDir := t.TempDir()

	scanResult := createTestScanResult()

	// Test concurrent report generation
	const numGoroutines = 5
	errChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			outputPath := filepath.Join(tempDir, "concurrent_report_"+string(rune('0'+id))+".json")
			err := manager.GenerateReport(scanResult, outputPath, FormatJSON)
			errChan <- err
		}(i)
	}

	// Collect results
	for i := 0; i < numGoroutines; i++ {
		err := <-errChan
		if err != nil {
			t.Errorf("Concurrent report generation failed: %v", err)
		}
	}
}

// Helper function to create a test scan result
func createTestScanResult() *types.ScanResult {
	return &types.ScanResult{
		Timestamp:   time.Now(),
		Target:      "https://test-server.com",
		PolicyUsed:  "test-policy",
		OverallRisk: "High",
		RiskScore:   75,
		Findings: []types.Finding{
			{
				ID:          "FIND_001",
				RuleID:      "RULE_001",
				Severity:    "Critical",
				Category:    "Injection",
				Title:       "Command Injection",
				Description: "Potential command injection vulnerability",
				Evidence:    "exec() call detected",
				Location:    "line 42",
				LineNumber:  42,
				CodeLine:    "exec(userInput)",
				Remediation: "Use parameterized commands",
				Timestamp:   time.Now(),
			},
			{
				ID:          "FIND_002",
				RuleID:      "RULE_002",
				Severity:    "High",
				Category:    "Authentication",
				Title:       "Weak Authentication",
				Description: "Weak authentication mechanism detected",
				Evidence:    "No password policy enforced",
				Location:    "auth module",
				Remediation: "Implement strong password policy",
				Timestamp:   time.Now(),
			},
			{
				ID:          "FIND_003",
				RuleID:      "RULE_003",
				Severity:    "Medium",
				Category:    "Information Disclosure",
				Title:       "Information Leak",
				Description: "Sensitive information exposed",
				Evidence:    "Debug info in headers",
				Location:    "HTTP headers",
				Remediation: "Remove debug information",
				Timestamp:   time.Now(),
			},
			{
				ID:          "FIND_004",
				RuleID:      "RULE_004",
				Severity:    "Low",
				Category:    "Configuration",
				Title:       "Weak Configuration",
				Description: "Suboptimal configuration detected",
				Evidence:    "Default settings used",
				Location:    "config file",
				Remediation: "Update configuration",
				Timestamp:   time.Now(),
			},
		},
		MCPServer: types.MCPServerInfo{
			Name:         "Test MCP Server",
			Version:      "1.0.0",
			Protocol:     "MCP/1.0",
			Capabilities: []string{"tools", "resources"},
			Tools: []types.MCPTool{
				{
					Name:        "test-tool",
					Description: "Test tool for scanning",
					InputSchema: map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"input": map[string]interface{}{
								"type": "string",
							},
						},
					},
				},
			},
			Resources: []types.MCPResource{
				{
					URI:         "file://test.txt",
					Name:        "test-resource",
					Description: "Test resource",
					MimeType:    "text/plain",
				},
			},
		},
		Summary: types.ScanSummary{
			TotalFindings:    4,
			CriticalFindings: 1,
			HighFindings:     1,
			MediumFindings:   1,
			LowFindings:      1,
		},
	}
}
