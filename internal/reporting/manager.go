// Copyright (c) 2025 Gareth Phillips/syphon1c
// Licensed under the MIT License - see LICENSE file for details

package reporting

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

// OutputFormat represents the supported output formats
type OutputFormat string

const (
	FormatJSON OutputFormat = "json"
	FormatHTML OutputFormat = "html"
	FormatPDF  OutputFormat = "pdf"
	FormatText OutputFormat = "text"
)

// Reporter interface for generating reports in different formats
type Reporter interface {
	GenerateReport(result *types.ScanResult, outputPath string) error
}

// ReportManager manages multiple report formats and generation
type ReportManager struct {
	htmlReporter *HTMLReporter
	pdfReporter  *PDFReporter
}

// NewReportManager creates a new report manager
func NewReportManager() *ReportManager {
	return &ReportManager{}
}

// GenerateReport generates a report in the specified format
func (rm *ReportManager) GenerateReport(result *types.ScanResult, outputPath string, format OutputFormat) error {
	switch format {
	case FormatJSON:
		return rm.generateJSONReport(result, outputPath)
	case FormatHTML:
		return rm.generateHTMLReport(result, outputPath)
	case FormatPDF:
		return rm.generatePDFReport(result, outputPath)
	case FormatText:
		return rm.generateTextReport(result, outputPath)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

// GenerateMultipleReports generates reports in multiple formats
func (rm *ReportManager) GenerateMultipleReports(result *types.ScanResult, baseDir string, formats []OutputFormat) (map[OutputFormat]string, error) {
	generatedFiles := make(map[OutputFormat]string)
	timestamp := time.Now().Format("20060102_150405")

	// Create output directory
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	for _, format := range formats {
		filename := fmt.Sprintf("mcp_security_report_%s.%s", timestamp, string(format))
		outputPath := filepath.Join(baseDir, filename)

		err := rm.GenerateReport(result, outputPath, format)
		if err != nil {
			// Log error but continue with other formats
			fmt.Printf("Warning: Failed to generate %s report: %v\n", format, err)
			continue
		}

		generatedFiles[format] = outputPath
	}

	if len(generatedFiles) == 0 {
		return nil, fmt.Errorf("failed to generate any reports")
	}

	return generatedFiles, nil
}

// generateJSONReport creates a structured JSON report from scan results with proper formatting.
// The function marshals the complete scan result structure into indented JSON format,
// preserving all vulnerability details, metadata, and risk assessments for programmatic
// consumption by SIEM systems, CI/CD pipelines, and security automation tools.
//
// Parameters:
//   - result: Complete scan result containing findings, metadata, and risk scores
//   - outputPath: Full file path where the JSON report will be written
//
// Returns:
//   - error: Non-nil if directory creation, JSON marshalling, or file writing fails
//
// The generated JSON includes all scan findings, tool information, policy details,
// and risk calculations suitable for integration with security orchestration platforms.
func (rm *ReportManager) generateJSONReport(result *types.ScanResult, outputPath string) error {
	// Create output directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Marshal to JSON with indentation
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result to JSON: %w", err)
	}

	// Write to file
	if err := os.WriteFile(outputPath, jsonData, 0600); err != nil { // Fix G306: use 0600 permissions
		return fmt.Errorf("failed to write JSON report: %w", err)
	}

	return nil
}

// generateHTMLReport creates a comprehensive HTML report with interactive visualizations.
// The function utilizes the HTML reporter to generate a detailed security assessment report
// featuring vulnerability summaries, risk visualizations, code evidence, and executive
// dashboards suitable for security teams and management review.
//
// Parameters:
//   - result: Complete scan result containing findings and metadata
//   - outputPath: Full file path where the HTML report will be written
//
// Returns:
//   - error: Non-nil if HTML reporter initialization or report generation fails
//
// The HTML report includes interactive charts, detailed vulnerability descriptions,
// code evidence with syntax highlighting, and risk assessment visualizations.
func (rm *ReportManager) generateHTMLReport(result *types.ScanResult, outputPath string) error {
	if rm.htmlReporter == nil {
		var err error
		rm.htmlReporter, err = NewHTMLReporter()
		if err != nil {
			return fmt.Errorf("failed to create HTML reporter: %w", err)
		}
	}

	return rm.htmlReporter.GenerateReport(result, outputPath)
}

// generatePDFReport creates a professional PDF security assessment report.
// The function leverages the PDF reporter to generate publication-quality security
// reports suitable for compliance documentation, executive briefings, and formal
// security assessments requiring portable document format.
//
// Parameters:
//   - result: Complete scan result containing findings and risk assessment data
//   - outputPath: Full file path where the PDF report will be written
//
// Returns:
//   - error: Non-nil if PDF reporter initialization or document generation fails
//
// The PDF report includes executive summary, detailed findings, risk matrices,
// and recommendations formatted for professional security documentation standards.
func (rm *ReportManager) generatePDFReport(result *types.ScanResult, outputPath string) error {
	if rm.pdfReporter == nil {
		var err error
		rm.pdfReporter, err = NewPDFReporter()
		if err != nil {
			return fmt.Errorf("failed to create PDF reporter: %w", err)
		}
	}
	return rm.pdfReporter.GenerateReport(result, outputPath)
}

// generateTextReport generates a plain text report
func (rm *ReportManager) generateTextReport(result *types.ScanResult, outputPath string) error {
	// Create output directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	var content strings.Builder

	// Header
	content.WriteString("=== MCP Security Scanner Report ===\n\n")
	content.WriteString(fmt.Sprintf("Target: %s\n", result.Target))
	content.WriteString(fmt.Sprintf("Policy: %s\n", result.PolicyUsed))
	content.WriteString(fmt.Sprintf("Scan Date: %s\n", result.Timestamp.Format("2006-01-02 15:04:05")))
	content.WriteString(fmt.Sprintf("Overall Risk: %s (Score: %d)\n\n", result.OverallRisk, result.RiskScore))

	// MCP Server Info
	if result.MCPServer.Name != "" {
		content.WriteString("=== MCP Server Information ===\n")
		content.WriteString(fmt.Sprintf("Name: %s\n", result.MCPServer.Name))
		content.WriteString(fmt.Sprintf("Version: %s\n", result.MCPServer.Version))
		content.WriteString(fmt.Sprintf("Protocol: %s\n", result.MCPServer.Protocol))
		content.WriteString(fmt.Sprintf("Tools: %d\n", len(result.MCPServer.Tools)))
		content.WriteString(fmt.Sprintf("Resources: %d\n", len(result.MCPServer.Resources)))
		content.WriteString(fmt.Sprintf("Capabilities: %s\n\n", strings.Join(result.MCPServer.Capabilities, ", ")))
	}

	// Summary
	content.WriteString("=== Summary ===\n")
	content.WriteString(fmt.Sprintf("Total Findings: %d\n", result.Summary.TotalFindings))
	if result.Summary.CriticalFindings > 0 {
		content.WriteString(fmt.Sprintf("Critical: %d\n", result.Summary.CriticalFindings))
	}
	if result.Summary.HighFindings > 0 {
		content.WriteString(fmt.Sprintf("High: %d\n", result.Summary.HighFindings))
	}
	if result.Summary.MediumFindings > 0 {
		content.WriteString(fmt.Sprintf("Medium: %d\n", result.Summary.MediumFindings))
	}
	if result.Summary.LowFindings > 0 {
		content.WriteString(fmt.Sprintf("Low: %d\n", result.Summary.LowFindings))
	}
	content.WriteString("\n")

	// Findings
	if len(result.Findings) > 0 {
		content.WriteString("=== Security Findings ===\n")
		for i, finding := range result.Findings {
			content.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, finding.Severity, finding.Title))
			content.WriteString(fmt.Sprintf("   Category: %s\n", finding.Category))
			content.WriteString(fmt.Sprintf("   Location: %s\n", finding.Location))

			// Add line number if available
			if finding.LineNumber > 0 {
				content.WriteString(fmt.Sprintf("   Line Number: %d\n", finding.LineNumber))
			}

			content.WriteString(fmt.Sprintf("   Description: %s\n", finding.Description))

			if finding.Evidence != "" {
				content.WriteString(fmt.Sprintf("   Evidence: %s\n", finding.Evidence))
			}

			// Add code line if available
			if finding.CodeLine != "" {
				content.WriteString(fmt.Sprintf("   Code Line: %s\n", finding.CodeLine))
			}

			// Add code context if available
			if len(finding.CodeContext) > 0 {
				content.WriteString("   Code Context:\n")
				for _, contextLine := range finding.CodeContext {
					content.WriteString(fmt.Sprintf("     %s\n", contextLine))
				}
			}

			if finding.Remediation != "" {
				content.WriteString(fmt.Sprintf("   Remediation: %s\n", finding.Remediation))
			}
			content.WriteString("\n")
		}
	} else {
		content.WriteString("=== Security Findings ===\n")
		content.WriteString("No security findings detected.\n\n")
	}

	// Footer
	content.WriteString("=== Report Information ===\n")
	content.WriteString("Generated by: MCP Security Scanner v1.0\n")
	content.WriteString(fmt.Sprintf("Generated on: %s\n", time.Now().Format("2006-01-02 15:04:05 MST")))

	// Write to file
	if err := os.WriteFile(outputPath, []byte(content.String()), 0600); err != nil { // Fix G306: use 0600 permissions
		return fmt.Errorf("failed to write text report: %w", err)
	}

	return nil
}

// ParseOutputFormat parses a string into an OutputFormat
func ParseOutputFormat(format string) (OutputFormat, error) {
	switch strings.ToLower(format) {
	case "json":
		return FormatJSON, nil
	case "html":
		return FormatHTML, nil
	case "pdf":
		return FormatPDF, nil
	case "text", "txt":
		return FormatText, nil
	default:
		return "", fmt.Errorf("unsupported output format: %s (supported: json, html, pdf, text)", format)
	}
}

// GetSupportedFormats returns all supported output formats
func GetSupportedFormats() []OutputFormat {
	return []OutputFormat{FormatJSON, FormatHTML, FormatPDF, FormatText}
}

// GetFormatExtension returns the file extension for a format
func GetFormatExtension(format OutputFormat) string {
	switch format {
	case FormatJSON:
		return "json"
	case FormatHTML:
		return "html"
	case FormatPDF:
		return "pdf"
	case FormatText:
		return "txt"
	default:
		return "txt"
	}
}
