// Copyright (c) 2025 Gareth Phillips/syphon1c
// Licensed under the MIT License - see LICENSE file for details

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/syphon1c/mcp-security-scanner/internal/config"
	"github.com/syphon1c/mcp-security-scanner/internal/errors"
	"github.com/syphon1c/mcp-security-scanner/internal/integration"
	"github.com/syphon1c/mcp-security-scanner/internal/logging"
	"github.com/syphon1c/mcp-security-scanner/internal/proxy"
	"github.com/syphon1c/mcp-security-scanner/internal/reporting"
	"github.com/syphon1c/mcp-security-scanner/internal/scanner"
	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

const Version = "v1.0.0-beta"

func main() {
	// Initialize logging system
	logConfig := logging.Config{
		Level:      "INFO",
		Component:  "mcpscan",
		Output:     "stdout",
		EnableFile: false,
	}
	logger, err := logging.NewLogger(logConfig)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	// logger.Info("Starting MCP Security Scanner %s with args: %v", Version, os.Args)

	if len(os.Args) < 2 {
		// logger.Error("Insufficient arguments provided - expected minimum 2 arguments, received %d", len(os.Args))
		printUsage()
		os.Exit(1)
	}

	// Load application configuration
	appConfig, err := config.LoadDefaultConfig()
	if err != nil {
		configErr := errors.ConfigurationError("failed to load application configuration")
		logger.Error("Configuration loading failed - error: %v, original: %v, user message: %s",
			configErr.Error(), err.Error(), configErr.UserMessage)
		log.Fatalf("Failed to load configuration: %v", configErr.UserMessage)
	}

	logger.Info("Configuration loaded successfully - policy directory: %s, integrations enabled: %t",
		appConfig.Scanner.PolicyDirectory, appConfig.Integration.SIEM.Endpoint != "")

	// Create alert processor for enterprise integrations
	alertProcessor := integration.NewAlertProcessor(appConfig.Integration)

	// Validate integration configurations
	if validationErrors := alertProcessor.ValidateIntegrations(); len(validationErrors) > 0 {
		logger.Warn("Integration configuration issues detected - %d errors found", len(validationErrors))
		for i, err := range validationErrors {
			logger.Warn("Integration validation error %d: %v", i+1, err.Error())
		}
	}

	// Convert to scanner config for backward compatibility
	scannerConfig := appConfig.ToScannerConfig()

	command := os.Args[1]
	logger.Info("Executing command: %s", command)

	switch command {
	case "scan-local":
		handleScanLocal(scannerConfig, alertProcessor)
	case "scan-remote":
		handleScanRemote(scannerConfig, alertProcessor)
	case "proxy":
		handleProxy(scannerConfig, alertProcessor)
	case "policies":
		handleListPolicies(scannerConfig, alertProcessor)
	case "integrations":
		handleIntegrations(alertProcessor)
	case "version":
		fmt.Printf("MCP Security Scanner %s\n", Version)
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf("MCP Security Scanner %s\n", Version)
	fmt.Println("Usage:")
	fmt.Println("  mcpscan scan-local <path> <policy> [options]     - Scan local MCP server")
	fmt.Println("  mcpscan scan-remote <url> <policy> [options]     - Scan remote MCP server")
	fmt.Println("  mcpscan proxy <target-url> <port>                - Start MCP security proxy")
	fmt.Println("  mcpscan policies                                 - List available policies")
	fmt.Println("  mcpscan integrations                             - Test enterprise integrations")
	fmt.Println("  mcpscan version                                  - Show version information")
	fmt.Println("\nOptions:")
	fmt.Println("  --output-format <format>   Output format: json, html, pdf, text (default: json)")
	fmt.Println("  --output-file <file>       Output file path (optional)")
	fmt.Println("  --output-dir <dir>         Output directory for multiple formats")
	fmt.Println("  --all-formats              Generate reports in all formats")
	fmt.Println("  --verbose                  Enable verbose output")
	fmt.Println("\nExamples:")
	fmt.Println("  mcpscan scan-local ./my-mcp-server critical-security")
	fmt.Println("  mcpscan scan-local ./my-mcp-server critical-security --output-format html")
	fmt.Println("  mcpscan scan-local ./my-mcp-server critical-security --output-file report.pdf")
	fmt.Println("  mcpscan scan-local ./my-mcp-server critical-security --all-formats --output-dir ./reports")
	fmt.Println("  mcpscan scan-remote https://api.example.com/mcp standard-security --output-format pdf")
	fmt.Println("  mcpscan proxy https://target-server.com 8080")
}

// CommandOptions holds parsed command line options
type CommandOptions struct {
	OutputFormat reporting.OutputFormat
	OutputFile   string
	OutputDir    string
	AllFormats   bool
	Verbose      bool
}

// parseOptions parses command line options from the arguments
func parseOptions(args []string) CommandOptions {
	options := CommandOptions{
		OutputFormat: reporting.FormatJSON, // default
		AllFormats:   false,
		Verbose:      false,
	}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--output-format":
			if i+1 < len(args) {
				if format, err := reporting.ParseOutputFormat(args[i+1]); err == nil {
					options.OutputFormat = format
					i++ // skip next argument
				}
			}
		case "--output-file":
			if i+1 < len(args) {
				options.OutputFile = args[i+1]
				i++ // skip next argument
			}
		case "--output-dir":
			if i+1 < len(args) {
				options.OutputDir = args[i+1]
				i++ // skip next argument
			}
		case "--all-formats":
			options.AllFormats = true
		case "--verbose":
			options.Verbose = true
		}
	}

	return options
}

func handleScanLocal(config types.ScannerConfig, alertProcessor *integration.AlertProcessor) {
	if len(os.Args) < 4 {
		fmt.Println("Usage: mcpscan scan-local <path> <policy> [options]")
		os.Exit(1)
	}

	targetPath := os.Args[2]
	policyName := os.Args[3]
	options := parseOptions(os.Args[4:])

	// Create scanner
	mcpScanner, err := scanner.NewScanner(config, alertProcessor)
	if err != nil {
		log.Fatalf("Failed to initialize scanner: %v", err)
	}

	// Perform scan
	fmt.Printf("Starting local scan of: %s\n", targetPath)
	if options.Verbose {
		fmt.Printf("Using policy: %s\n", policyName)
	}

	result, err := mcpScanner.ScanLocalMCPServer(targetPath, policyName)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Generate and output results
	err = generateReports(result, options)
	if err != nil {
		log.Fatalf("Failed to generate reports: %v", err)
	}
}

func handleScanRemote(config types.ScannerConfig, alertProcessor *integration.AlertProcessor) {
	if len(os.Args) < 4 {
		fmt.Println("Usage: mcpscan scan-remote <url> <policy> [options]")
		os.Exit(1)
	}

	targetURL := os.Args[2]
	policyName := os.Args[3]
	options := parseOptions(os.Args[4:])

	// Create scanner
	mcpScanner, err := scanner.NewScanner(config, alertProcessor)
	if err != nil {
		log.Fatalf("Failed to initialize scanner: %v", err)
	}

	// Perform scan
	fmt.Printf("Starting remote scan of: %s\n", targetURL)
	if options.Verbose {
		fmt.Printf("Using policy: %s\n", policyName)
	}

	result, err := mcpScanner.ScanRemoteMCPServer(targetURL, policyName)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Generate and output results
	err = generateReports(result, options)
	if err != nil {
		log.Fatalf("Failed to generate reports: %v", err)
	}
}

func handleProxy(config types.ScannerConfig, alertProcessor *integration.AlertProcessor) {
	if len(os.Args) != 4 {
		fmt.Println("Usage: mcpscan proxy <target-url> <port>")
		os.Exit(1)
	}

	targetURL := os.Args[2]
	portStr := os.Args[3]

	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatalf("Invalid port number: %s", portStr)
	}

	// Load policies for proxy
	mcpScanner, err := scanner.NewScanner(config, alertProcessor)
	if err != nil {
		log.Fatalf("Failed to initialize scanner for policy loading: %v", err)
	}

	policies := mcpScanner.GetPolicyEngine().GetAllPolicies()

	// Create and start proxy
	mcpProxy, err := proxy.NewProxy(targetURL, policies, alertProcessor)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	fmt.Printf("Starting MCP security proxy...\n")
	fmt.Printf("Target: %s\n", targetURL)
	fmt.Printf("Port: %d\n", port)
	fmt.Printf("Monitoring endpoints:\n")
	fmt.Printf("  - Health: http://localhost:%d/monitor/health\n", port)
	fmt.Printf("  - Alerts: http://localhost:%d/monitor/alerts\n", port)
	fmt.Printf("  - Logs: http://localhost:%d/monitor/logs\n", port)

	log.Fatal(mcpProxy.Start(port))
}

func handleListPolicies(config types.ScannerConfig, alertProcessor *integration.AlertProcessor) {
	// Create scanner to access policy engine
	mcpScanner, err := scanner.NewScanner(config, alertProcessor)
	if err != nil {
		log.Fatalf("Failed to initialize scanner: %v", err)
	}

	policies := mcpScanner.GetPolicyEngine().ListPolicies()

	if len(policies) == 0 {
		fmt.Println("No security policies found.")
		fmt.Printf("Check the policy directory: %s\n", config.PolicyDirectory)
		return
	}

	fmt.Println("Available Security Policies:")
	for name, description := range policies {
		fmt.Printf("  %-20s - %s\n", name, description)
	}
}

// generateReports generates reports in the requested formats
func generateReports(result *types.ScanResult, options CommandOptions) error {
	reportManager := reporting.NewReportManager()

	if options.AllFormats {
		// Generate all formats
		outputDir := options.OutputDir
		if outputDir == "" {
			outputDir = "./reports" // default output directory
		}

		fmt.Printf("Generating reports in all formats to: %s\n", outputDir)

		allFormats := reporting.GetSupportedFormats()
		generatedFiles, err := reportManager.GenerateMultipleReports(result, outputDir, allFormats)
		if err != nil {
			return fmt.Errorf("failed to generate reports: %w", err)
		}

		fmt.Println("Generated reports:")
		for format, filePath := range generatedFiles {
			fmt.Printf("  %s: %s\n", format, filePath)
		}

		// Also show console output for immediate feedback
		if options.Verbose {
			fmt.Println("\n=== Console Output ===")
			outputResultConsole(result)
		}

		return nil
	}

	// Generate single format
	if options.OutputFile != "" {
		// Use specified output file
		fmt.Printf("Generating %s report: %s\n", options.OutputFormat, options.OutputFile)
		err := reportManager.GenerateReport(result, options.OutputFile, options.OutputFormat)
		if err != nil {
			return fmt.Errorf("failed to generate %s report: %w", options.OutputFormat, err)
		}
		fmt.Printf("Report saved to: %s\n", options.OutputFile)
	} else if options.OutputFormat != reporting.FormatJSON {
		// Generate timestamped file for non-JSON formats
		outputDir := options.OutputDir
		if outputDir == "" {
			outputDir = "./reports"
		}

		timestamp := time.Now().Format("20060102_150405")
		extension := reporting.GetFormatExtension(options.OutputFormat)
		filename := fmt.Sprintf("mcp_security_report_%s.%s", timestamp, extension)
		outputPath := fmt.Sprintf("%s/%s", outputDir, filename)

		fmt.Printf("Generating %s report: %s\n", options.OutputFormat, outputPath)
		err := reportManager.GenerateReport(result, outputPath, options.OutputFormat)
		if err != nil {
			return fmt.Errorf("failed to generate %s report: %w", options.OutputFormat, err)
		}
		fmt.Printf("Report saved to: %s\n", outputPath)
	}

	// Always show console output for JSON format or when no file specified
	if options.OutputFormat == reporting.FormatJSON && options.OutputFile == "" {
		outputResultConsole(result)
	} else if options.Verbose {
		fmt.Println("\n=== Console Output ===")
		outputResultConsole(result)
	}

	return nil
}

// outputResultConsole outputs scan results to the console (legacy function)
func outputResultConsole(result *types.ScanResult) {
	// Pretty print the scan result
	fmt.Printf("\n=== Scan Results ===\n")
	fmt.Printf("Target: %s\n", result.Target)
	fmt.Printf("Policy: %s\n", result.PolicyUsed)
	fmt.Printf("Timestamp: %s\n", result.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("Overall Risk: %s (Score: %d)\n", result.OverallRisk, result.RiskScore)

	if result.MCPServer.Name != "" {
		fmt.Printf("\n=== MCP Server Info ===\n")
		fmt.Printf("Name: %s\n", result.MCPServer.Name)
		fmt.Printf("Version: %s\n", result.MCPServer.Version)
		fmt.Printf("Protocol: %s\n", result.MCPServer.Protocol)
		fmt.Printf("Tools: %d\n", len(result.MCPServer.Tools))
		fmt.Printf("Resources: %d\n", len(result.MCPServer.Resources))
	}

	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Total Findings: %d\n", result.Summary.TotalFindings)
	if result.Summary.CriticalFindings > 0 {
		fmt.Printf("Critical: %d\n", result.Summary.CriticalFindings)
	}
	if result.Summary.HighFindings > 0 {
		fmt.Printf("High: %d\n", result.Summary.HighFindings)
	}
	if result.Summary.MediumFindings > 0 {
		fmt.Printf("Medium: %d\n", result.Summary.MediumFindings)
	}
	if result.Summary.LowFindings > 0 {
		fmt.Printf("Low: %d\n", result.Summary.LowFindings)
	}

	if len(result.Findings) > 0 {
		fmt.Printf("\n=== Findings ===\n")
		for i, finding := range result.Findings {
			fmt.Printf("%d. [%s] %s\n", i+1, finding.Severity, finding.Title)
			fmt.Printf("   Category: %s\n", finding.Category)
			fmt.Printf("   Location: %s\n", finding.Location)
			fmt.Printf("   Description: %s\n", finding.Description)
			if finding.Evidence != "" {
				fmt.Printf("   Evidence: %s\n", finding.Evidence)
			}
			fmt.Printf("   Remediation: %s\n", finding.Remediation)
			fmt.Println()
		}
	}

	// Also output JSON for programmatic use
	fmt.Printf("\n=== JSON Output ===\n")
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal result to JSON: %v", err)
		return
	}
	fmt.Println(string(jsonData))
}

// handleIntegrations tests and displays status of enterprise integrations
func handleIntegrations(alertProcessor *integration.AlertProcessor) {
	fmt.Println("=== Enterprise Integration Status ===")

	// Get integration status
	status := alertProcessor.GetIntegrationStatus()
	enabled := alertProcessor.GetEnabledIntegrations()

	fmt.Printf("Enabled Integrations: %v\n", enabled)
	fmt.Printf("Total Enabled: %d\n\n", len(enabled))

	// Show detailed status
	for integration, isEnabled := range status {
		fmt.Printf("%-10s: ", integration)
		if isEnabled {
			fmt.Printf("✅ ENABLED\n")
		} else {
			fmt.Printf("❌ DISABLED\n")
		}
	}

	fmt.Println("\n=== Configuration Validation ===")

	// Validate configurations
	if validationErrors := alertProcessor.ValidateIntegrations(); len(validationErrors) > 0 {
		fmt.Println("❌ Configuration Issues Found:")
		for _, err := range validationErrors {
			fmt.Printf("  - %v\n", err)
		}
	} else {
		fmt.Println("✅ All enabled integrations are properly configured")
	}

	// Test connectivity for enabled integrations
	fmt.Println("\n=== Connectivity Test ===")
	testResults := alertProcessor.TestIntegrations()

	for integration, err := range testResults {
		fmt.Printf("%-10s: ", integration)
		if err != nil {
			fmt.Printf("❌ FAILED - %v\n", err)
		} else {
			fmt.Printf("✅ SUCCESS\n")
		}
	}

	if len(enabled) == 0 {
		fmt.Println("\n💡 To enable integrations, update your configuration file:")
		fmt.Println("   - Set integration.siem.enabled: true")
		fmt.Println("   - Set integration.soar.enabled: true")
		fmt.Println("   - Set integration.slack.enabled: true")
		fmt.Println("   - Configure endpoints and authentication")
	}
}
