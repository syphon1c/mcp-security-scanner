package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/syphon1c/mcp-security-scanner/internal/config"
	"github.com/syphon1c/mcp-security-scanner/internal/integration"
	"github.com/syphon1c/mcp-security-scanner/internal/policy"
	"github.com/syphon1c/mcp-security-scanner/internal/proxy"
	"github.com/syphon1c/mcp-security-scanner/internal/reporting"
	"github.com/syphon1c/mcp-security-scanner/internal/scanner"
	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

type CLIOptions struct {
	OutputFormat string
	OutputFile   string
	OutputDir    string
	AllFormats   bool
	Verbose      bool
}

// getAvailablePolicies dynamically discovers and returns available security policies
func getAvailablePolicies() []string {
	// Load configuration to get policy directory
	cfg, err := config.LoadDefaultConfig()
	if err != nil {
		// If we can't load config, try default policy directory
		return getAvailablePoliciesFromDir("./policies")
	}

	return getAvailablePoliciesFromDir(cfg.Scanner.PolicyDirectory)
}

// getAvailablePoliciesFromDir loads policies from a specific directory
func getAvailablePoliciesFromDir(policyDir string) []string {
	// Create policy engine and load policies
	engine := policy.NewEngine()
	err := engine.LoadPoliciesFromDirectory(policyDir)
	if err != nil {
		// If we can't load policies, return empty slice
		return []string{}
	}

	// Get policy names
	policies := engine.ListPolicies()
	var policyNames []string
	for name := range policies {
		policyNames = append(policyNames, name)
	}

	return policyNames
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "scan-local":
		handleLocalScan()
	case "scan-remote":
		handleRemoteScan()
	case "proxy":
		handleProxy()
	case "policies":
		handleListPolicies()
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("MCP Security Scanner v1.0.0")
	fmt.Println("Usage:")
	fmt.Println("  mcpscan scan-local <path> <policy> [options]   - Scan local MCP server")
	fmt.Println("  mcpscan scan-remote <url> <policy> [options]   - Scan remote MCP server")
	fmt.Println("  mcpscan proxy <target-url> <port> [options]    - Start live monitoring proxy")
	fmt.Println("  mcpscan policies                               - List all available security policies")
	fmt.Println("")

	// Dynamically list available policies
	fmt.Println("Available policies:")
	availablePolicies := getAvailablePolicies()
	if len(availablePolicies) == 0 {
		fmt.Println("  (No policies found - ensure policies directory exists with .json files)")
	} else {
		for _, policyName := range availablePolicies {
			fmt.Printf("  %s\n", policyName)
		}
	}

	fmt.Println("")
	fmt.Println("Output Options:")
	fmt.Println("  --output-format FORMAT    Output format: json, html, pdf, text (default: json)")
	fmt.Println("  --output-file PATH        Output file path")
	fmt.Println("  --output-dir DIR          Output directory (default: ./reports)")
	fmt.Println("  --all-formats             Generate all output formats")
	fmt.Println("  --verbose                 Verbose output")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  mcpscan scan-local /path/to/server critical-security")
	fmt.Println("  mcpscan scan-local /path/to/server critical-security --output-format html")
	fmt.Println("  mcpscan scan-local /path/to/server critical-security --all-formats --output-dir ./reports")
	fmt.Println("  mcpscan scan-remote http://localhost:8000 advanced-polymorphic-security --output-format pdf")
}

func parseOptions(args []string) CLIOptions {
	opts := CLIOptions{
		OutputFormat: "json", // default
	}

	// Simple flag parsing for our specific needs
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--output-format":
			if i+1 < len(args) {
				opts.OutputFormat = args[i+1]
				i++
			}
		case "--output-file":
			if i+1 < len(args) {
				opts.OutputFile = args[i+1]
				i++
			}
		case "--output-dir":
			if i+1 < len(args) {
				opts.OutputDir = args[i+1]
				i++
			}
		case "--all-formats":
			opts.AllFormats = true
		case "--verbose":
			opts.Verbose = true
		}
	}

	return opts
}

func handleLocalScan() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: mcpscan scan-local <path> <policy> [options]")
		os.Exit(1)
	}

	serverPath := os.Args[2]
	policyName := os.Args[3]
	opts := parseOptions(os.Args[4:])

	fmt.Printf("🔍 Starting local scan of: %s\n", serverPath)
	fmt.Printf("📋 Using policy: %s\n", policyName)
	if opts.Verbose {
		fmt.Printf("⚙️  Output format: %s\n", opts.OutputFormat)
	}

	// Load configuration from YAML with environment variable support
	appConfig, err := config.LoadDefaultConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	if opts.Verbose {
		config.PrintConfigSummary(appConfig)
	}

	// Convert to scanner configuration and override output format if specified
	scannerConfig := appConfig.ToScannerConfig()
	if opts.OutputFormat != "json" { // Override if user specified different format
		scannerConfig.OutputFormat = opts.OutputFormat
	}

	// Initialize scanner
	alertProcessor := (*integration.AlertProcessor)(nil)
	s, err := scanner.NewScanner(scannerConfig, alertProcessor)
	if err != nil {
		log.Fatalf("Failed to initialize scanner: %v", err)
	}

	// Perform scan
	result, err := s.ScanLocalMCPServer(serverPath, policyName)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Output results
	outputResults(result, opts, appConfig)
}

func handleRemoteScan() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: mcpscan scan-remote <url> <policy> [options]")
		os.Exit(1)
	}

	serverURL := os.Args[2]
	policyName := os.Args[3]
	opts := parseOptions(os.Args[4:])

	fmt.Printf("🌐 Starting remote scan of: %s\n", serverURL)
	fmt.Printf("📋 Using policy: %s\n", policyName)
	if opts.Verbose {
		fmt.Printf("⚙️  Output format: %s\n", opts.OutputFormat)
	}

	// Load configuration from YAML with environment variable support
	appConfig, err := config.LoadDefaultConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	if opts.Verbose {
		config.PrintConfigSummary(appConfig)
	}

	// Convert to scanner configuration and override output format if specified
	scannerConfig := appConfig.ToScannerConfig()
	if opts.OutputFormat != "json" { // Override if user specified different format
		scannerConfig.OutputFormat = opts.OutputFormat
	}

	// Initialize scanner
	alertProcessor := (*integration.AlertProcessor)(nil)
	s, err := scanner.NewScanner(scannerConfig, alertProcessor)
	if err != nil {
		log.Fatalf("Failed to initialize scanner: %v", err)
	}

	// Perform scan
	result, err := s.ScanRemoteMCPServer(serverURL, policyName)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Output results
	outputResults(result, opts, appConfig)
}

func outputResults(result *types.ScanResult, opts CLIOptions, appConfig *config.AppConfig) {
	// Always show console output
	displayConsoleReport(result, opts.Verbose)

	// Generate file reports based on options
	reportManager := reporting.NewReportManager()

	// Use configured output directory if not specified by user
	defaultOutputDir := appConfig.Scanner.Output.Directory
	if defaultOutputDir == "" {
		defaultOutputDir = "./reports"
	}

	if opts.AllFormats {
		// Generate all formats
		outputDir := opts.OutputDir
		if outputDir == "" {
			outputDir = defaultOutputDir
		}

		formats := reporting.GetSupportedFormats()
		generated, err := reportManager.GenerateMultipleReports(result, outputDir, formats)
		if err != nil {
			fmt.Printf("❌ Error generating reports: %v\n", err)
			return
		}

		fmt.Printf("\n📁 Reports generated in: %s\n", outputDir)
		for format, path := range generated {
			fmt.Printf("   📄 %s: %s\n", strings.ToUpper(string(format)), filepath.Base(path))
		}
	} else {
		// Generate single format
		outputFormat := opts.OutputFormat
		if outputFormat == "" {
			outputFormat = appConfig.Scanner.Output.DefaultFormat
		}

		format, err := reporting.ParseOutputFormat(outputFormat)
		if err != nil {
			fmt.Printf("❌ Invalid output format: %v\n", err)
			return
		}

		outputPath := opts.OutputFile
		if outputPath == "" {
			// Generate default filename using configured base name
			ext := reporting.GetFormatExtension(format)
			timestamp := time.Now().Format("20060102_150405")
			filenameBase := appConfig.Scanner.Output.FilenameBase
			if filenameBase == "" {
				filenameBase = "mcp_security_report"
			}
			filename := fmt.Sprintf("%s_%s.%s", filenameBase, timestamp, ext)

			outputDir := opts.OutputDir
			if outputDir == "" {
				outputDir = defaultOutputDir
			}
			outputPath = filepath.Join(outputDir, filename)
		}

		err = reportManager.GenerateReport(result, outputPath, format)
		if err != nil {
			fmt.Printf("❌ Error generating %s report: %v\n", format, err)
			return
		}

		fmt.Printf("\n📄 %s report saved to: %s\n", strings.ToUpper(string(format)), outputPath)
	}
}

func displayConsoleReport(result *types.ScanResult, verbose bool) {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Printf("🛡️  MCP Security Scan Report\n")
	fmt.Println(strings.Repeat("=", 80))

	fmt.Printf("📅 Timestamp: %s\n", result.Timestamp.Format(time.RFC3339))
	fmt.Printf("🎯 Target: %s\n", result.Target)
	fmt.Printf("📋 Policy: %s\n", result.PolicyUsed)

	fmt.Printf("\n🚨 Security Findings: %d total\n", len(result.Findings))

	// Count by severity
	counts := make(map[string]int)
	for _, finding := range result.Findings {
		counts[finding.Severity]++
	}

	if counts["Critical"] > 0 {
		fmt.Printf("   🔴 Critical: %d\n", counts["Critical"])
	}
	if counts["High"] > 0 {
		fmt.Printf("   🟠 High: %d\n", counts["High"])
	}
	if counts["Medium"] > 0 {
		fmt.Printf("   🟡 Medium: %d\n", counts["Medium"])
	}
	if counts["Low"] > 0 {
		fmt.Printf("   🔵 Low: %d\n", counts["Low"])
	}

	fmt.Printf("\n📊 Risk Score: %d\n", result.RiskScore)

	if len(result.Findings) > 0 && verbose {
		fmt.Println("\n📋 Detailed Findings:")
		fmt.Println(strings.Repeat("-", 80))

		for i, finding := range result.Findings {
			severityIcon := getSeverityIcon(finding.Severity)
			fmt.Printf("\n%d. %s %s [%s]\n", i+1, severityIcon, finding.Title, finding.Severity)
			fmt.Printf("   📝 %s\n", finding.Description)

			if finding.Evidence != "" {
				fmt.Printf("   🔍 Evidence: %s\n", finding.Evidence)
			}

			if finding.Location != "" {
				fmt.Printf("   📍 Location: %s\n", finding.Location)
			}

			// Show line number and code if available
			if finding.LineNumber > 0 {
				fmt.Printf("   📄 Line: %d\n", finding.LineNumber)
			}

			if finding.CodeLine != "" {
				fmt.Printf("   💻 Code: %s\n", finding.CodeLine)
			}

			// Show code context if available
			if len(finding.CodeContext) > 0 {
				fmt.Printf("   📜 Context:\n")
				for _, line := range finding.CodeContext {
					fmt.Printf("      %s\n", line)
				}
			}

			if finding.Remediation != "" {
				fmt.Printf("   💡 Fix: %s\n", finding.Remediation)
			}
		}
	} else if len(result.Findings) > 0 {
		fmt.Println("\n📋 Use --verbose for detailed findings")
	}

	fmt.Println("\n" + strings.Repeat("=", 80))
}

func getSeverityIcon(severity string) string {
	switch severity {
	case "Critical":
		return "🔴"
	case "High":
		return "🟠"
	case "Medium":
		return "🟡"
	case "Low":
		return "🔵"
	default:
		return "⚪"
	}
}

func handleProxy() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: mcpscan proxy <target-url> <port> [policy]")
		fmt.Println("Example: mcpscan proxy http://localhost:8000 9080 critical-security")
		os.Exit(1)
	}

	targetURL := os.Args[2]
	portStr := os.Args[3]

	// Load configuration first to get default policy
	appConfig, err := config.LoadDefaultConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	policyName := appConfig.Scanner.DefaultPolicy // Use default from config
	if len(os.Args) > 4 {
		policyName = os.Args[4] // Override if user provided policy
	}

	// Validate port (use config port if provided port fails)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		fmt.Printf("⚠️  Invalid port number: %s, using configured port: %d\n", portStr, appConfig.Proxy.Port)
		port = appConfig.Proxy.Port
	}

	fmt.Printf("🔍 Starting MCP Live Monitoring Proxy\n")
	fmt.Printf("📡 Target: %s\n", targetURL)
	fmt.Printf("🌐 Proxy Port: %d\n", port)
	fmt.Printf("🛡️  Security Policy: %s\n", policyName)

	// Load security policies from configured directory
	engine := policy.NewEngine()
	if err := engine.LoadPoliciesFromDirectory(appConfig.Scanner.PolicyDirectory); err != nil {
		log.Fatalf("Failed to load policies: %v", err)
	}

	policies := engine.GetAllPolicies()
	if len(policies) == 0 {
		log.Fatal("No security policies loaded")
	}

	// Create proxy
	alertProcessor := (*integration.AlertProcessor)(nil)
	p, err := proxy.NewProxy(targetURL, policies, alertProcessor)
	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	fmt.Printf("\n🚀 Proxy starting on port %d...\n", port)
	fmt.Printf("📊 Monitor at: http://localhost:%d/monitor\n", port)
	fmt.Printf("🏥 Health check: http://localhost:%d/health\n", port)
	fmt.Printf("📈 Metrics: http://localhost:%d/metrics\n", port)
	fmt.Printf("\n⚠️  Traffic will be intercepted and analysed for security threats\n")
	fmt.Printf("📝 Alerts will be displayed in real-time\n")
	fmt.Printf("\n🛑 Press Ctrl+C to stop\n\n")

	// Start proxy server
	if err := p.Start(port); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
}

// handleListPolicies lists all available security policies
func handleListPolicies() {
	fmt.Println("🛡️  MCP Security Scanner - Available Policies")
	fmt.Println("=============================================")

	// Load configuration to get policy directory
	cfg, err := config.LoadDefaultConfig()
	if err != nil {
		fmt.Printf("⚠️  Warning: Could not load config, using default policy directory: %v\n", err)
		listPoliciesFromDirectory("./policies")
		return
	}

	fmt.Printf("📁 Policy Directory: %s\n\n", cfg.Scanner.PolicyDirectory)
	listPoliciesFromDirectory(cfg.Scanner.PolicyDirectory)
}

// listPoliciesFromDirectory loads and displays policies from a directory
func listPoliciesFromDirectory(policyDir string) {
	engine := policy.NewEngine()
	err := engine.LoadPoliciesFromDirectory(policyDir)
	if err != nil {
		fmt.Printf("❌ Error loading policies from %s: %v\n", policyDir, err)
		return
	}

	policies := engine.GetAllPolicies()
	if len(policies) == 0 {
		fmt.Println("❌ No policies found in the specified directory")
		fmt.Println("")
		fmt.Println("💡 To create a custom policy:")
		fmt.Println("   1. Copy the org-custom-template.json file")
		fmt.Println("   2. Rename it to your-org-name-security.json")
		fmt.Println("   3. Modify the patterns to match your organisation's needs")
		return
	}

	fmt.Printf("Found %d policies:\n\n", len(policies))

	for name, policyObj := range policies {
		status := "✅"
		if strings.Contains(name, "template") {
			status = "📝"
		}

		fmt.Printf("%s %s\n", status, name)
		fmt.Printf("   Description: %s\n", policyObj.Description)
		fmt.Printf("   Version: %s\n", policyObj.Version)
		fmt.Printf("   Severity: %s\n", policyObj.Severity)
		fmt.Printf("   Rules: %d\n", len(policyObj.Rules))

		if strings.Contains(name, "template") {
			fmt.Printf("   💡 This is a template - copy and customise for your organisation\n")
		}

		fmt.Println("")
	}

	fmt.Println("Usage Examples:")
	for name := range policies {
		if !strings.Contains(name, "template") {
			fmt.Printf("  ./mcpscan scan-local /path/to/server %s\n", name)
			break
		}
	}
}
