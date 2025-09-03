// Test script to verify pattern compilation caching performance
package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/syphon1c/mcp-security-scanner/internal/config"
	"github.com/syphon1c/mcp-security-scanner/internal/integration"
	"github.com/syphon1c/mcp-security-scanner/internal/scanner"
	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

func main() {
	// Test pattern caching performance
	fmt.Println("🧪 Testing Pattern Compilation Caching Performance")
	fmt.Println(strings.Repeat("=", 60))

	// Load configuration
	appConfig, err := config.LoadDefaultConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create scanner config
	scannerConfig := appConfig.ToScannerConfig()

	// Create alert processor (required for scanner)
	alertProcessor := integration.NewAlertProcessor(appConfig.Integration)

	// Create scanner
	mcpScanner, err := scanner.NewScanner(scannerConfig, alertProcessor)
	if err != nil {
		log.Fatalf("Failed to create scanner: %v", err)
	}

	// Test content with multiple polymorphic patterns
	testContent := `
import subprocess
subprocess.call("rm -rf /tmp/*", shell=True)
subprocess.run(["rm", "-rf", "/tmp/*"])
os.system("rm -rf /tmp/*")

eval("print('hello')")
exec("print('world')")

# SQL injection patterns
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")

# XSS patterns
document.write("<script>" + userInput + "</script>")
innerHTML = "<div>" + untrustedData + "</div>"
`

	// Create test result structure
	result := &types.ScanResult{
		Target:      "test-file.py",
		PolicyUsed:  "advanced-polymorphic-security",
		Timestamp:   time.Now(),
		Findings:    []types.Finding{},
		Summary:     types.Summary{},
		OverallRisk: "Low",
		RiskScore:   0,
	}

	fmt.Println("📊 Running First Scan (Cold Cache)...")
	start1 := time.Now()

	// First scan - cold cache
	err = mcpScanner.AnalyzeContentWithPolicy(testContent, "test.py", "advanced-polymorphic-security", result)
	if err != nil {
		log.Printf("Warning: Failed to analyze content: %v", err)
		// Try with a fallback policy
		err = mcpScanner.AnalyzeContentWithPolicy(testContent, "test.py", "critical-security", result)
		if err != nil {
			log.Fatalf("Failed to analyze content with fallback policy: %v", err)
		}
	}

	duration1 := time.Since(start1)
	finding1Count := len(result.Findings)

	fmt.Printf("✅ First scan completed in: %v\n", duration1)
	fmt.Printf("🔍 Findings detected: %d\n\n", finding1Count)

	// Reset result for second scan
	result2 := &types.ScanResult{
		Target:      "test-file.py",
		PolicyUsed:  result.PolicyUsed, // Use the same policy that worked
		Timestamp:   time.Now(),
		Findings:    []types.Finding{},
		Summary:     types.Summary{},
		OverallRisk: "Low",
		RiskScore:   0,
	}

	fmt.Println("🚀 Running Second Scan (Warm Cache)...")
	start2 := time.Now()

	// Second scan - warm cache
	err = mcpScanner.AnalyzeContentWithPolicy(testContent, "test.py", result.PolicyUsed, result2)
	if err != nil {
		log.Fatalf("Failed to analyze content on second scan: %v", err)
	}

	duration2 := time.Since(start2)
	finding2Count := len(result2.Findings)

	fmt.Printf("✅ Second scan completed in: %v\n", duration2)
	fmt.Printf("🔍 Findings detected: %d\n\n", finding2Count)

	// Calculate performance improvement
	if duration1 > 0 && duration2 > 0 {
		improvement := ((duration1 - duration2).Seconds() / duration1.Seconds()) * 100
		fmt.Println("📈 Performance Analysis:")
		fmt.Printf("  • First scan (cold):  %v\n", duration1)
		fmt.Printf("  • Second scan (warm): %v\n", duration2)
		if improvement > 0 {
			fmt.Printf("  • Performance gain:   %.1f%% faster\n", improvement)
		} else {
			fmt.Printf("  • Performance delta:  %.1f%%\n", improvement)
		}
		fmt.Printf("  • Consistency check:  %t (findings: %d vs %d)\n",
			finding1Count == finding2Count, finding1Count, finding2Count)
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("🎯 Pattern caching test completed successfully!")
}
