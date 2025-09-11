// Test script to verify pattern compilation caching performance
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/syphon1c/mcp-security-scanner/internal/config"
	"github.com/syphon1c/mcp-security-scanner/internal/integration"
	"github.com/syphon1c/mcp-security-scanner/internal/scanner"
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

	// Create a temporary test directory with vulnerable content
	testDir := "/tmp/mcp-caching-test-" + fmt.Sprintf("%d", time.Now().Unix())
	err = os.MkdirAll(testDir, 0o755) // Fix octalLiteral: use new octal literal style
	if err != nil {
		log.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir) // Cleanup

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

	testFile := filepath.Join(testDir, "test.py")
	err = os.WriteFile(testFile, []byte(testContent), 0o644) // Fix octalLiteral: use new octal literal style
	if err != nil {
		log.Fatalf("Failed to create test file: %v", err)
	}

	// Determine which policy to use
	policyEngine := mcpScanner.GetPolicyEngine()
	if policyEngine == nil {
		log.Fatalf("Failed to get policy engine from scanner")
	}
	policies := policyEngine.ListPolicies()
	var policyName string
	if _, exists := policies["advanced-polymorphic-security"]; exists {
		policyName = "advanced-polymorphic-security"
	} else if _, exists := policies["critical-security"]; exists {
		policyName = "critical-security"
	} else {
		log.Fatalf("No suitable policy found for testing")
	}

	fmt.Printf("📁 Using test directory: %s\n", testDir)
	fmt.Printf("📋 Using policy: %s\n\n", policyName)

	fmt.Println("📊 Running First Scan (Cold Cache)...")
	start1 := time.Now()

	// First scan - cold cache
	result1, err := mcpScanner.ScanLocalMCPServer(testDir, policyName)
	if err != nil {
		log.Fatalf("Failed to analyze content on first scan: %v", err)
	}

	duration1 := time.Since(start1)
	finding1Count := len(result1.Findings)

	fmt.Printf("✅ First scan completed in: %v\n", duration1)
	fmt.Printf("🔍 Findings detected: %d\n\n", finding1Count)

	fmt.Println("🚀 Running Second Scan (Warm Cache)...")
	start2 := time.Now()

	// Second scan - warm cache
	result2, err := mcpScanner.ScanLocalMCPServer(testDir, policyName)
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
