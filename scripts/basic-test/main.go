// Simple test script to verify the scanner is working correctly
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
	// Test basic scanner functionality
	fmt.Println("🧪 Testing Scanner Basic Functionality")
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

	// Create a temporary test file with vulnerable content
	testDir := "/tmp/mcp-test-" + fmt.Sprintf("%d", time.Now().Unix())
	err = os.MkdirAll(testDir, 0o755) // Fix octalLiteral: use new octal literal style
	if err != nil {
		log.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir) // Cleanup

	testFile := filepath.Join(testDir, "test.py")
	testContent := `#!/usr/bin/env python3
import subprocess
import os

# Vulnerable patterns that should be detected
subprocess.call("rm -rf /tmp/*", shell=True)  # Command injection
query = "SELECT * FROM users WHERE id = " + user_id  # SQL injection
eval("print('hello')")  # Code injection

def dangerous_function():
    os.system("rm -rf /")  # Dangerous system call
    return "done"
`

	err = os.WriteFile(testFile, []byte(testContent), 0o644) // Fix octalLiteral: use new octal literal style
	if err != nil {
		log.Fatalf("Failed to create test file: %v", err)
	}

	fmt.Printf("📁 Created test directory: %s\n", testDir)
	fmt.Printf("📄 Created test file: %s\n\n", testFile)

	// List available policies
	policyEngine := mcpScanner.GetPolicyEngine()
	if policyEngine == nil {
		log.Fatalf("Failed to get policy engine from scanner")
	}
	policies := policyEngine.ListPolicies()
	fmt.Printf("📋 Available policies (%d found):\n", len(policies))
	for name, description := range policies {
		fmt.Printf("  • %s: %s\n", name, description)
	}
	fmt.Println()

	// Try scanning with different policies
	policyNames := []string{"critical-security", "standard-security", "advanced-polymorphic-security"}

	for _, policyName := range policyNames {
		fmt.Printf("🔍 Testing scan with policy: %s\n", policyName)

		result, err := mcpScanner.ScanLocalMCPServer(testDir, policyName)
		if err != nil {
			fmt.Printf("  ❌ Failed: %v\n\n", err)
			continue
		}

		fmt.Printf("  ✅ Success! Found %d findings\n", len(result.Findings))
		fmt.Printf("  📊 Risk Score: %d (%s)\n", result.RiskScore, result.OverallRisk)

		if len(result.Findings) > 0 {
			fmt.Printf("  🔍 Sample findings:\n")
			for i, finding := range result.Findings {
				if i >= 3 { // Limit to first 3 findings
					fmt.Printf("    ... and %d more\n", len(result.Findings)-3)
					break
				}
				fmt.Printf("    • [%s] %s\n", finding.Severity, finding.Title)
			}
		}
		fmt.Println()
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("🎯 Scanner functionality test completed!")
}
