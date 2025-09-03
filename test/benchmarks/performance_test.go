package benchmarks

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/syphon1c/mcp-security-scanner/internal/integration"
	"github.com/syphon1c/mcp-security-scanner/internal/scanner"
	"github.com/syphon1c/mcp-security-scanner/pkg/types"
	"github.com/syphon1c/mcp-security-scanner/test/mocks"
	"github.com/syphon1c/mcp-security-scanner/test/testdata"
)

func BenchmarkScannerCreation(b *testing.B) {
	// Create test policy directory
	tempDir := b.TempDir()
	createTestPolicyFile(b, tempDir, "benchmark-policy")

	config := types.ScannerConfig{
		Timeout:         30 * time.Second,
		UserAgent:       "Benchmark-Scanner",
		PolicyDirectory: tempDir,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s, err := scanner.NewScanner(config, (*integration.AlertProcessor)(nil))
		if err != nil {
			b.Fatalf("Failed to create scanner: %v", err)
		}
		_ = s // Use the scanner to prevent optimization
	}
}

func BenchmarkLocalScanSmallProject(b *testing.B) {
	// Create a small test project
	tempDir := b.TempDir()
	createTestProject(b, tempDir, 5) // 5 files

	// Create scanner
	tempPolicyDir := b.TempDir()
	createTestPolicyFile(b, tempPolicyDir, "benchmark-policy")

	config := types.ScannerConfig{
		Timeout:         30 * time.Second,
		UserAgent:       "Benchmark-Scanner",
		PolicyDirectory: tempPolicyDir,
	}

	s, err := scanner.NewScanner(config, (*integration.AlertProcessor)(nil))
	if err != nil {
		b.Fatalf("Failed to create scanner: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := s.ScanLocalMCPServer(tempDir, "benchmark-policy")
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
		_ = result // Use the result to prevent optimization
	}
}

func BenchmarkLocalScanMediumProject(b *testing.B) {
	// Create a medium test project
	tempDir := b.TempDir()
	createTestProject(b, tempDir, 50) // 50 files

	// Create scanner
	tempPolicyDir := b.TempDir()
	createTestPolicyFile(b, tempPolicyDir, "benchmark-policy")

	config := types.ScannerConfig{
		Timeout:         30 * time.Second,
		UserAgent:       "Benchmark-Scanner",
		PolicyDirectory: tempPolicyDir,
	}

	s, err := scanner.NewScanner(config, (*integration.AlertProcessor)(nil))
	if err != nil {
		b.Fatalf("Failed to create scanner: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := s.ScanLocalMCPServer(tempDir, "benchmark-policy")
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
		_ = result
	}
}

func BenchmarkLocalScanLargeProject(b *testing.B) {
	// Create a large test project
	tempDir := b.TempDir()
	createTestProject(b, tempDir, 200) // 200 files

	// Create scanner
	tempPolicyDir := b.TempDir()
	createTestPolicyFile(b, tempPolicyDir, "benchmark-policy")

	config := types.ScannerConfig{
		Timeout:         60 * time.Second, // Longer timeout for large project
		UserAgent:       "Benchmark-Scanner",
		PolicyDirectory: tempPolicyDir,
	}

	s, err := scanner.NewScanner(config, (*integration.AlertProcessor)(nil))
	if err != nil {
		b.Fatalf("Failed to create scanner: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := s.ScanLocalMCPServer(tempDir, "benchmark-policy")
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
		_ = result
	}
}

func BenchmarkRemoteMCPScan(b *testing.B) {
	// Start mock server
	mockServer := mocks.NewMockMCPServer()
	defer mockServer.Close()

	// Create scanner
	tempPolicyDir := b.TempDir()
	createTestPolicyFile(b, tempPolicyDir, "benchmark-policy")

	config := types.ScannerConfig{
		Timeout:         30 * time.Second,
		UserAgent:       "Benchmark-Scanner",
		PolicyDirectory: tempPolicyDir,
	}

	s, err := scanner.NewScanner(config, (*integration.AlertProcessor)(nil))
	if err != nil {
		b.Fatalf("Failed to create scanner: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := s.ScanRemoteMCPServer(mockServer.GetURL(), "benchmark-policy")
		if err != nil {
			b.Fatalf("Remote scan failed: %v", err)
		}
		_ = result
	}
}

func BenchmarkVulnerabilityDetection(b *testing.B) {
	// Create files with known vulnerabilities
	tempDir := b.TempDir()

	// Create vulnerable files
	for name, code := range testdata.VulnerableSamples {
		filename := filepath.Join(tempDir, name+".py")
		err := os.WriteFile(filename, []byte(code), 0644)
		if err != nil {
			b.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Create comprehensive policy
	tempPolicyDir := b.TempDir()
	createComprehensivePolicyFile(b, tempPolicyDir, "vuln-benchmark-policy")

	config := types.ScannerConfig{
		Timeout:         30 * time.Second,
		UserAgent:       "Benchmark-Scanner",
		PolicyDirectory: tempPolicyDir,
	}

	s, err := scanner.NewScanner(config, (*integration.AlertProcessor)(nil))
	if err != nil {
		b.Fatalf("Failed to create scanner: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := s.ScanLocalMCPServer(tempDir, "vuln-benchmark-policy")
		if err != nil {
			b.Fatalf("Vulnerability scan failed: %v", err)
		}
		_ = result
	}
}

func BenchmarkPolicyLoading(b *testing.B) {
	// Create multiple policy files
	tempDir := b.TempDir()
	for i := 0; i < 10; i++ {
		createTestPolicyFile(b, tempDir, "policy-"+string(rune('A'+i)))
	}

	config := types.ScannerConfig{
		Timeout:         30 * time.Second,
		UserAgent:       "Benchmark-Scanner",
		PolicyDirectory: tempDir,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s, err := scanner.NewScanner(config, (*integration.AlertProcessor)(nil))
		if err != nil {
			b.Fatalf("Failed to create scanner: %v", err)
		}
		_ = s
	}
}

func BenchmarkConcurrentScans(b *testing.B) {
	// Test concurrent scanning performance
	tempDir := b.TempDir()
	createTestProject(b, tempDir, 20)

	tempPolicyDir := b.TempDir()
	createTestPolicyFile(b, tempPolicyDir, "concurrent-benchmark-policy")

	config := types.ScannerConfig{
		Timeout:         30 * time.Second,
		UserAgent:       "Benchmark-Scanner",
		PolicyDirectory: tempPolicyDir,
	}

	s, err := scanner.NewScanner(config, (*integration.AlertProcessor)(nil))
	if err != nil {
		b.Fatalf("Failed to create scanner: %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			result, err := s.ScanLocalMCPServer(tempDir, "concurrent-benchmark-policy")
			if err != nil {
				b.Errorf("Concurrent scan failed: %v", err)
			}
			_ = result
		}
	})
}

func BenchmarkRegexPatternMatching(b *testing.B) {
	// Benchmark pattern matching performance
	testContent := ""
	for _, code := range testdata.VulnerableSamples {
		testContent += code + "\n"
	}

	// Create scanner with comprehensive patterns
	tempPolicyDir := b.TempDir()
	createComprehensivePolicyFile(b, tempPolicyDir, "regex-benchmark-policy")

	config := types.ScannerConfig{
		Timeout:         30 * time.Second,
		UserAgent:       "Benchmark-Scanner",
		PolicyDirectory: tempPolicyDir,
	}

	s, err := scanner.NewScanner(config, (*integration.AlertProcessor)(nil))
	if err != nil {
		b.Fatalf("Failed to create scanner: %v", err)
	}

	// Create temporary file with test content
	tempDir := b.TempDir()
	testFile := filepath.Join(tempDir, "benchmark_test.py")
	err = os.WriteFile(testFile, []byte(testContent), 0644)
	if err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := s.ScanLocalMCPServer(tempDir, "regex-benchmark-policy")
		if err != nil {
			b.Fatalf("Pattern matching scan failed: %v", err)
		}
		_ = result
	}
}

// Helper functions for creating test data

func createTestProject(b *testing.B, baseDir string, numFiles int) {
	for i := 0; i < numFiles; i++ {
		subdir := filepath.Join(baseDir, "subdir"+string(rune('A'+i%5)))
		err := os.MkdirAll(subdir, 0755)
		if err != nil {
			b.Fatalf("Failed to create subdirectory: %v", err)
		}

		filename := filepath.Join(subdir, "file"+string(rune('0'+i%10))+".py")

		// Use different vulnerability samples for variety
		sampleNames := make([]string, 0, len(testdata.VulnerableSamples))
		for name := range testdata.VulnerableSamples {
			sampleNames = append(sampleNames, name)
		}

		var content string
		if len(sampleNames) > 0 {
			content = testdata.VulnerableSamples[sampleNames[i%len(sampleNames)]]
		} else {
			content = "# Simple test file\nprint('Hello, World!')\n"
		}

		err = os.WriteFile(filename, []byte(content), 0644)
		if err != nil {
			b.Fatalf("Failed to create test file: %v", err)
		}
	}
}

func createTestPolicyFile(b *testing.B, dir, policyName string) {
	policyContent := `{
		"version": "1.0",
		"policyName": "` + policyName + `",
		"description": "Benchmark test policy",
		"severity": "High",
		"rules": [
			{
				"id": "BENCH_001",
				"title": "Simple Test Rule",
				"category": "Testing",
				"severity": "Medium",
				"patterns": ["test.*pattern", "print\\s*\\("],
				"description": "A simple test rule for benchmarking",
				"remediation": "This is just a test"
			}
		],
		"blockedPatterns": [],
		"riskThresholds": {
			"critical": 50,
			"high": 30,
			"medium": 15,
			"low": 5
		}
	}`

	policyFile := filepath.Join(dir, policyName+".json")
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	if err != nil {
		b.Fatalf("Failed to create policy file: %v", err)
	}
}

func createComprehensivePolicyFile(b *testing.B, dir, policyName string) {
	policyContent := `{
		"version": "1.0",
		"policyName": "` + policyName + `",
		"description": "Comprehensive benchmark policy with many patterns",
		"severity": "High",
		"rules": [
			{
				"id": "CMD_001",
				"title": "Command Injection",
				"category": "Command Injection",
				"severity": "Critical",
				"patterns": [
					"subprocess\\\\.run.*shell=True",
					"exec\\\\s*\\\\(",
					"system\\\\s*\\\\(",
					"os\\\\.system",
					"popen\\\\s*\\\\(",
					"shell_exec\\\\s*\\\\("
				],
				"description": "Command injection vulnerabilities",
				"remediation": "Use parameterized commands"
			},
			{
				"id": "SQL_001",
				"title": "SQL Injection", 
				"category": "SQL Injection",
				"severity": "Critical",
				"patterns": [
					"SELECT.*\\\\+.*",
					"f[\"']SELECT.*{.*}.*[\"']",
					"\\\\.execute\\\\s*\\\\(.*\\\\+.*\\\\)",
					"WHERE.*\\\\+.*",
					"INSERT.*\\\\+.*",
					"UPDATE.*\\\\+.*",
					"DELETE.*\\\\+.*"
				],
				"description": "SQL injection vulnerabilities",
				"remediation": "Use parameterized queries"
			},
			{
				"id": "CRED_001",
				"title": "Hardcoded Credentials",
				"category": "Credentials",
				"severity": "High",
				"patterns": [
					"PASSWORD\\\\s*=\\\\s*[\"'][^\"']+[\"']",
					"API_KEY\\\\s*=\\\\s*[\"'][^\"']+[\"']",
					"SECRET\\\\s*=\\\\s*[\"'][^\"']+[\"']",
					"TOKEN\\\\s*=\\\\s*[\"'][^\"']+[\"']",
					"private_key\\\\s*=\\\\s*[\"'][^\"']+[\"']"
				],
				"description": "Hardcoded credentials detected",
				"remediation": "Use environment variables or secure vaults"
			},
			{
				"id": "PATH_001",
				"title": "Path Traversal",
				"category": "Path Traversal",
				"severity": "High",
				"patterns": [
					"\\\\.\\\\./",
					"\\\\.\\\\.\\\\\\\\",
					"%2e%2e%2f",
					"%2e%2e%5c",
					"..%2f",
					"..%5c"
				],
				"description": "Path traversal vulnerabilities",
				"remediation": "Validate and sanitize file paths"
			}
		],
		"blockedPatterns": [],
		"riskThresholds": {
			"critical": 50,
			"high": 30,
			"medium": 15,
			"low": 5
		}
	}`

	policyFile := filepath.Join(dir, policyName+".json")
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	if err != nil {
		b.Fatalf("Failed to create comprehensive policy file: %v", err)
	}
}
