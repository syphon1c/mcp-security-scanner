package testdata

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

// TestPolicies contains pre-defined test policies for testing
var TestPolicies = map[string]*types.SecurityPolicy{
	"basic-test": {
		Version:     "1.0",
		PolicyName:  "basic-test",
		Description: "Basic test policy for unit tests",
		Severity:    "Medium",
		Rules: []types.SecurityRule{
			{
				ID:          "TEST_001",
				Name:        "Test Pattern",
				Category:    "Testing",
				Severity:    "Low",
				Patterns:    []string{"test.*pattern"},
				Description: "Simple test pattern",
				Conditions:  []string{},
			},
		},
		BlockedPatterns: []types.BlockedPattern{},
		RiskThresholds: types.RiskThresholds{
			Critical: 50,
			High:     30,
			Medium:   15,
			Low:      5,
		},
	},

	"command-injection": {
		Version:     "1.0",
		PolicyName:  "command-injection",
		Description: "Policy focused on command injection detection",
		Severity:    "Critical",
		Rules: []types.SecurityRule{
			{
				ID:       "CMD_001",
				Name:     "Command Injection via subprocess",
				Category: "Command Injection",
				Severity: "Critical",
				Patterns: []string{
					"subprocess\\.run.*shell=True",
					"subprocess\\.call.*shell=True",
					"subprocess\\.Popen.*shell=True",
				},
				Description: "Dangerous use of subprocess with shell=True",
				Conditions:  []string{},
			},
			{
				ID:       "CMD_002",
				Name:     "Direct Command Execution",
				Category: "Command Injection",
				Severity: "Critical",
				Patterns: []string{
					"exec\\s*\\(",
					"eval\\s*\\(",
					"os\\.system\\s*\\(",
				},
				Description: "Direct execution of user-controlled code",
				Conditions:  []string{},
			},
		},
		BlockedPatterns: []types.BlockedPattern{
			{
				Pattern:     "rm\\s+-rf\\s+/",
				Type:        "regex",
				Category:    "Dangerous Commands",
				Description: "Dangerous rm command detected",
			},
		},
		RiskThresholds: types.RiskThresholds{
			Critical: 50,
			High:     30,
			Medium:   15,
			Low:      5,
		},
	},

	"sql-injection": {
		Version:     "1.0",
		PolicyName:  "sql-injection",
		Description: "Policy focused on SQL injection detection",
		Severity:    "Critical",
		Rules: []types.SecurityRule{
			{
				ID:       "SQL_001",
				Name:     "SQL String Concatenation",
				Category: "SQL Injection",
				Severity: "Critical",
				Patterns: []string{
					"SELECT.*\\+.*",
					"INSERT.*\\+.*",
					"UPDATE.*\\+.*",
					"DELETE.*\\+.*",
				},
				Description: "SQL queries built with string concatenation",
				Conditions:  []string{},
			},
			{
				ID:       "SQL_002",
				Name:     "Format String SQL",
				Category: "SQL Injection",
				Severity: "Critical",
				Patterns: []string{
					"f[\"']SELECT.*{.*}.*[\"']",
					"f[\"']INSERT.*{.*}.*[\"']",
					"\\.format\\(.*SELECT.*\\)",
				},
				Description: "SQL queries using format strings",
				Conditions:  []string{},
			},
		},
		BlockedPatterns: []types.BlockedPattern{
			{
				Pattern:     "' OR '1'='1",
				Type:        "exact",
				Category:    "SQL Injection Payload",
				Description: "Classic SQL injection payload detected",
			},
		},
		RiskThresholds: types.RiskThresholds{
			Critical: 50,
			High:     30,
			Medium:   15,
			Low:      5,
		},
	},

	"mcp-specific": {
		Version:     "1.0",
		PolicyName:  "mcp-specific",
		Description: "Policy for MCP-specific vulnerabilities",
		Severity:    "High",
		Rules: []types.SecurityRule{
			{
				ID:       "MCP_001",
				Name:     "Unsafe Tool Implementation",
				Category: "MCP Security",
				Severity: "Critical",
				Patterns: []string{
					"def.*execute_command.*:",
					"subprocess\\.run\\(.*arguments\\[",
					"os\\.system\\(.*tool_args",
				},
				Description: "MCP tool implementations that execute system commands",
				Conditions:  []string{},
			},
			{
				ID:       "MCP_002",
				Name:     "Resource Path Traversal",
				Category: "MCP Security",
				Severity: "High",
				Patterns: []string{
					"file://.*\\.\\./",
					"open\\(.*resource_uri",
					"resource_uri\\.replace\\(",
				},
				Description: "MCP resource handlers vulnerable to path traversal",
				Conditions:  []string{},
			},
			{
				ID:       "MCP_003",
				Name:     "Information Disclosure",
				Category: "MCP Security",
				Severity: "Medium",
				Patterns: []string{
					"os\\.environ",
					"socket\\.gethostname\\(",
					"subprocess\\.check_output\\(\\[\"ps\"",
				},
				Description: "MCP tools that may leak system information",
				Conditions:  []string{},
			},
		},
		BlockedPatterns: []types.BlockedPattern{
			{
				Pattern:     "file://.*etc/passwd",
				Type:        "regex",
				Category:    "Sensitive File Access",
				Description: "Attempt to access sensitive system files",
			},
		},
		RiskThresholds: types.RiskThresholds{
			Critical: 50,
			High:     30,
			Medium:   15,
			Low:      5,
		},
	},
}

// GetTestPolicyJSON returns a test policy as JSON string
func GetTestPolicyJSON(policyName string) (string, error) {
	policy, exists := TestPolicies[policyName]
	if !exists {
		return "", ErrPolicyNotFound
	}

	jsonData, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

// MockScanResults contains pre-defined scan results for testing
var MockScanResults = map[string]*types.ScanResult{
	"clean-scan": {
		Timestamp:   time.Now(),
		Target:      "/test/clean-project",
		PolicyUsed:  "basic-test",
		OverallRisk: "Minimal",
		RiskScore:   0,
		Findings:    []types.Finding{},
		MCPServer: types.MCPServerInfo{
			Name:      "Clean Test Server",
			Version:   "1.0.0",
			Protocol:  "MCP",
			Tools:     []types.MCPTool{},
			Resources: []types.MCPResource{},
		},
		Summary: types.ScanSummary{
			TotalFindings:    0,
			CriticalFindings: 0,
			HighFindings:     0,
			MediumFindings:   0,
			LowFindings:      0,
		},
	},

	"vulnerable-scan": {
		Timestamp:   time.Now(),
		Target:      "/test/vulnerable-project",
		PolicyUsed:  "command-injection",
		OverallRisk: "Critical",
		RiskScore:   85,
		Findings: []types.Finding{
			{
				ID:          "FIND_001",
				RuleID:      "CMD_001",
				Severity:    "Critical",
				Category:    "Command Injection",
				Title:       "Unsafe subprocess call",
				Description: "subprocess.run() called with shell=True",
				Evidence:    "subprocess.run(user_input, shell=True)",
				Location:    "/test/vulnerable-project/main.py:15",
				LineNumber:  15,
				CodeLine:    "    result = subprocess.run(user_input, shell=True)",
				Remediation: "Use subprocess without shell=True",
				Timestamp:   time.Now(),
			},
			{
				ID:          "FIND_002",
				RuleID:      "CMD_002",
				Severity:    "Critical",
				Category:    "Command Injection",
				Title:       "Direct exec() call",
				Description: "exec() called with user input",
				Evidence:    "exec(user_code)",
				Location:    "/test/vulnerable-project/main.py:25",
				LineNumber:  25,
				CodeLine:    "    exec(user_code)",
				Remediation: "Avoid exec() with user input",
				Timestamp:   time.Now(),
			},
		},
		MCPServer: types.MCPServerInfo{
			Name:     "Vulnerable Test Server",
			Version:  "1.0.0",
			Protocol: "MCP",
			Tools: []types.MCPTool{
				{
					Name:        "dangerous_exec",
					Description: "Execute arbitrary commands",
					InputSchema: map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"command": map[string]interface{}{"type": "string"},
						},
					},
				},
			},
			Resources: []types.MCPResource{},
		},
		Summary: types.ScanSummary{
			TotalFindings:    2,
			CriticalFindings: 2,
			HighFindings:     0,
			MediumFindings:   0,
			LowFindings:      0,
		},
	},
}

// Test file contents for creating temporary test files
var TestFileContents = map[string]string{
	"safe.py": `
import subprocess
import shlex

def safe_command(user_input):
    # Safe: Using shlex to escape arguments
    safe_input = shlex.quote(user_input)
    result = subprocess.run(["ls", safe_input], capture_output=True)
    return result.stdout

def safe_query(user_id):
    # Safe: Using parameterized query
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
`,

	"vulnerable.py": `
import subprocess
import os

def unsafe_command(user_input):
    # VULNERABLE: shell=True with user input
    result = subprocess.run(user_input, shell=True)
    return result

def unsafe_exec(user_code):
    # VULNERABLE: exec with user input
    exec(user_code)

def unsafe_query(user_id):
    # VULNERABLE: String concatenation in SQL
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()
`,

	"config.py": `
# VULNERABLE: Hardcoded credentials
DATABASE_PASSWORD = "super_secret_123"
API_KEY = "sk-1234567890abcdef"
JWT_SECRET = "my-jwt-secret-key"

# Safe configuration
DATABASE_HOST = os.getenv("DB_HOST", "localhost")
DATABASE_PORT = int(os.getenv("DB_PORT", "5432"))
`,

	"mcp_server.py": `
def handle_tool_call(tool_name, arguments):
    if tool_name == "execute_command":
        # VULNERABLE: No input validation
        command = arguments.get("command")
        return subprocess.run(command, shell=True)
    
def read_resource(resource_uri):
    # VULNERABLE: Path traversal
    file_path = resource_uri.replace("file://", "")
    return open(file_path).read()

def get_system_info():
    # VULNERABLE: Information disclosure
    return {
        "hostname": socket.gethostname(),
        "env_vars": dict(os.environ),
        "processes": subprocess.check_output(["ps", "aux"])
    }
`,
}

// Error definitions
var (
	ErrPolicyNotFound = fmt.Errorf("policy not found")
)
