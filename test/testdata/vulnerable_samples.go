package testdata

// VulnerableSamples contains code samples with known vulnerabilities for testing
var VulnerableSamples = map[string]string{
	"command_injection_python": `
import subprocess
import os

def process_user_input(user_input):
    # VULNERABLE: Direct command execution
    result = subprocess.run(f"ls {user_input}", shell=True)
    return result

def dangerous_exec():
    # VULNERABLE: Using exec with user input
    user_code = request.form.get('code')
    exec(user_code)
`,

	"command_injection_go": `
package main

import (
    "os/exec"
    "fmt"
)

func ProcessFile(filename string) {
    // VULNERABLE: Command injection
    cmd := exec.Command("cat", filename)
    output, _ := cmd.Output()
    fmt.Println(string(output))
}

func DangerousSystem(userInput string) {
    // VULNERABLE: Direct system call
    exec.Command("sh", "-c", userInput).Run()
}
`,

	"sql_injection": `
def get_user(user_id):
    # VULNERABLE: SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()

def search_products(search_term):
    # VULNERABLE: String concatenation in SQL
    sql = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
    return db.execute(sql)
`,

	"path_traversal": `
import os

def read_file(filename):
    # VULNERABLE: Path traversal
    filepath = os.path.join("/app/uploads", filename)
    with open(filepath, 'r') as f:
        return f.read()

def serve_file(file_path):
    # VULNERABLE: No path validation
    return open(f"/var/www/{file_path}").read()
`,

	"hardcoded_secrets": `
# VULNERABLE: Hardcoded credentials
DATABASE_PASSWORD = "super_secret_123"
API_KEY = "sk-1234567890abcdef"
JWT_SECRET = "my-jwt-secret-key"

def connect_db():
    return psycopg2.connect(
        host="localhost",
        database="mydb",
        user="admin",
        password="admin123"  # VULNERABLE: Hardcoded password
    )
`,

	"insecure_crypto": `
import hashlib
import md5

def hash_password(password):
    # VULNERABLE: Weak hashing algorithm
    return md5.new(password.encode()).hexdigest()

def weak_hash(data):
    # VULNERABLE: MD5 is cryptographically broken
    return hashlib.md5(data.encode()).hexdigest()
`,

	"mcp_tool_injection": `
def handle_tool_call(tool_name, arguments):
    # VULNERABLE: No input validation on MCP tool calls
    if tool_name == "execute_command":
        command = arguments.get("command")
        return subprocess.run(command, shell=True)
    
def process_mcp_resource(resource_uri):
    # VULNERABLE: Path traversal in resource access
    file_path = resource_uri.replace("file://", "")
    return open(file_path).read()
`,

	"mcp_data_leakage": `
def get_system_info():
    # VULNERABLE: Exposing sensitive system information
    return {
        "hostname": socket.gethostname(),
        "env_vars": dict(os.environ),
        "process_list": subprocess.check_output(["ps", "aux"]),
        "network_config": subprocess.check_output(["ifconfig"])
    }
`,
}

// SafeSamples contains secure code examples for testing false positives
var SafeSamples = map[string]string{
	"safe_command_execution": `
import subprocess
import shlex

def safe_process_file(filename):
    # SAFE: Using shlex to escape arguments
    safe_filename = shlex.quote(filename)
    result = subprocess.run(["cat", safe_filename], capture_output=True)
    return result.stdout

def validated_command(user_input):
    # SAFE: Input validation and allowlist
    allowed_commands = ["ls", "pwd", "date"]
    if user_input not in allowed_commands:
        raise ValueError("Invalid command")
    return subprocess.run([user_input], capture_output=True)
`,

	"safe_sql_queries": `
def get_user_safe(user_id):
    # SAFE: Using parameterised queries
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()

def search_products_safe(search_term):
    # SAFE: Prepared statement
    sql = "SELECT * FROM products WHERE name LIKE %s"
    return db.execute(sql, (f"%{search_term}%",))
`,

	"safe_file_access": `
import os
import os.path

def read_file_safe(filename):
    # SAFE: Path validation and restriction
    base_dir = "/app/uploads"
    filepath = os.path.join(base_dir, filename)
    filepath = os.path.abspath(filepath)
    
    if not filepath.startswith(base_dir):
        raise ValueError("Path traversal attempt detected")
    
    with open(filepath, 'r') as f:
        return f.read()
`,

	"safe_configuration": `
import os
from cryptography.fernet import Fernet

# SAFE: Using environment variables
DATABASE_PASSWORD = os.getenv("DB_PASSWORD")
API_KEY = os.getenv("API_KEY")

def get_secret_key():
    # SAFE: Loading from secure configuration
    key_file = os.getenv("KEY_FILE", "/etc/secrets/app.key")
    with open(key_file, 'rb') as f:
        return f.read()
`,
}

// MCPVulnerabilityTestCases contains MCP-specific vulnerability test cases
var MCPVulnerabilityTestCases = []struct {
	Name        string
	Method      string
	Params      map[string]interface{}
	ExpectedVul string
	Severity    string
}{
	{
		Name:   "Command Injection via Tool Call",
		Method: "tools/call",
		Params: map[string]interface{}{
			"name": "execute_command",
			"arguments": map[string]interface{}{
				"command": "ls; rm -rf /",
			},
		},
		ExpectedVul: "MCP_TOOL_INJECTION",
		Severity:    "Critical",
	},
	{
		Name:   "Path Traversal via Resource Access",
		Method: "resources/read",
		Params: map[string]interface{}{
			"uri": "file://../../../etc/passwd",
		},
		ExpectedVul: "MCP_PATH_TRAVERSAL",
		Severity:    "High",
	},
	{
		Name:   "Information Disclosure via System Tool",
		Method: "tools/call",
		Params: map[string]interface{}{
			"name": "get_system_info",
			"arguments": map[string]interface{}{
				"include_sensitive": true,
			},
		},
		ExpectedVul: "MCP_INFO_DISCLOSURE",
		Severity:    "Medium",
	},
	{
		Name:   "SQL Injection via Database Tool",
		Method: "tools/call",
		Params: map[string]interface{}{
			"name": "query_database",
			"arguments": map[string]interface{}{
				"query": "SELECT * FROM users WHERE id = '1' OR '1'='1'",
			},
		},
		ExpectedVul: "MCP_SQL_INJECTION",
		Severity:    "Critical",
	},
}
