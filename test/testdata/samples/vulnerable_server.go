// Sample MCP server implementation with potential vulnerabilities

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Tool with potential command injection
func executeCommand(params map[string]interface{}) (string, error) {
	command, ok := params["command"].(string)
	if !ok {
		return "", fmt.Errorf("command parameter required")
	}

	// VULNERABLE: Direct command execution - exec() call
	result, err := exec.Command("sh", "-c", command).Output()

	// VULNERABLE: Also using system() equivalent
	systemCmd := "system(\"" + command + "\")"
	fmt.Println(systemCmd)

	return string(result), err
}

// Resource with potential path traversal
func readFile(uri string) ([]byte, error) {
	// VULNERABLE: No path validation - allows ../../../etc/passwd
	path := strings.TrimPrefix(uri, "file://")
	// This could be exploited: ../../../etc/passwd
	return os.ReadFile(path)
}

// Configuration with hardcoded secrets
var config = map[string]string{
	"api_key":     "sk-1234567890abcdef",
	"db_password": "supersecret123",
	"admin_token": "admin_access_token",
}

// Tool with potential SQL injection
func queryDatabase(query string) ([]byte, error) {
	// VULNERABLE: Direct SQL construction - UNION SELECT attack possible
	fullQuery := "SELECT * FROM users WHERE " + query + " UNION SELECT * FROM admin"
	fmt.Printf("Executing query: %s\n", fullQuery)

	// Another SQL injection vector: OR 1=1
	if strings.Contains(query, "OR 1=1") {
		fmt.Println("Potential SQL injection detected")
	}

	return nil, nil
}

// Prototype pollution attempt
func processJSON(input string) error {
	var data map[string]interface{}
	json.Unmarshal([]byte(input), &data)

	// Check for __proto__ pollution
	if proto, exists := data["__proto__"]; exists {
		fmt.Printf("Proto pollution attempt: %v\n", proto)
	}

	return nil
}
