package mocks

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

// MockMCPServer provides a test MCP server for integration testing
type MockMCPServer struct {
	Server          *httptest.Server
	Tools           []types.MCPTool
	Resources       []types.MCPResource
	VulnerableTools map[string]bool
	RequestLog      []types.MCPMessage
}

// NewMockMCPServer creates a new mock MCP server
func NewMockMCPServer() *MockMCPServer {
	mock := &MockMCPServer{
		Tools: []types.MCPTool{
			{
				Name:        "safe_tool",
				Description: "A safe tool for testing",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"input": map[string]interface{}{
							"type": "string",
						},
					},
				},
			},
			{
				Name:        "vulnerable_command",
				Description: "A tool that executes system commands",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"command": map[string]interface{}{
							"type": "string",
						},
					},
				},
			},
			{
				Name:        "database_query",
				Description: "Execute database queries",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"query": map[string]interface{}{
							"type": "string",
						},
					},
				},
			},
		},
		Resources: []types.MCPResource{
			{
				URI:         "file://safe/path/document.txt",
				Name:        "safe_document",
				Description: "A safe document",
				MimeType:    "text/plain",
			},
			{
				URI:         "file://config/database.conf",
				Name:        "database_config",
				Description: "Database configuration",
				MimeType:    "text/plain",
			},
		},
		VulnerableTools: map[string]bool{
			"vulnerable_command": true,
			"database_query":     true,
		},
		RequestLog: make([]types.MCPMessage, 0),
	}

	// Create HTTP server
	mock.Server = httptest.NewServer(http.HandlerFunc(mock.handleRequest))
	return mock
}

// Close shuts down the mock server
func (m *MockMCPServer) Close() {
	m.Server.Close()
}

// GetURL returns the mock server URL
func (m *MockMCPServer) GetURL() string {
	return m.Server.URL
}

// handleRequest handles incoming MCP requests
func (m *MockMCPServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Only POST requests allowed", http.StatusMethodNotAllowed)
		return
	}

	var message types.MCPMessage
	err := json.NewDecoder(r.Body).Decode(&message)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Log the request
	m.RequestLog = append(m.RequestLog, message)

	// Route based on URL path
	switch {
	case strings.HasSuffix(r.URL.Path, "/mcp/initialize"):
		m.handleInitialize(w, &message)
	case strings.HasSuffix(r.URL.Path, "/mcp/tools/list"):
		m.handleToolsList(w, &message)
	case strings.HasSuffix(r.URL.Path, "/mcp/resources/list"):
		m.handleResourcesList(w, &message)
	case strings.HasSuffix(r.URL.Path, "/tools/call"):
		m.handleToolCall(w, &message)
	case strings.HasSuffix(r.URL.Path, "/resources/read"):
		m.handleResourceRead(w, &message)
	default:
		// Default handler for direct POST to base URL
		switch message.Method {
		case "initialize":
			m.handleInitialize(w, &message)
		case "tools/list":
			m.handleToolsList(w, &message)
		case "tools/call":
			m.handleToolCall(w, &message)
		case "resources/list":
			m.handleResourcesList(w, &message)
		case "resources/read":
			m.handleResourceRead(w, &message)
		default:
			m.handleError(w, &message, "Unknown method")
		}
	}
}

// handleInitialize handles MCP initialize requests
func (m *MockMCPServer) handleInitialize(w http.ResponseWriter, message *types.MCPMessage) {
	response := types.MCPMessage{
		JSONRPC: "2.0",
		ID:      message.ID,
		Result: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools":     map[string]interface{}{},
				"resources": map[string]interface{}{},
			},
			"serverInfo": map[string]interface{}{
				"name":    "Mock MCP Server",
				"version": "1.0.0",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleToolsList handles tools/list requests
func (m *MockMCPServer) handleToolsList(w http.ResponseWriter, message *types.MCPMessage) {
	response := types.MCPMessage{
		JSONRPC: "2.0",
		ID:      message.ID,
		Result: map[string]interface{}{
			"tools": m.Tools,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleResourcesList handles resources/list requests
func (m *MockMCPServer) handleResourcesList(w http.ResponseWriter, message *types.MCPMessage) {
	response := types.MCPMessage{
		JSONRPC: "2.0",
		ID:      message.ID,
		Result: map[string]interface{}{
			"resources": m.Resources,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleToolCall handles tools/call requests
func (m *MockMCPServer) handleToolCall(w http.ResponseWriter, message *types.MCPMessage) {
	params, ok := message.Params.(map[string]interface{})
	if !ok {
		m.handleError(w, message, "Invalid parameters")
		return
	}

	toolName, ok := params["name"].(string)
	if !ok {
		m.handleError(w, message, "Missing tool name")
		return
	}

	arguments, _ := params["arguments"].(map[string]interface{})

	// Simulate vulnerable responses
	result := map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": m.simulateToolExecution(toolName, arguments),
			},
		},
	}

	if m.VulnerableTools[toolName] {
		// Add vulnerability indicators
		result["_security_warning"] = "This tool may be vulnerable to injection"
	}

	response := types.MCPMessage{
		JSONRPC: "2.0",
		ID:      message.ID,
		Result:  result,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleResourceRead handles resources/read requests
func (m *MockMCPServer) handleResourceRead(w http.ResponseWriter, message *types.MCPMessage) {
	params, ok := message.Params.(map[string]interface{})
	if !ok {
		m.handleError(w, message, "Invalid parameters")
		return
	}

	uri, ok := params["uri"].(string)
	if !ok {
		m.handleError(w, message, "Missing resource URI")
		return
	}

	// Simulate resource content
	var content string
	if strings.Contains(uri, "../") || strings.Contains(uri, "..\\") {
		content = "VULNERABILITY: Path traversal detected in URI: " + uri
	} else if strings.Contains(uri, "passwd") || strings.Contains(uri, "shadow") {
		content = "root:x:0:0:root:/root:/bin/bash\nVULNERABILITY: Sensitive file access"
	} else {
		content = fmt.Sprintf("Safe content for resource: %s", uri)
	}

	response := types.MCPMessage{
		JSONRPC: "2.0",
		ID:      message.ID,
		Result: map[string]interface{}{
			"contents": []map[string]interface{}{
				{
					"uri":      uri,
					"mimeType": "text/plain",
					"text":     content,
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleError sends an error response
func (m *MockMCPServer) handleError(w http.ResponseWriter, message *types.MCPMessage, errorMsg string) {
	response := types.MCPMessage{
		JSONRPC: "2.0",
		ID:      message.ID,
		Error: &types.MCPError{
			Code:    -32602,
			Message: errorMsg,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// simulateToolExecution simulates tool execution responses
func (m *MockMCPServer) simulateToolExecution(toolName string, arguments map[string]interface{}) string {
	switch toolName {
	case "vulnerable_command":
		if cmd, ok := arguments["command"].(string); ok {
			return fmt.Sprintf("Executing command: %s\nVULNERABILITY: Command injection possible", cmd)
		}
		return "Command executed"

	case "database_query":
		if query, ok := arguments["query"].(string); ok {
			if strings.Contains(strings.ToLower(query), "or") && strings.Contains(query, "=") {
				return fmt.Sprintf("Query result: %s\nVULNERABILITY: SQL injection detected", query)
			}
			return fmt.Sprintf("Query executed: %s", query)
		}
		return "Query executed"

	case "safe_tool":
		if input, ok := arguments["input"].(string); ok {
			return fmt.Sprintf("Processed input safely: %s", input)
		}
		return "Safe operation completed"

	default:
		return fmt.Sprintf("Unknown tool: %s", toolName)
	}
}

// GetRequestLog returns the log of all requests received
func (m *MockMCPServer) GetRequestLog() []types.MCPMessage {
	return m.RequestLog
}

// ClearRequestLog clears the request log
func (m *MockMCPServer) ClearRequestLog() {
	m.RequestLog = make([]types.MCPMessage, 0)
}

// AddVulnerableTool adds a tool that should be flagged as vulnerable
func (m *MockMCPServer) AddVulnerableTool(toolName string) {
	m.VulnerableTools[toolName] = true
}

// NewVulnerableMCPServer creates a mock server with known vulnerabilities
func NewVulnerableMCPServer() *MockMCPServer {
	mock := NewMockMCPServer()

	// Add more vulnerable tools
	mock.Tools = append(mock.Tools, []types.MCPTool{
		{
			Name:        "system_exec",
			Description: "Execute system commands with full privileges",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"command": map[string]interface{}{
						"type": "string",
					},
					"shell": map[string]interface{}{
						"type": "boolean",
					},
				},
			},
		},
		{
			Name:        "file_reader",
			Description: "Read any file from the filesystem",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type": "string",
					},
				},
			},
		},
	}...)

	// Mark all tools as vulnerable
	mock.VulnerableTools["system_exec"] = true
	mock.VulnerableTools["file_reader"] = true

	return mock
}

// NewSecureMCPServer creates a mock server without vulnerabilities
func NewSecureMCPServer() *MockMCPServer {
	mock := &MockMCPServer{
		Tools: []types.MCPTool{
			{
				Name:        "safe_calculator",
				Description: "Perform safe mathematical calculations",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"expression": map[string]interface{}{
							"type": "string",
						},
					},
				},
			},
			{
				Name:        "text_processor",
				Description: "Process text safely",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"text": map[string]interface{}{
							"type": "string",
						},
					},
				},
			},
		},
		Resources: []types.MCPResource{
			{
				URI:         "data://public/info.txt",
				Name:        "public_info",
				Description: "Public information document",
				MimeType:    "text/plain",
			},
		},
		VulnerableTools: make(map[string]bool),
		RequestLog:      make([]types.MCPMessage, 0),
	}

	mock.Server = httptest.NewServer(http.HandlerFunc(mock.handleRequest))
	return mock
}
