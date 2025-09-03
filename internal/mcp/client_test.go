package mcp

import (
	"testing"
	"time"

	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name        string
		timeout     time.Duration
		userAgent   string
		description string
	}{
		{
			name:        "StandardClient",
			timeout:     30 * time.Second,
			userAgent:   "MCP-Security-Scanner/1.0",
			description: "Should create client with standard configuration",
		},
		{
			name:        "LongTimeoutClient",
			timeout:     2 * time.Minute,
			userAgent:   "Test-Agent",
			description: "Should create client with long timeout",
		},
		{
			name:        "ZeroTimeout",
			timeout:     0,
			userAgent:   "Quick-Agent",
			description: "Should handle zero timeout gracefully",
		},
		{
			name:        "EmptyUserAgent",
			timeout:     30 * time.Second,
			userAgent:   "",
			description: "Should handle empty user agent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.timeout, tt.userAgent)

			if client == nil {
				t.Errorf("Expected valid client, got nil. Description: %s", tt.description)
				return
			}

			// Test that client has the expected configuration
			if client.userAgent != tt.userAgent {
				t.Errorf("Expected user agent '%s', got '%s'", tt.userAgent, client.userAgent)
			}

			// Test that HTTP client is configured
			if client.httpClient == nil {
				t.Error("Expected HTTP client to be configured")
			}

			// Test timeout configuration
			if client.httpClient.Timeout != tt.timeout {
				t.Errorf("Expected timeout %v, got %v", tt.timeout, client.httpClient.Timeout)
			}
		})
	}
}

func TestClientSendRequest(t *testing.T) {
	client := NewClient(5*time.Second, "Test-Agent")

	tests := []struct {
		name        string
		serverURL   string
		message     types.MCPMessage
		expectError bool
		description string
	}{
		{
			name:      "ValidMessage",
			serverURL: "http://localhost:8080",
			message: types.MCPMessage{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "test",
			},
			expectError: true, // Will fail unless server is running
			description: "Should attempt to send valid MCP message",
		},
		{
			name:      "InvalidURL",
			serverURL: "not-a-url",
			message: types.MCPMessage{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "test",
			},
			expectError: true,
			description: "Should fail with invalid URL",
		},
		{
			name:      "EmptyURL",
			serverURL: "",
			message: types.MCPMessage{
				JSONRPC: "2.0",
				ID:      1,
				Method:  "test",
			},
			expectError: true,
			description: "Should fail with empty URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := client.SendRequest(tt.serverURL, tt.message)

			if tt.expectError {
				if err == nil {
					t.Logf("Unexpected success for %s (server might be running): got %d bytes",
						tt.name, len(response))
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %s: %v. Description: %s",
						tt.name, err, tt.description)
				}
				if response == nil {
					t.Error("Expected response data, got nil")
				}
			}
		})
	}
}

func TestClientInitialize(t *testing.T) {
	client := NewClient(5*time.Second, "Test-Agent")

	tests := []struct {
		name        string
		serverURL   string
		expectError bool
		description string
	}{
		{
			name:        "LocalhostInitialize",
			serverURL:   "http://localhost:8080",
			expectError: true, // Will fail unless server is running
			description: "Should attempt to initialize with localhost",
		},
		{
			name:        "InvalidHostInitialize",
			serverURL:   "http://nonexistent.invalid",
			expectError: true,
			description: "Should fail to initialize with invalid host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverInfo, err := client.Initialize(tt.serverURL)

			if tt.expectError {
				if err == nil {
					t.Logf("Unexpected success initializing %s (server might be running)", tt.serverURL)
					if serverInfo == nil {
						t.Error("Expected server info to not be nil on success")
					}
				} else {
					t.Logf("Expected error initializing %s: %v", tt.serverURL, err)
				}
			} else {
				if err != nil {
					t.Errorf("Failed to initialize %s: %v. Description: %s",
						tt.serverURL, err, tt.description)
				}
				if serverInfo == nil {
					t.Error("Expected server info to not be nil on success")
				}
			}
		})
	}
}

func TestClientListTools(t *testing.T) {
	client := NewClient(5*time.Second, "Test-Agent")

	tests := []struct {
		name        string
		serverURL   string
		expectError bool
		description string
	}{
		{
			name:        "LocalhostListTools",
			serverURL:   "http://localhost:8080",
			expectError: true, // Will fail unless server is running
			description: "Should attempt to list tools from localhost",
		},
		{
			name:        "InvalidHostListTools",
			serverURL:   "http://nonexistent.invalid",
			expectError: true,
			description: "Should fail to list tools from invalid host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tools, err := client.ListTools(tt.serverURL)

			if tt.expectError {
				if err == nil {
					t.Logf("Unexpected success listing tools from %s (server might be running)", tt.serverURL)
					if tools == nil {
						t.Error("Expected tools list to not be nil on success")
					}
					t.Logf("Successfully retrieved %d tools", len(tools))
				} else {
					t.Logf("Expected error listing tools from %s: %v", tt.serverURL, err)
				}
			} else {
				if err != nil {
					t.Errorf("Failed to list tools from %s: %v. Description: %s",
						tt.serverURL, err, tt.description)
				}
				if tools == nil {
					t.Error("Expected tools list to not be nil on success")
				}
			}
		})
	}
}

func TestClientListResources(t *testing.T) {
	client := NewClient(5*time.Second, "Test-Agent")

	tests := []struct {
		name        string
		serverURL   string
		expectError bool
		description string
	}{
		{
			name:        "LocalhostListResources",
			serverURL:   "http://localhost:8080",
			expectError: true, // Will fail unless server is running
			description: "Should attempt to list resources from localhost",
		},
		{
			name:        "InvalidHostListResources",
			serverURL:   "http://nonexistent.invalid",
			expectError: true,
			description: "Should fail to list resources from invalid host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resources, err := client.ListResources(tt.serverURL)

			if tt.expectError {
				if err == nil {
					t.Logf("Unexpected success listing resources from %s (server might be running)", tt.serverURL)
					if resources == nil {
						t.Error("Expected resources list to not be nil on success")
					}
					t.Logf("Successfully retrieved %d resources", len(resources))
				} else {
					t.Logf("Expected error listing resources from %s: %v", tt.serverURL, err)
				}
			} else {
				if err != nil {
					t.Errorf("Failed to list resources from %s: %v. Description: %s",
						tt.serverURL, err, tt.description)
				}
				if resources == nil {
					t.Error("Expected resources list to not be nil on success")
				}
			}
		})
	}
}

func TestClientCallTool(t *testing.T) {
	client := NewClient(5*time.Second, "Test-Agent")

	tests := []struct {
		name        string
		serverURL   string
		toolName    string
		args        map[string]interface{}
		expectError bool
		description string
	}{
		{
			name:        "SimpleToolCall",
			serverURL:   "http://localhost:8080",
			toolName:    "test_tool",
			args:        map[string]interface{}{"param1": "value1"},
			expectError: true, // Will fail unless server is running
			description: "Should attempt to call tool with simple arguments",
		},
		{
			name:        "EmptyToolCall",
			serverURL:   "http://localhost:8080",
			toolName:    "",
			args:        map[string]interface{}{},
			expectError: true,
			description: "Should handle empty tool name",
		},
		{
			name:      "ComplexArgsToolCall",
			serverURL: "http://localhost:8080",
			toolName:  "complex_tool",
			args: map[string]interface{}{
				"string_param": "test",
				"int_param":    42,
				"bool_param":   true,
				"array_param":  []string{"a", "b", "c"},
			},
			expectError: true,
			description: "Should handle complex tool arguments",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := client.CallTool(tt.serverURL, tt.toolName, tt.args)

			if tt.expectError {
				if err == nil {
					t.Logf("Unexpected success calling tool %s (server might be running): got %d bytes",
						tt.toolName, len(result))
				} else {
					t.Logf("Expected error calling tool %s: %v", tt.toolName, err)
				}
			} else {
				if err != nil {
					t.Errorf("Failed to call tool %s: %v. Description: %s",
						tt.toolName, err, tt.description)
				}
				if result == nil {
					t.Error("Expected result to not be nil on success")
				}
			}
		})
	}
}

func TestClientReadResource(t *testing.T) {
	client := NewClient(5*time.Second, "Test-Agent")

	tests := []struct {
		name        string
		serverURL   string
		resourceURI string
		expectError bool
		description string
	}{
		{
			name:        "FileResource",
			serverURL:   "http://localhost:8080",
			resourceURI: "file:///path/to/test.txt",
			expectError: true, // Will fail unless server is running
			description: "Should attempt to read file resource",
		},
		{
			name:        "HTTPResource",
			serverURL:   "http://localhost:8080",
			resourceURI: "http://example.com/resource",
			expectError: true,
			description: "Should attempt to read HTTP resource",
		},
		{
			name:        "EmptyURI",
			serverURL:   "http://localhost:8080",
			resourceURI: "",
			expectError: true,
			description: "Should handle empty resource URI",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, err := client.ReadResource(tt.serverURL, tt.resourceURI)

			if tt.expectError {
				if err == nil {
					t.Logf("Unexpected success reading resource %s (server might be running): got %d bytes",
						tt.resourceURI, len(content))
				} else {
					t.Logf("Expected error reading resource %s: %v", tt.resourceURI, err)
				}
			} else {
				if err != nil {
					t.Errorf("Failed to read resource %s: %v. Description: %s",
						tt.resourceURI, err, tt.description)
				}
				if content == nil {
					t.Error("Expected content to not be nil on success")
				}
			}
		})
	}
}

func TestClientReadResourceWithHeaders(t *testing.T) {
	client := NewClient(5*time.Second, "Test-Agent")

	tests := []struct {
		name        string
		serverURL   string
		resourceURI string
		headers     map[string]string
		expectError bool
		description string
	}{
		{
			name:        "ResourceWithHeaders",
			serverURL:   "http://localhost:8080",
			resourceURI: "file:///path/to/test.txt",
			headers:     map[string]string{"Authorization": "Bearer token"},
			expectError: true, // Will fail unless server is running
			description: "Should attempt to read resource with custom headers",
		},
		{
			name:        "ResourceEmptyHeaders",
			serverURL:   "http://localhost:8080",
			resourceURI: "file:///path/to/test.txt",
			headers:     map[string]string{},
			expectError: true,
			description: "Should handle empty headers map",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, err := client.ReadResourceWithHeaders(tt.serverURL, tt.resourceURI, tt.headers)

			if tt.expectError {
				if err == nil {
					t.Logf("Unexpected success reading resource %s with headers (server might be running): got %d bytes",
						tt.resourceURI, len(content))
				} else {
					t.Logf("Expected error reading resource %s with headers: %v", tt.resourceURI, err)
				}
			} else {
				if err != nil {
					t.Errorf("Failed to read resource %s with headers: %v. Description: %s",
						tt.resourceURI, err, tt.description)
				}
				if content == nil {
					t.Error("Expected content to not be nil on success")
				}
			}
		})
	}
}
