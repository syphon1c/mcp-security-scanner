// Copyright (c) 2025 Gareth Phillips/syphon1c
// Licensed under the MIT License - see LICENSE file for details

package mcp

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

// Client handles MCP protocol communication
type Client struct {
	httpClient *http.Client
	userAgent  string
}

// NewClient creates a new MCP protocol client with specified timeout and user agent configuration.
// The client is configured with secure TLS settings and customizable timeout values for
// reliable communication with MCP servers during security scanning operations.
//
// Parameters:
//   - timeout: Maximum duration for HTTP requests before timing out
//   - userAgent: Custom user agent string for HTTP requests (useful for identification)
//
// Returns:
//   - *Client: Configured MCP client ready for protocol communication
//
// The client includes secure TLS configuration with certificate verification enabled
// and customizable timeout settings to handle varying MCP server response times.
func NewClient(timeout time.Duration, userAgent string) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false,
					MinVersion:         tls.VersionTLS12, // Fix G402: TLS MinVersion too low
				},
			},
		},
		userAgent: userAgent,
	}
}

// SendRequest transmits MCP protocol messages to target servers and retrieves response data.
// The function handles JSON marshalling, HTTP request construction, secure communication,
// and response processing for all MCP protocol interactions during security scanning.
//
// Parameters:
//   - serverURL: Complete URL of the target MCP server including protocol and port
//   - message: MCP message structure conforming to JSONRPC 2.0 protocol specification
//
// Returns:
//   - []byte: Raw response body from the MCP server
//   - error: Non-nil if marshalling, request creation, network communication, or response reading fails
//
// The function sets appropriate Content-Type and User-Agent headers, handles HTTP errors,
// and provides detailed error information for debugging and security analysis purposes.
func (c *Client) SendRequest(serverURL string, message types.MCPMessage) ([]byte, error) {
	jsonData, err := json.Marshal(message)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal MCP message: %v", err)
	}

	req, err := http.NewRequest("POST", serverURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	return body, nil
}

// Initialize sends an MCP initialize message
func (c *Client) Initialize(serverURL string) (*types.MCPServerInfo, error) {
	initMsg := types.MCPMessage{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "MCP-Security-Scanner",
				"version": "1.0.0",
			},
		},
	}

	// Append MCP initialize endpoint
	initURL := serverURL + "/mcp/initialize"
	responseBody, err := c.SendRequest(initURL, initMsg)
	if err != nil {
		return nil, fmt.Errorf("initialize request failed: %v", err)
	}

	var response types.MCPMessage
	err = json.Unmarshal(responseBody, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse initialize response: %v", err)
	}

	serverInfo := &types.MCPServerInfo{
		Protocol: "MCP",
	}

	// Extract server capabilities from response
	if result, ok := response.Result.(map[string]interface{}); ok {
		if serverInfoData, ok := result["serverInfo"].(map[string]interface{}); ok {
			if name, ok := serverInfoData["name"].(string); ok {
				serverInfo.Name = name
			}
			if version, ok := serverInfoData["version"].(string); ok {
				serverInfo.Version = version
			}
		}
	}

	return serverInfo, nil
}

// ListTools discovers available tools from the MCP server
func (c *Client) ListTools(serverURL string) ([]types.MCPTool, error) {
	toolsMsg := types.MCPMessage{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}

	// Append MCP tools endpoint
	toolsURL := serverURL + "/mcp/tools/list"
	responseBody, err := c.SendRequest(toolsURL, toolsMsg)
	if err != nil {
		return nil, fmt.Errorf("tools/list request failed: %v", err)
	}

	var response types.MCPMessage
	err = json.Unmarshal(responseBody, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tools/list response: %v", err)
	}

	var tools []types.MCPTool

	if result, ok := response.Result.(map[string]interface{}); ok {
		if toolsList, ok := result["tools"].([]interface{}); ok {
			for _, toolData := range toolsList {
				if toolMap, ok := toolData.(map[string]interface{}); ok {
					tool := types.MCPTool{}
					if name, ok := toolMap["name"].(string); ok {
						tool.Name = name
					}
					if desc, ok := toolMap["description"].(string); ok {
						tool.Description = desc
					}
					if schema, ok := toolMap["inputSchema"].(map[string]interface{}); ok {
						tool.InputSchema = schema
					}
					tools = append(tools, tool)
				}
			}
		}
	}

	return tools, nil
}

// ListResources discovers available resources from the MCP server
func (c *Client) ListResources(serverURL string) ([]types.MCPResource, error) {
	resourcesMsg := types.MCPMessage{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "resources/list",
	}

	// Append MCP resources endpoint
	resourcesURL := serverURL + "/mcp/resources/list"
	responseBody, err := c.SendRequest(resourcesURL, resourcesMsg)
	if err != nil {
		return nil, fmt.Errorf("resources/list request failed: %v", err)
	}

	var response types.MCPMessage
	err = json.Unmarshal(responseBody, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse resources/list response: %v", err)
	}

	var resources []types.MCPResource

	if result, ok := response.Result.(map[string]interface{}); ok {
		if resourcesList, ok := result["resources"].([]interface{}); ok {
			for _, resourceData := range resourcesList {
				if resourceMap, ok := resourceData.(map[string]interface{}); ok {
					resource := types.MCPResource{}
					if uri, ok := resourceMap["uri"].(string); ok {
						resource.URI = uri
					}
					if name, ok := resourceMap["name"].(string); ok {
						resource.Name = name
					}
					if desc, ok := resourceMap["description"].(string); ok {
						resource.Description = desc
					}
					if mimeType, ok := resourceMap["mimeType"].(string); ok {
						resource.MimeType = mimeType
					}
					resources = append(resources, resource)
				}
			}
		}
	}

	return resources, nil
}

// CallTool calls a specific tool with given arguments
func (c *Client) CallTool(serverURL, toolName string, arguments map[string]interface{}) ([]byte, error) {
	toolCall := types.MCPMessage{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      toolName,
			"arguments": arguments,
		},
	}

	return c.SendRequest(serverURL, toolCall)
}

// ReadResource reads a specific resource from the MCP server
func (c *Client) ReadResource(serverURL, resourceURI string) ([]byte, error) {
	resourceRead := types.MCPMessage{
		JSONRPC: "2.0",
		ID:      5,
		Method:  "resources/read",
		Params: map[string]interface{}{
			"uri": resourceURI,
		},
	}

	return c.SendRequest(serverURL, resourceRead)
}

// ReadResourceWithHeaders reads a resource with custom headers
func (c *Client) ReadResourceWithHeaders(serverURL, resourceURI string, headers map[string]string) ([]byte, error) {
	// Create a custom request with headers
	resourceRead := types.MCPMessage{
		JSONRPC: "2.0",
		ID:      6,
		Method:  "resources/read",
		Params: map[string]interface{}{
			"uri":     resourceURI,
			"headers": headers,
		},
	}

	return c.SendRequest(serverURL, resourceRead)
}
