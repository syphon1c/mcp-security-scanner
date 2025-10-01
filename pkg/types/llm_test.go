package types

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDetectLLMProvider(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		headers  map[string]string
		expected LLMProvider
	}{
		{
			name:     "OpenAI endpoint",
			endpoint: "https://api.openai.com/v1/chat/completions",
			headers:  map[string]string{},
			expected: ProviderOpenAI,
		},
		{
			name:     "Claude endpoint",
			endpoint: "https://api.anthropic.com/v1/messages",
			headers:  map[string]string{},
			expected: ProviderClaude,
		},
		{
			name:     "Google endpoint",
			endpoint: "https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent",
			headers:  map[string]string{},
			expected: ProviderGoogle,
		},
		{
			name:     "OpenAI by header",
			endpoint: "https://custom-proxy.com/api",
			headers:  map[string]string{"Authorization": "Bearer sk-1234567890abcdef"},
			expected: ProviderOpenAI,
		},
		{
			name:     "Claude by header",
			endpoint: "https://custom-proxy.com/api",
			headers:  map[string]string{"Authorization": "Bearer x-api-key-12345"},
			expected: ProviderClaude,
		},
		{
			name:     "Generic unknown",
			endpoint: "https://unknown-provider.com/api",
			headers:  map[string]string{},
			expected: ProviderGeneric,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectLLMProvider(tt.endpoint, tt.headers)
			if result != tt.expected {
				t.Errorf("DetectLLMProvider() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestNormalizeLLMRequest(t *testing.T) {
	tests := []struct {
		name      string
		rawJSON   string
		provider  LLMProvider
		expectErr bool
		checkFunc func(*LLMRequest) error
	}{
		{
			name: "OpenAI format",
			rawJSON: `{
				"model": "gpt-4",
				"messages": [
					{"role": "user", "content": "Hello"}
				],
				"max_tokens": 100,
				"temperature": 0.7
			}`,
			provider:  ProviderOpenAI,
			expectErr: false,
			checkFunc: func(req *LLMRequest) error {
				if req.Model != "gpt-4" {
					t.Errorf("Expected model 'gpt-4', got '%s'", req.Model)
				}
				if len(req.Messages) != 1 {
					t.Errorf("Expected 1 message, got %d", len(req.Messages))
				}
				if req.Messages[0].Role != "user" {
					t.Errorf("Expected role 'user', got '%s'", req.Messages[0].Role)
				}
				return nil
			},
		},
		{
			name: "Claude format",
			rawJSON: `{
				"model": "claude-3-sonnet-20240229",
				"max_tokens": 1024,
				"messages": [
					{"role": "user", "content": "Hello Claude"}
				],
				"system": "You are a helpful assistant"
			}`,
			provider:  ProviderClaude,
			expectErr: false,
			checkFunc: func(req *LLMRequest) error {
				if req.Model != "claude-3-sonnet-20240229" {
					t.Errorf("Expected model 'claude-3-sonnet-20240229', got '%s'", req.Model)
				}
				if req.System != "You are a helpful assistant" {
					t.Errorf("Expected system message, got '%s'", req.System)
				}
				return nil
			},
		},
		{
			name:      "Invalid JSON",
			rawJSON:   `{"invalid": json}`,
			provider:  ProviderOpenAI,
			expectErr: true,
			checkFunc: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NormalizeLLMRequest([]byte(tt.rawJSON), tt.provider)
			
			if tt.expectErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			
			if result.Provider != tt.provider {
				t.Errorf("Expected provider %v, got %v", tt.provider, result.Provider)
			}
			
			if tt.checkFunc != nil {
				tt.checkFunc(result)
			}
		})
	}
}

func TestLLMMessage_GetContentAsString(t *testing.T) {
	tests := []struct {
		name     string
		message  LLMMessage
		expected string
	}{
		{
			name: "String content",
			message: LLMMessage{
				Role:    "user",
				Content: "Hello, world!",
			},
			expected: "Hello, world!",
		},
		{
			name: "Array content with text",
			message: LLMMessage{
				Role: "user",
				Content: []LLMContent{
					{Type: "text", Text: "Hello"},
					{Type: "text", Text: "world"},
				},
			},
			expected: "Hello world ",
		},
		{
			name: "Mixed content with image",
			message: LLMMessage{
				Role: "user",
				Content: []LLMContent{
					{Type: "text", Text: "Look at this image:"},
					{Type: "image_url", ImageURL: &LLMImageURL{URL: "https://example.com/image.jpg"}},
					{Type: "text", Text: "What do you see?"},
				},
			},
			expected: "Look at this image: What do you see? ",
		},
		{
			name: "Empty content",
			message: LLMMessage{
				Role:    "user",
				Content: "",
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.message.GetContentAsString()
			if result != tt.expected {
				t.Errorf("GetContentAsString() = '%s', want '%s'", result, tt.expected)
			}
		})
	}
}

func TestLLMRequest_CountTokensEstimate(t *testing.T) {
	tests := []struct {
		name     string
		request  LLMRequest
		minCount int // Minimum expected tokens (rough estimate)
		maxCount int // Maximum expected tokens (rough estimate)
	}{
		{
			name: "Simple request",
			request: LLMRequest{
				Model: "gpt-4",
				Messages: []LLMMessage{
					{Role: "user", Content: "Hello"},
				},
			},
			minCount: 1,
			maxCount: 5,
		},
		{
			name: "Longer request",
			request: LLMRequest{
				Model: "gpt-4",
				Messages: []LLMMessage{
					{Role: "system", Content: "You are a helpful assistant."},
					{Role: "user", Content: "Please explain quantum computing in simple terms."},
				},
			},
			minCount: 10,
			maxCount: 25,
		},
		{
			name: "Request with system message",
			request: LLMRequest{
				Model:  "claude-3-sonnet-20240229",
				System: "You are an expert in artificial intelligence.",
				Messages: []LLMMessage{
					{Role: "user", Content: "What is machine learning?"},
				},
			},
			minCount: 10,
			maxCount: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := tt.request.CountTokensEstimate()
			if count < tt.minCount || count > tt.maxCount {
				t.Errorf("CountTokensEstimate() = %d, want between %d and %d", count, tt.minCount, tt.maxCount)
			}
		})
	}
}

func TestLLMSecurityContext(t *testing.T) {
	context := LLMSecurityContext{
		RequestID:       "test-123",
		Provider:        ProviderOpenAI,
		Model:          "gpt-4",
		ClientIP:       "192.168.1.100",
		Timestamp:      time.Now(),
		PromptInjection: true,
		Jailbreaking:   false,
		ContainsPII:    true,
		RiskScore:      7,
		RiskLevel:      "High",
		BlockedReasons: []string{"Prompt injection detected", "PII found"},
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(context)
	if err != nil {
		t.Errorf("Failed to marshal LLMSecurityContext: %v", err)
	}

	// Test JSON deserialization
	var decoded LLMSecurityContext
	err = json.Unmarshal(jsonData, &decoded)
	if err != nil {
		t.Errorf("Failed to unmarshal LLMSecurityContext: %v", err)
	}

	// Verify key fields
	if decoded.RequestID != context.RequestID {
		t.Errorf("RequestID mismatch: got %s, want %s", decoded.RequestID, context.RequestID)
	}
	if decoded.Provider != context.Provider {
		t.Errorf("Provider mismatch: got %v, want %v", decoded.Provider, context.Provider)
	}
	if decoded.RiskLevel != context.RiskLevel {
		t.Errorf("RiskLevel mismatch: got %s, want %s", decoded.RiskLevel, context.RiskLevel)
	}
	if len(decoded.BlockedReasons) != len(context.BlockedReasons) {
		t.Errorf("BlockedReasons length mismatch: got %d, want %d", len(decoded.BlockedReasons), len(context.BlockedReasons))
	}
}

func TestLLMResponse(t *testing.T) {
	response := LLMResponse{
		ID:      "chatcmpl-123",
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   "gpt-4",
		Choices: []LLMChoice{
			{
				Index: 0,
				Message: &LLMMessage{
					Role:    "assistant",
					Content: "Hello! How can I help you today?",
				},
				FinishReason: stringPtr("stop"),
			},
		},
		Usage: &LLMUsage{
			PromptTokens:     10,
			CompletionTokens: 8,
			TotalTokens:      18,
		},
	}

	// Test JSON serialization
	jsonData, err := json.Marshal(response)
	if err != nil {
		t.Errorf("Failed to marshal LLMResponse: %v", err)
	}

	// Test JSON deserialization
	var decoded LLMResponse
	err = json.Unmarshal(jsonData, &decoded)
	if err != nil {
		t.Errorf("Failed to unmarshal LLMResponse: %v", err)
	}

	// Verify key fields
	if decoded.ID != response.ID {
		t.Errorf("ID mismatch: got %s, want %s", decoded.ID, response.ID)
	}
	if decoded.Model != response.Model {
		t.Errorf("Model mismatch: got %s, want %s", decoded.Model, response.Model)
	}
	if len(decoded.Choices) != len(response.Choices) {
		t.Errorf("Choices length mismatch: got %d, want %d", len(decoded.Choices), len(response.Choices))
	}
	if decoded.Usage.TotalTokens != response.Usage.TotalTokens {
		t.Errorf("TotalTokens mismatch: got %d, want %d", decoded.Usage.TotalTokens, response.Usage.TotalTokens)
	}
}

// Helper function for tests
func stringPtr(s string) *string {
	return &s
}