package types

import (
	"encoding/json"
	"time"
)

// LLMProvider represents different LLM API providers
type LLMProvider string

const (
	ProviderOpenAI  LLMProvider = "openai"
	ProviderClaude  LLMProvider = "claude"
	ProviderGoogle  LLMProvider = "google"
	ProviderCohere  LLMProvider = "cohere"
	ProviderGeneric LLMProvider = "generic"
)

// LLMRequest represents a unified LLM API request structure
// Compatible with OpenAI, Claude, and other major providers
type LLMRequest struct {
	// Common fields across providers
	Model       string       `json:"model"`
	Messages    []LLMMessage `json:"messages"`
	MaxTokens   *int         `json:"max_tokens,omitempty"`
	Temperature *float32     `json:"temperature,omitempty"`
	Stream      *bool        `json:"stream,omitempty"`

	// OpenAI specific fields
	TopP             *float32           `json:"top_p,omitempty"`
	FrequencyPenalty *float32           `json:"frequency_penalty,omitempty"`
	PresencePenalty  *float32           `json:"presence_penalty,omitempty"`
	Stop             []string           `json:"stop,omitempty"`
	Tools            []LLMTool          `json:"tools,omitempty"`
	ToolChoice       interface{}        `json:"tool_choice,omitempty"`
	ResponseFormat   *LLMResponseFormat `json:"response_format,omitempty"`

	// Claude specific fields
	System string `json:"system,omitempty"`

	// Provider metadata (not sent to API)
	Provider  LLMProvider `json:"-"`
	Timestamp time.Time   `json:"-"`
	ClientIP  string      `json:"-"`
}

// LLMMessage represents a chat message
type LLMMessage struct {
	Role       string        `json:"role"`    // "user", "assistant", "system", "tool"
	Content    interface{}   `json:"content"` // string or []LLMContent for multimodal
	Name       string        `json:"name,omitempty"`
	ToolCalls  []LLMToolCall `json:"tool_calls,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"`
}

// LLMContent represents multimodal content (text, images, etc.)
type LLMContent struct {
	Type     string       `json:"type"` // "text", "image_url"
	Text     string       `json:"text,omitempty"`
	ImageURL *LLMImageURL `json:"image_url,omitempty"`
}

// LLMImageURL represents image content
type LLMImageURL struct {
	URL    string `json:"url"`
	Detail string `json:"detail,omitempty"` // "low", "high", "auto"
}

// LLMTool represents a function/tool definition
type LLMTool struct {
	Type     string          `json:"type"` // "function"
	Function LLMToolFunction `json:"function"`
}

// LLMToolFunction represents a function definition
type LLMToolFunction struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

// LLMToolCall represents a tool call made by the assistant
type LLMToolCall struct {
	ID       string          `json:"id"`
	Type     string          `json:"type"` // "function"
	Function LLMFunctionCall `json:"function"`
}

// LLMFunctionCall represents a function call
type LLMFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// LLMResponseFormat represents the response format specification
type LLMResponseFormat struct {
	Type   string                 `json:"type"` // "text", "json_object"
	Schema map[string]interface{} `json:"schema,omitempty"`
}

// LLMResponse represents a unified LLM API response
type LLMResponse struct {
	ID      string      `json:"id"`
	Object  string      `json:"object"`
	Created int64       `json:"created"`
	Model   string      `json:"model"`
	Choices []LLMChoice `json:"choices"`
	Usage   *LLMUsage   `json:"usage,omitempty"`

	// Error handling
	Error *LLMError `json:"error,omitempty"`

	// Provider metadata (not from API)
	Provider       LLMProvider   `json:"-"`
	ProcessingTime time.Duration `json:"-"`
	Timestamp      time.Time     `json:"-"`
}

// LLMChoice represents a response choice
type LLMChoice struct {
	Index        int          `json:"index"`
	Message      *LLMMessage  `json:"message,omitempty"`
	Delta        *LLMMessage  `json:"delta,omitempty"` // For streaming
	FinishReason *string      `json:"finish_reason"`
	Logprobs     *LLMLogprobs `json:"logprobs,omitempty"`
}

// LLMLogprobs represents log probabilities
type LLMLogprobs struct {
	Content []LLMTokenLogprob `json:"content,omitempty"`
}

// LLMTokenLogprob represents token log probabilities
type LLMTokenLogprob struct {
	Token   string  `json:"token"`
	Logprob float64 `json:"logprob"`
	Bytes   []int   `json:"bytes,omitempty"`
}

// LLMUsage represents token usage statistics
type LLMUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// LLMError represents API error responses
type LLMError struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Param   string `json:"param,omitempty"`
}

// LLMStreamResponse represents streaming response chunks
type LLMStreamResponse struct {
	ID      string      `json:"id"`
	Object  string      `json:"object"`
	Created int64       `json:"created"`
	Model   string      `json:"model"`
	Choices []LLMChoice `json:"choices"`
}

// LLMSecurityContext holds security analysis context for LLM requests/responses
type LLMSecurityContext struct {
	RequestID string      `json:"request_id"`
	Provider  LLMProvider `json:"provider"`
	Model     string      `json:"model"`
	ClientIP  string      `json:"client_ip"`
	Timestamp time.Time   `json:"timestamp"`

	// Content analysis
	PromptTokenCount   int  `json:"prompt_token_count"`
	ResponseTokenCount int  `json:"response_token_count"`
	ContainsPII        bool `json:"contains_pii"`
	ContainsSecrets    bool `json:"contains_secrets"`

	// Security flags
	PromptInjection  bool `json:"prompt_injection"`
	Jailbreaking     bool `json:"jailbreaking"`
	ContentViolation bool `json:"content_violation"`
	ExcessiveTokens  bool `json:"excessive_tokens"`

	// Risk assessment
	RiskScore      int      `json:"risk_score"`
	RiskLevel      string   `json:"risk_level"`
	BlockedReasons []string `json:"blocked_reasons,omitempty"`

	// Metadata
	UserAgent    string `json:"user_agent,omitempty"`
	RequestSize  int64  `json:"request_size"`
	ResponseSize int64  `json:"response_size"`
}

// LLMProxyLog represents a log entry for LLM proxy traffic
type LLMProxyLog struct {
	Timestamp time.Time   `json:"timestamp"`
	RequestID string      `json:"request_id"`
	Method    string      `json:"method"`
	Provider  LLMProvider `json:"provider"`
	Model     string      `json:"model"`
	ClientIP  string      `json:"client_ip"`
	UserAgent string      `json:"user_agent"`

	// Request/Response data
	Request  *LLMRequest  `json:"request,omitempty"`
	Response *LLMResponse `json:"response,omitempty"`

	// Performance metrics
	Duration     time.Duration `json:"duration"`
	RequestSize  int64         `json:"request_size"`
	ResponseSize int64         `json:"response_size"`

	// Security analysis
	SecurityContext LLMSecurityContext `json:"security_context"`

	// Status
	StatusCode int    `json:"status_code"`
	Error      string `json:"error,omitempty"`
	Blocked    bool   `json:"blocked"`
	Risk       string `json:"risk"`
}

// DetectLLMProvider attempts to identify the LLM provider from the request
func DetectLLMProvider(endpoint string, headers map[string]string) LLMProvider {
	// Check endpoint patterns
	if contains(endpoint, "openai.com") || contains(endpoint, "api.openai") {
		return ProviderOpenAI
	}
	if contains(endpoint, "anthropic.com") || contains(endpoint, "claude") {
		return ProviderClaude
	}
	if contains(endpoint, "googleapis.com") || contains(endpoint, "gemini") {
		return ProviderGoogle
	}
	if contains(endpoint, "cohere.ai") || contains(endpoint, "cohere.com") {
		return ProviderCohere
	}

	// Check headers
	if auth := headers["Authorization"]; auth != "" {
		if contains(auth, "Bearer sk-") {
			return ProviderOpenAI
		}
		if contains(auth, "Bearer x-api-key") || contains(auth, "x-api-key") {
			return ProviderClaude
		}
	}

	return ProviderGeneric
}

// NormalizeLLMRequest converts provider-specific requests to unified format
func NormalizeLLMRequest(rawRequest []byte, provider LLMProvider) (*LLMRequest, error) {
	var request LLMRequest

	switch provider {
	case ProviderOpenAI:
		// OpenAI format is our base format
		if err := json.Unmarshal(rawRequest, &request); err != nil {
			return nil, err
		}

	case ProviderClaude:
		// Convert Claude format to unified format
		var claudeReq struct {
			Model       string       `json:"model"`
			MaxTokens   int          `json:"max_tokens"`
			Messages    []LLMMessage `json:"messages"`
			System      string       `json:"system,omitempty"`
			Temperature *float32     `json:"temperature,omitempty"`
			Stream      *bool        `json:"stream,omitempty"`
		}

		if err := json.Unmarshal(rawRequest, &claudeReq); err != nil {
			return nil, err
		}

		request.Model = claudeReq.Model
		request.MaxTokens = &claudeReq.MaxTokens
		request.Messages = claudeReq.Messages
		request.System = claudeReq.System
		request.Temperature = claudeReq.Temperature
		request.Stream = claudeReq.Stream

	default:
		// Generic parsing
		if err := json.Unmarshal(rawRequest, &request); err != nil {
			return nil, err
		}
	}

	request.Provider = provider
	request.Timestamp = time.Now()

	return &request, nil
}

// GetContentAsString extracts text content from LLM messages
func (msg *LLMMessage) GetContentAsString() string {
	switch content := msg.Content.(type) {
	case string:
		return content
	case []LLMContent:
		var text string
		for _, c := range content {
			if c.Type == "text" {
				text += c.Text + " "
			}
		}
		return text
	default:
		// Try to convert to string
		if str, ok := content.(string); ok {
			return str
		}
		return ""
	}
}

// CountTokensEstimate provides a rough token count estimate
// This is a simple approximation - real implementations should use proper tokenizers
func (req *LLMRequest) CountTokensEstimate() int {
	var totalText string

	for _, msg := range req.Messages {
		totalText += msg.GetContentAsString() + " "
	}

	if req.System != "" {
		totalText += req.System + " "
	}

	// Rough approximation: 1 token ≈ 4 characters for English text
	return len(totalText) / 4
}

// Helper function for string containment check
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
