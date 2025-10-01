package proxy

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/syphon1c/mcp-security-scanner/internal/analyzer"
	"github.com/syphon1c/mcp-security-scanner/internal/integration"
	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

// LLMProxy handles LLM API traffic interception and analysis
// Reuses the existing proxy infrastructure but with LLM-specific message handling
type LLMProxy struct {
	target          *url.URL
	policies        map[string]*types.SecurityPolicy
	policyDir       string
	alertChan       chan types.SecurityAlert
	logChan         chan types.LLMProxyLog
	alertProcessor  *integration.AlertProcessor
	trafficAnalyzer *analyzer.AdvancedTrafficAnalyzer

	// LLM-specific configuration
	maxTokens      int
	blockStreaming bool
	provider       types.LLMProvider
}

// NewLLMProxy creates a new LLM security proxy
func NewLLMProxy(targetURL string, policies map[string]*types.SecurityPolicy, policyDir string, alertProcessor *integration.AlertProcessor) (*LLMProxy, error) {
	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %v", err)
	}

	// Detect provider from target URL
	provider := types.DetectLLMProvider(targetURL, nil)

	proxy := &LLMProxy{
		target:          target,
		policies:        policies,
		policyDir:       policyDir,
		alertChan:       make(chan types.SecurityAlert, 100),
		logChan:         make(chan types.LLMProxyLog, 1000),
		alertProcessor:  alertProcessor,
		trafficAnalyzer: analyzer.NewAdvancedTrafficAnalyzer(),
		maxTokens:       8192, // Default token limit
		blockStreaming:  false,
		provider:        provider,
	}

	// Start background processors (reuse existing pattern)
	go proxy.processAlerts()
	go proxy.processLogs()

	return proxy, nil
}

// Start begins the LLM proxy server
func (p *LLMProxy) Start(port int) error {
	mux := http.NewServeMux()

	// LLM API endpoints - catch all paths that might be LLM APIs
	mux.HandleFunc("/", p.handleLLMProxy)

	// Monitoring endpoints (reuse existing pattern)
	mux.HandleFunc("/monitor/health", p.handleHealth)
	mux.HandleFunc("/monitor/alerts", p.handleAlerts)
	mux.HandleFunc("/monitor/logs", p.handleLogs)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("LLM Security Proxy starting on port %d", port)
	log.Printf("Proxying to: %s", p.target.String())
	log.Printf("Provider detected: %s", p.provider)

	return server.ListenAndServe()
}

// handleLLMProxy handles LLM API traffic with security analysis
func (p *LLMProxy) handleLLMProxy(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	requestID := p.generateRequestID()

	// Read request body for analysis
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Detect provider from headers if not already detected
	if p.provider == types.ProviderGeneric {
		headers := make(map[string]string)
		for k, v := range r.Header {
			if len(v) > 0 {
				headers[k] = v[0]
			}
		}
		p.provider = types.DetectLLMProvider(p.target.String(), headers)
	}

	// Parse and normalize LLM request
	llmRequest, err := types.NormalizeLLMRequest(body, p.provider)
	if err != nil {
		log.Printf("Failed to parse LLM request: %v", err)
		// Continue with proxy even if parsing fails
	}

	// Security analysis
	securityContext := p.analyzeLLMRequest(llmRequest, r, requestID)

	// Check if request should be blocked
	if securityContext.RiskLevel == "Critical" || len(securityContext.BlockedReasons) > 0 {
		p.blockRequest(w, securityContext, startTime)
		return
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(p.target)

	// Modify the request to target
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = p.target.Host
		req.URL.Scheme = p.target.Scheme
		req.URL.Host = p.target.Host

		// Preserve original path
		if !strings.HasPrefix(req.URL.Path, "/") {
			req.URL.Path = "/" + req.URL.Path
		}
	}

	// Capture response for analysis
	proxy.ModifyResponse = func(resp *http.Response) error {
		return p.analyzeResponse(resp, securityContext, requestID, startTime)
	}

	// Forward the request
	proxy.ServeHTTP(w, r)
}

// analyzeLLMRequest performs security analysis on LLM requests
func (p *LLMProxy) analyzeLLMRequest(request *types.LLMRequest, r *http.Request, requestID string) types.LLMSecurityContext {
	context := types.LLMSecurityContext{
		RequestID:   requestID,
		Provider:    p.provider,
		ClientIP:    r.RemoteAddr,
		Timestamp:   time.Now(),
		UserAgent:   r.UserAgent(),
		RequestSize: r.ContentLength,
	}

	if request == nil {
		context.RiskLevel = "Low"
		return context
	}

	context.Model = request.Model
	context.PromptTokenCount = request.CountTokensEstimate()

	// Analyze messages for security issues
	var allContent strings.Builder
	for _, msg := range request.Messages {
		content := msg.GetContentAsString()
		allContent.WriteString(content + " ")

		// Check for prompt injection patterns
		if p.containsPromptInjection(content) {
			context.PromptInjection = true
			context.BlockedReasons = append(context.BlockedReasons, "Prompt injection detected")
		}

		// Check for jailbreaking attempts
		if p.containsJailbreaking(content) {
			context.Jailbreaking = true
			context.BlockedReasons = append(context.BlockedReasons, "Jailbreaking attempt detected")
		}

		// Check for PII
		if p.containsPII(content) {
			context.ContainsPII = true
		}

		// Check for secrets
		if p.containsSecrets(content) {
			context.ContainsSecrets = true
			context.BlockedReasons = append(context.BlockedReasons, "Sensitive information detected")
		}
	}

	// Check token limits
	if request.MaxTokens != nil && *request.MaxTokens > p.maxTokens {
		context.ExcessiveTokens = true
		context.BlockedReasons = append(context.BlockedReasons, fmt.Sprintf("Token limit exceeded: %d > %d", *request.MaxTokens, p.maxTokens))
	}

	// Calculate risk score and level
	context.RiskScore = p.calculateLLMRiskScore(context)
	context.RiskLevel = p.determineLLMRiskLevel(context.RiskScore)

	// Generate security alert if needed
	if context.RiskScore >= 7 { // High risk threshold
		alert := types.SecurityAlert{
			Timestamp:   time.Now(),
			Severity:    context.RiskLevel,
			AlertType:   "LLM Security Violation",
			Description: fmt.Sprintf("High-risk LLM request detected from %s", context.ClientIP),
			Source:      context.ClientIP,
			Evidence:    fmt.Sprintf("Risk score: %d, Reasons: %v", context.RiskScore, context.BlockedReasons),
			Action:      "Monitor",
		}

		if len(context.BlockedReasons) > 0 {
			alert.Action = "Blocked"
		}

		select {
		case p.alertChan <- alert:
		default:
		}
	}

	return context
}

// analyzeResponse analyzes LLM API responses for security issues
func (p *LLMProxy) analyzeResponse(resp *http.Response, securityContext types.LLMSecurityContext, requestID string, startTime time.Time) error {
	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body = io.NopCloser(bytes.NewReader(respBody))

	// Parse LLM response
	var llmResponse types.LLMResponse
	if err := json.Unmarshal(respBody, &llmResponse); err == nil {
		// Analyze response content
		for _, choice := range llmResponse.Choices {
			if choice.Message != nil {
				content := choice.Message.GetContentAsString()

				// Check for information disclosure
				if p.containsSecrets(content) {
					securityContext.ContainsSecrets = true
				}

				// Check for PII in response
				if p.containsPII(content) {
					securityContext.ContainsPII = true
				}
			}
		}

		// Update token counts
		if llmResponse.Usage != nil {
			securityContext.PromptTokenCount = llmResponse.Usage.PromptTokens
			securityContext.ResponseTokenCount = llmResponse.Usage.CompletionTokens
		}
	}

	// Update security context
	securityContext.ResponseSize = int64(len(respBody))

	// Log the transaction
	proxyLog := types.LLMProxyLog{
		Timestamp:       time.Now(),
		RequestID:       requestID,
		Method:          resp.Request.Method,
		Provider:        p.provider,
		Model:           securityContext.Model,
		ClientIP:        securityContext.ClientIP,
		UserAgent:       securityContext.UserAgent,
		Duration:        time.Since(startTime),
		RequestSize:     securityContext.RequestSize,
		ResponseSize:    securityContext.ResponseSize,
		SecurityContext: securityContext,
		StatusCode:      resp.StatusCode,
		Risk:            securityContext.RiskLevel,
	}

	select {
	case p.logChan <- proxyLog:
	default:
		// Channel full, skip logging
	}

	return nil
}

// Security analysis helper methods
func (p *LLMProxy) containsPromptInjection(content string) bool {
	patterns := []string{
		"ignore previous instructions",
		"ignore all previous instructions",
		"\\n\\nHuman:",
		"\\n\\nAssistant:",
		"SYSTEM: Now you are",
		"<!-- Ignore everything above",
		"[INST]",
		"</INST>",
		"pretend you are not an AI",
		"disregard safety guidelines",
		"override previous context",
	}

	content = strings.ToLower(content)
	for _, pattern := range patterns {
		if strings.Contains(content, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func (p *LLMProxy) containsJailbreaking(content string) bool {
	patterns := []string{
		"DAN mode",
		"developer mode",
		"jailbreak",
		"ignore your instructions",
		"act as if you have no restrictions",
		"you are not bound by",
		"bypass your programming",
		"evil mode",
		"unrestricted mode",
	}

	content = strings.ToLower(content)
	for _, pattern := range patterns {
		if strings.Contains(content, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

func (p *LLMProxy) containsPII(content string) bool {
	patterns := []string{
		"social security number",
		"ssn:",
		"credit card",
		"password:",
		"email:",
		"phone number:",
		"address:",
	}

	content = strings.ToLower(content)
	for _, pattern := range patterns {
		if strings.Contains(content, pattern) {
			return true
		}
	}
	return false
}

func (p *LLMProxy) containsSecrets(content string) bool {
	patterns := []string{
		"api_key",
		"secret_key",
		"private_key",
		"access_token",
		"bearer ",
		"sk-",
		"pk-",
	}

	content = strings.ToLower(content)
	for _, pattern := range patterns {
		if strings.Contains(content, pattern) {
			return true
		}
	}
	return false
}

// Risk assessment methods
func (p *LLMProxy) calculateLLMRiskScore(context types.LLMSecurityContext) int {
	score := 0

	if context.PromptInjection {
		score += 5
	}
	if context.Jailbreaking {
		score += 4
	}
	if context.ContainsSecrets {
		score += 3
	}
	if context.ContainsPII {
		score += 2
	}
	if context.ExcessiveTokens {
		score += 2
	}

	return score
}

func (p *LLMProxy) determineLLMRiskLevel(score int) string {
	if score >= 8 {
		return "Critical"
	} else if score >= 5 {
		return "High"
	} else if score >= 3 {
		return "Medium"
	} else if score > 0 {
		return "Low"
	}
	return "Minimal"
}

// Utility methods
func (p *LLMProxy) generateRequestID() string {
	return fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%d", time.Now().UnixNano()))))[:8]
}

func (p *LLMProxy) blockRequest(w http.ResponseWriter, context types.LLMSecurityContext, startTime time.Time) {
	errorResponse := map[string]interface{}{
		"error": map[string]interface{}{
			"type":    "security_violation",
			"code":    "blocked_by_policy",
			"message": fmt.Sprintf("Request blocked due to security policy violation: %s", strings.Join(context.BlockedReasons, ", ")),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(errorResponse)

	// Log blocked request
	blockedLog := types.LLMProxyLog{
		Timestamp:       time.Now(),
		RequestID:       context.RequestID,
		Provider:        context.Provider,
		Model:           context.Model,
		ClientIP:        context.ClientIP,
		UserAgent:       context.UserAgent,
		Duration:        time.Since(startTime),
		SecurityContext: context,
		StatusCode:      403,
		Blocked:         true,
		Risk:            context.RiskLevel,
	}

	select {
	case p.logChan <- blockedLog:
	default:
	}
}

// Background processors (reuse existing patterns)
func (p *LLMProxy) processAlerts() {
	for alert := range p.alertChan {
		if p.alertProcessor != nil {
			p.alertProcessor.ProcessAlert(alert)
		}
	}
}

func (p *LLMProxy) processLogs() {
	// Process logs - could write to file, send to SIEM, etc.
	for log := range p.logChan {
		// For now, just log to stdout
		_ = log // Placeholder
	}
}

// Monitoring endpoints (reuse existing implementations)
func (p *LLMProxy) handleHealth(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":       "healthy",
		"timestamp":    time.Now().Format(time.RFC3339),
		"proxy_type":   "llm",
		"target":       p.target.String(),
		"provider":     string(p.provider),
		"alerts_queue": len(p.alertChan),
		"logs_queue":   len(p.logChan),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (p *LLMProxy) handleAlerts(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":  "ok",
		"message": "LLM alerts endpoint active",
		"alerts":  []interface{}{}, // Would contain recent alerts
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (p *LLMProxy) handleLogs(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":  "ok",
		"message": "LLM logs endpoint active",
		"logs":    []interface{}{}, // Would contain recent logs
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
