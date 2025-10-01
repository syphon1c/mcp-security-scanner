package proxy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/syphon1c/mcp-security-scanner/internal/analyzer"
	"github.com/syphon1c/mcp-security-scanner/internal/integration"
	"github.com/syphon1c/mcp-security-scanner/internal/web"
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
	adminServer     *web.LLMAdminServer

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
		adminServer:     web.NewLLMAdminServer(policies, policyDir, string(provider)),
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
	router := mux.NewRouter()

	// Add LLM admin routes FIRST (before catch-all routes)
	p.adminServer.AddRoutes(router)

	// Monitoring endpoints (reuse existing pattern)
	router.HandleFunc("/monitor/health", p.handleHealth).Methods("GET")
	router.HandleFunc("/monitor/alerts", p.handleAlerts).Methods("GET")
	router.HandleFunc("/monitor/logs", p.handleLogs).Methods("GET")

	// LLM API endpoints - catch all paths that might be LLM APIs
	router.HandleFunc("/v1/{path:.*}", p.handleLLMProxy).Methods("GET", "POST", "PUT", "DELETE")
	router.HandleFunc("/chat/{path:.*}", p.handleLLMProxy).Methods("GET", "POST", "PUT", "DELETE")
	router.HandleFunc("/completions/{path:.*}", p.handleLLMProxy).Methods("GET", "POST", "PUT", "DELETE")
	router.HandleFunc("/models/{path:.*}", p.handleLLMProxy).Methods("GET", "POST", "PUT", "DELETE")

	// Catch-all for other potential LLM endpoints (this must be LAST)
	router.PathPrefix("/").HandlerFunc(p.handleLLMProxy)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("LLM Security Proxy starting on port %d", port)
	log.Printf("Proxying to: %s", p.target.String())
	log.Printf("Provider detected: %s", p.provider)
	log.Printf("LLM Admin Dashboard available at: http://localhost:%d/admin", port)

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

		// Check for security violations using policy patterns
		violations := p.analyzeContentWithPolicies(content)

		if violations.PromptInjection {
			context.PromptInjection = true
			context.BlockedReasons = append(context.BlockedReasons, "Prompt injection detected")
		}

		if violations.Jailbreaking {
			context.Jailbreaking = true
			context.BlockedReasons = append(context.BlockedReasons, "Jailbreaking attempt detected")
		}

		if violations.ContainsPII {
			context.ContainsPII = true
		}

		if violations.ContainsSecrets {
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
	if len(context.BlockedReasons) > 0 || context.RiskScore >= 7 { // Alert for blocked requests or high risk
		// Create specific alert types based on detection reasons
		alertTypes := []string{}

		if context.PromptInjection {
			alertTypes = append(alertTypes, "Prompt Injection")
		}
		if context.Jailbreaking {
			alertTypes = append(alertTypes, "Jailbreaking Attempt")
		}
		if context.ContainsPII {
			alertTypes = append(alertTypes, "PII Exposure Risk")
		}
		if context.ContainsSecrets {
			alertTypes = append(alertTypes, "Secret Leakage Risk")
		}

		// Default to generic if no specific type detected
		if len(alertTypes) == 0 {
			alertTypes = append(alertTypes, "LLM Security Violation")
		}

		for _, alertType := range alertTypes {
			alert := types.SecurityAlert{
				Timestamp:   time.Now(),
				Severity:    context.RiskLevel,
				AlertType:   alertType,
				Description: fmt.Sprintf("%s detected from %s", alertType, context.ClientIP),
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
		// Analyze response content using policies
		for _, choice := range llmResponse.Choices {
			if choice.Message != nil {
				content := choice.Message.GetContentAsString()
				violations := p.analyzeContentWithPolicies(content)

				// Check for information disclosure
				if violations.ContainsSecrets {
					securityContext.ContainsSecrets = true
				}

				// Check for PII in response
				if violations.ContainsPII {
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

// analyzeContentWithPolicies analyzes content using policy-defined patterns
func (p *LLMProxy) analyzeContentWithPolicies(content string) types.LLMViolations {
	violations := types.LLMViolations{}
	content = strings.ToLower(content)

	// Iterate through all loaded policies
	for _, policy := range p.policies {
		if policy.PolicyType != "llm" {
			continue // Skip non-LLM policies
		}

		// Check each rule in the policy
		for _, rule := range policy.Rules {
			category := strings.ToLower(rule.Category)

			// Check if content matches any patterns in this rule
			for _, pattern := range rule.Patterns {
				if strings.Contains(content, strings.ToLower(pattern)) {
					switch {
					case strings.Contains(rule.ID, "PROMPT_INJECTION") || category == "ai_security" && strings.Contains(strings.ToLower(rule.Description), "prompt"):
						violations.PromptInjection = true
					case strings.Contains(rule.ID, "JAILBREAKING") || strings.Contains(strings.ToLower(rule.Description), "jailbreak"):
						violations.Jailbreaking = true
					case strings.Contains(rule.ID, "PII") || category == "data_privacy":
						violations.ContainsPII = true
					case strings.Contains(rule.ID, "SECRET") || category == "information_disclosure":
						violations.ContainsSecrets = true
					}
					break // Found a match, no need to check other patterns in this rule
				}
			}
		}
	}

	return violations
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
	bytes := make([]byte, 4)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID if random fails
		return fmt.Sprintf("%x", time.Now().UnixNano())[:8]
	}
	return hex.EncodeToString(bytes)
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
	if err := json.NewEncoder(w).Encode(errorResponse); err != nil {
		log.Printf("Failed to encode error response: %v", err)
	}

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

		// Record in admin server for dashboard
		p.adminServer.RecordAlert(alert)

		log.Printf("LLM Security Alert: %s - %s", alert.AlertType, alert.Description)
	}
}

func (p *LLMProxy) processLogs() {
	// Process logs - feed to admin dashboard and external systems
	for logEntry := range p.logChan {
		// Record in admin server for monitoring
		p.adminServer.RecordLLMActivity(logEntry)

		// Log to stdout for debugging (can be configured)
		log.Printf("LLM Request: %s %s [%s] - Tokens: %d+%d, Risk: %s",
			logEntry.Method, logEntry.Model, logEntry.Provider,
			logEntry.SecurityContext.PromptTokenCount,
			logEntry.SecurityContext.ResponseTokenCount,
			logEntry.Risk)
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
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode health response: %v", err)
	}
}

func (p *LLMProxy) handleAlerts(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":  "ok",
		"message": "LLM alerts endpoint active",
		"alerts":  []interface{}{}, // Would contain recent alerts
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode alerts response: %v", err)
	}
}

func (p *LLMProxy) handleLogs(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":  "ok",
		"message": "LLM logs endpoint active",
		"logs":    []interface{}{}, // Would contain recent logs
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode logs response: %v", err)
	}
}
