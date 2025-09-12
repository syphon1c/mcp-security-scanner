package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/syphon1c/mcp-security-scanner/internal/analyzer"
	"github.com/syphon1c/mcp-security-scanner/internal/integration"
	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

// Proxy handles MCP traffic interception and analysis
type Proxy struct {
	target          *url.URL
	policies        map[string]*types.SecurityPolicy
	alertChan       chan types.SecurityAlert
	logChan         chan types.ProxyLog
	upgrader        websocket.Upgrader
	alertProcessor  *integration.AlertProcessor
	trafficAnalyzer *analyzer.AdvancedTrafficAnalyzer
}

// NewProxy creates a new MCP security proxy with integrated alert processing
func NewProxy(targetURL string, policies map[string]*types.SecurityPolicy, alertProcessor *integration.AlertProcessor) (*Proxy, error) {
	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %v", err)
	}

	return &Proxy{
		target:          target,
		policies:        policies,
		alertChan:       make(chan types.SecurityAlert, 100),
		logChan:         make(chan types.ProxyLog, 1000),
		alertProcessor:  alertProcessor,
		trafficAnalyzer: analyzer.NewAdvancedTrafficAnalyzer(),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}, nil
}

// Start starts the proxy server
func (p *Proxy) Start(port int) error {
	router := mux.NewRouter()

	// Monitoring endpoints (must be before the catch-all)
	router.HandleFunc("/monitor/alerts", p.handleAlerts).Methods("GET")
	router.HandleFunc("/monitor/logs", p.handleLogs).Methods("GET")
	router.HandleFunc("/monitor/health", p.handleHealth).Methods("GET")

	// WebSocket proxy endpoint
	router.HandleFunc("/ws", p.handleWebSocketProxy)

	// HTTP/HTTPS proxy endpoints (catch-all, must be last)
	router.PathPrefix("/").HandlerFunc(p.handleHTTPProxy)

	log.Printf("Starting MCP proxy on port %d, forwarding to %s", port, p.target.String())

	// Start background monitoring goroutines
	go p.processAlerts()
	go p.processLogs()

	// Create HTTP server with proper timeouts to prevent resource exhaustion
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return server.ListenAndServe()
}

// handleHTTPProxy handles HTTP traffic proxying with security analysis
func (p *Proxy) handleHTTPProxy(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(p.target)

	// Modify the request
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = p.target.Host
		req.URL.Scheme = p.target.Scheme
		req.URL.Host = p.target.Host
	}

	// Intercept and analyze the request
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Analyze request for security issues
	var mcpMessage types.MCPMessage
	if json.Unmarshal(body, &mcpMessage) == nil {
		if p.analyzeRequest(&mcpMessage, r.RemoteAddr) {
			// Block the request if security analysis indicates it should be blocked
			http.Error(w, "Request blocked due to security policy violation", http.StatusForbidden)

			// Log the blocked request
			blockedLog := types.ProxyLog{
				Timestamp: time.Now(),
				Method:    mcpMessage.Method,
				Request:   mcpMessage,
				Duration:  time.Since(startTime),
				Risk:      "High",
			}
			select {
			case p.logChan <- blockedLog:
			default:
			}
			return
		}
	}

	// Modify response
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Read response body for analysis
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		resp.Body = io.NopCloser(bytes.NewReader(respBody))

		// Analyze response
		var respMessage types.MCPMessage
		if json.Unmarshal(respBody, &respMessage) == nil {
			p.analyzeResponse(&respMessage, r.RemoteAddr)
		}

		// Log the transaction
		proxyLog := types.ProxyLog{
			Timestamp: time.Now(),
			Method:    mcpMessage.Method,
			Request:   mcpMessage,
			Response:  respMessage,
			Duration:  time.Since(startTime),
			Risk:      p.assessRisk(&mcpMessage, &respMessage),
		}

		select {
		case p.logChan <- proxyLog:
		default:
			// Channel full, skip logging
		}

		return nil
	}

	proxy.ServeHTTP(w, r)
}

// handleWebSocketProxy manages WebSocket connections with real-time security monitoring.
// The function upgrades HTTP connections to WebSocket protocol, establishes bidirectional
// communication with the target server, and performs continuous security analysis of
// MCP messages flowing through the WebSocket tunnel.
//
// Parameters:
//   - w: HTTP response writer for the WebSocket upgrade
//   - r: HTTP request containing WebSocket upgrade headers and client information
//
// The function handles:
// - WebSocket protocol upgrade and connection establishment
// - Bidirectional message forwarding between client and target server
// - Real-time MCP message analysis and threat detection
// - Connection cleanup and error handling for both client and target connections
func (p *Proxy) handleWebSocketProxy(w http.ResponseWriter, r *http.Request) {
	// Upgrade the HTTP connection to WebSocket
	clientConn, err := p.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer clientConn.Close()

	// Connect to target WebSocket
	targetURL := fmt.Sprintf("ws://%s%s", p.target.Host, r.URL.Path)
	targetConn, _, err := websocket.DefaultDialer.Dial(targetURL, nil)
	if err != nil {
		log.Printf("Failed to connect to target WebSocket: %v", err)
		return
	}
	defer targetConn.Close()

	// Start bidirectional message forwarding
	go p.forwardWebSocketMessages(clientConn, targetConn, "client->target", r.RemoteAddr)
	p.forwardWebSocketMessages(targetConn, clientConn, "target->client", r.RemoteAddr)
}

// forwardWebSocketMessages provides bidirectional WebSocket message forwarding with security analysis.
// The function continuously reads messages from the source connection, performs MCP-specific threat
// analysis, and forwards validated messages to the destination connection. Security analysis includes
// pattern matching, injection detection, and policy enforcement.
//
// Parameters:
//   - from: Source WebSocket connection to read messages from
//   - to: Destination WebSocket connection to forward messages to
//   - direction: String identifier for message flow direction (e.g., "client->target")
//   - clientIP: Client IP address for security logging and alerting
//
// The function handles:
// - Continuous message reading and forwarding
// - MCP message parsing and security analysis
// - Threat detection based on message direction and content
// - Graceful connection termination on errors or policy violations
func (p *Proxy) forwardWebSocketMessages(from, to *websocket.Conn, direction, clientIP string) {
	for {
		messageType, message, err := from.ReadMessage()
		if err != nil {
			log.Printf("WebSocket read error (%s): %v", direction, err)
			break
		}

		// Analyze message for security issues
		var mcpMessage types.MCPMessage
		if json.Unmarshal(message, &mcpMessage) == nil {
			if direction == "client->target" {
				p.analyzeRequest(&mcpMessage, clientIP)
			} else {
				p.analyzeResponse(&mcpMessage, clientIP)
			}
		}

		// Forward the message
		err = to.WriteMessage(messageType, message)
		if err != nil {
			log.Printf("WebSocket write error (%s): %v", direction, err)
			break
		}
	}
}

// analyzeRequest analyzes incoming MCP requests for security threats
// analyzeRequest analyzes MCP requests for security threats
// Returns true if the request should be blocked
func (p *Proxy) analyzeRequest(message *types.MCPMessage, clientIP string) bool {
	shouldBlock := false

	// Generate session ID from client IP (in production, use proper session management)
	sessionID := fmt.Sprintf("session_%s_%d", clientIP, time.Now().Unix()/3600) // hourly sessions

	// Perform advanced traffic analysis
	analysisResult := p.trafficAnalyzer.AnalyzeTraffic(message, clientIP, sessionID)

	// Generate alerts based on advanced analysis
	if analysisResult.ThreatLevel == "Critical" || analysisResult.ThreatLevel == "High" {
		for _, anomaly := range analysisResult.BehavioralAnomalies {
			alert := types.SecurityAlert{
				Timestamp:   time.Now(),
				Severity:    anomaly.Severity,
				AlertType:   fmt.Sprintf("Behavioral Anomaly: %s", anomaly.Type),
				Description: anomaly.Description,
				Source:      clientIP,
				Evidence:    fmt.Sprintf("Confidence: %.2f", anomaly.Confidence),
				Action:      "Monitor",
			}
			select {
			case p.alertChan <- alert:
			default:
			}
		}

		for _, sequence := range analysisResult.SequenceMatches {
			alert := types.SecurityAlert{
				Timestamp:   time.Now(),
				Severity:    sequence.Severity,
				AlertType:   fmt.Sprintf("Attack Sequence: %s", sequence.SequenceName),
				Description: fmt.Sprintf("Detected sequence pattern with %.2f confidence", sequence.Confidence),
				Source:      clientIP,
				Evidence:    fmt.Sprintf("Steps: %v", sequence.Steps),
				Action:      "Monitor",
			}
			select {
			case p.alertChan <- alert:
			default:
			}
		}

		for _, finding := range analysisResult.ContentFindings {
			if finding.Risk == "High" {
				alert := types.SecurityAlert{
					Timestamp:   time.Now(),
					Severity:    "High",
					AlertType:   fmt.Sprintf("Content Analysis: %s", finding.Type),
					Description: fmt.Sprintf("Suspicious content detected in %s category", finding.Category),
					Source:      clientIP,
					Evidence:    finding.Content,
					Action:      "Monitor",
				}
				select {
				case p.alertChan <- alert:
				default:
				}
			}
		}
	}

	// Check for suspicious patterns in tool calls (existing logic)
	if message.Method == "tools/call" {
		if params, ok := message.Params.(map[string]interface{}); ok {
			if args, ok := params["arguments"].(map[string]interface{}); ok {
				for key, value := range args {
					if strVal, ok := value.(string); ok {
						if p.containsSuspiciousPattern(strVal) {
							alert := types.SecurityAlert{
								Timestamp:   time.Now(),
								Severity:    "High",
								AlertType:   "Suspicious Tool Call",
								Description: fmt.Sprintf("Potential injection attempt in tool parameter: %s", key),
								Source:      clientIP,
								Evidence:    strVal,
								Action:      "Monitor",
							}
							select {
							case p.alertChan <- alert:
							default:
							}
						}
					}
				}
			}
		}
	}

	// Check for blocked patterns
	if p.checkBlockedPatterns(message, clientIP) {
		shouldBlock = true
	}

	// Block if advanced analysis indicates critical threat
	if analysisResult.ThreatLevel == "Critical" {
		shouldBlock = true

		// Generate blocking alert
		alert := types.SecurityAlert{
			Timestamp:   time.Now(),
			Severity:    "Critical",
			AlertType:   "Advanced Analysis Block",
			Description: fmt.Sprintf("Request blocked by advanced traffic analysis (Risk Score: %d)", analysisResult.RiskScore),
			Source:      clientIP,
			Evidence:    fmt.Sprintf("Threat Level: %s, Confidence: %.2f", analysisResult.ThreatLevel, analysisResult.ConfidenceScore),
			Action:      "Block",
		}
		select {
		case p.alertChan <- alert:
		default:
		}
	}

	return shouldBlock
} // analyzeResponse analyzes MCP responses for information disclosure
func (p *Proxy) analyzeResponse(message *types.MCPMessage, clientIP string) {
	// Check for error messages that might disclose sensitive information
	if message.Error != nil {
		errorMsg := message.Error.Message
		if p.containsInformationDisclosure(errorMsg) {
			alert := types.SecurityAlert{
				Timestamp:   time.Now(),
				Severity:    "Medium",
				AlertType:   "Information Disclosure",
				Description: "Response contains potentially sensitive information",
				Source:      clientIP,
				Evidence:    errorMsg,
				Action:      "Monitor",
			}
			select {
			case p.alertChan <- alert:
			default:
			}
		}
	}

	// Check for successful responses to blocked methods
	if message.Result != nil && message.Method != "" {
		restrictedMethods := []string{"admin/", "system/", "debug/", "internal/"}
		for _, restricted := range restrictedMethods {
			if strings.HasPrefix(message.Method, restricted) {
				alert := types.SecurityAlert{
					Timestamp:   time.Now(),
					Severity:    "High",
					AlertType:   "Restricted Method Access",
					Description: fmt.Sprintf("Access to restricted method: %s", message.Method),
					Source:      clientIP,
					Evidence:    fmt.Sprintf("Method: %s", message.Method),
					Action:      "Monitor",
				}
				select {
				case p.alertChan <- alert:
				default:
				}
			}
		}
	}
}

// containsSuspiciousPattern checks if input contains suspicious patterns
func (p *Proxy) containsSuspiciousPattern(input string) bool {
	suspiciousPatterns := []string{
		`[;&|]\s*(cat|ls|dir|type|whoami|id|net|curl|wget)`,
		`\$\([^)]*\)`,
		"`[^`]*`",
		`<script[^>]*>`,
		`javascript:`,
		`data:text/html`,
		`\{\{.*\}\}`,
		`\$\{.*\}`,
		`\.\.\/`,
		`%2e%2e%2f`,
		`(rm|del)\s+(-rf|-r|-f)`,
		`(DROP|DELETE|INSERT|UPDATE)\s+(TABLE|FROM|INTO)`,
	}

	for _, pattern := range suspiciousPatterns {
		matched, _ := regexp.MatchString("(?i)"+pattern, input)
		if matched {
			return true
		}
	}

	return false
}

// containsInformationDisclosure checks for information disclosure in error messages
func (p *Proxy) containsInformationDisclosure(message string) bool {
	disclosurePatterns := []string{
		`/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+/`, // File paths
		`C:\\[^\\s]+`,                     // Windows paths
		`at line \d+`,                     // Stack traces
		`in file [^\\s]+`,                 // File references
		`database error`,                  // Database errors
		`internal error`,                  // Internal errors
		`Exception in thread`,             // Java exceptions
		`Traceback \(most recent call\)`,  // Python tracebacks
	}

	for _, pattern := range disclosurePatterns {
		matched, _ := regexp.MatchString("(?i)"+pattern, message)
		if matched {
			return true
		}
	}

	return false
}

// checkBlockedPatterns checks message against blocked patterns from policies
// Returns true if any blocked pattern is matched and the request should be blocked
func (p *Proxy) checkBlockedPatterns(message *types.MCPMessage, clientIP string) bool {
	// Convert message to string for pattern matching
	messageBytes, err := json.Marshal(message)
	if err != nil {
		return false
	}
	messageStr := string(messageBytes)

	// Check against all loaded policies
	for _, policy := range p.policies {
		for _, pattern := range policy.BlockedPatterns {
			var matched bool
			switch pattern.Type {
			case "regex":
				matched, _ = regexp.MatchString(pattern.Pattern, messageStr)
			case "exact":
				matched = strings.Contains(messageStr, pattern.Pattern)
			case "contains":
				matched = strings.Contains(strings.ToLower(messageStr), strings.ToLower(pattern.Pattern))
			}

			if matched {
				alert := types.SecurityAlert{
					Timestamp:   time.Now(),
					Severity:    "High",
					AlertType:   "Blocked Pattern Detected",
					Description: pattern.Description,
					Source:      clientIP,
					Evidence:    fmt.Sprintf("Pattern: %s, Category: %s", pattern.Pattern, pattern.Category),
					Action:      "Block",
				}
				select {
				case p.alertChan <- alert:
				default:
				}
				return true // Return immediately on first match to block the request
			}
		}
	}
	return false
}

// assessRisk assesses the risk level of a request/response pair
func (p *Proxy) assessRisk(request, response *types.MCPMessage) string {
	riskScore := 0

	// High risk methods
	highRiskMethods := []string{"tools/call", "resources/read", "resources/write"}
	for _, method := range highRiskMethods {
		if request.Method == method {
			riskScore += 3
			break
		}
	}

	// Check for suspicious parameters
	if request.Params != nil {
		paramsBytes, _ := json.Marshal(request.Params)
		if p.containsSuspiciousPattern(string(paramsBytes)) {
			riskScore += 5
		}
	}

	// Check for error responses (might indicate probing)
	if response != nil && response.Error != nil {
		riskScore += 1
	}

	// Determine risk level
	if riskScore >= 5 {
		return "High"
	} else if riskScore >= 3 {
		return "Medium"
	} else if riskScore > 0 {
		return "Low"
	}
	return "Minimal"
}

// processAlerts processes security alerts in the background with enterprise integrations
func (p *Proxy) processAlerts() {
	for alert := range p.alertChan {
		// Log the alert locally
		log.Printf("SECURITY ALERT [%s]: %s - %s (Source: %s)",
			alert.Severity, alert.AlertType, alert.Description, alert.Source)

		// Process alert through enterprise integrations (SIEM/SOAR/Slack)
		if p.alertProcessor != nil {
			go p.alertProcessor.ProcessAlert(alert)
		}

		// Log alert details for debugging
		alertBytes, _ := json.MarshalIndent(alert, "", "  ")
		log.Printf("Alert details: %s", string(alertBytes))
	}
}

// processLogs processes proxy logs in the background
func (p *Proxy) processLogs() {
	for proxyLog := range p.logChan {
		// Log high-risk transactions
		if proxyLog.Risk == "High" || proxyLog.Risk == "Medium" {
			log.Printf("PROXY LOG [%s]: %s took %v (Risk: %s)",
				proxyLog.Timestamp.Format("15:04:05"), proxyLog.Method, proxyLog.Duration, proxyLog.Risk)
		}

		// Here you would typically:
		// - Store in database
		// - Send to log aggregation system
		// - Update analytics
	}
}

// handleAlerts returns recent security alerts
func (p *Proxy) handleAlerts(w http.ResponseWriter, r *http.Request) {
	// This is a simplified implementation
	// In production, you'd query a database or cache

	response := map[string]interface{}{
		"status":  "ok",
		"message": "Alert endpoint active",
		"alerts":  []interface{}{}, // Would contain recent alerts
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil { // Fix errcheck
		log.Printf("Failed to encode alerts response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleLogs returns recent proxy logs
func (p *Proxy) handleLogs(w http.ResponseWriter, r *http.Request) {
	// This is a simplified implementation
	response := map[string]interface{}{
		"status":  "ok",
		"message": "Logs endpoint active",
		"logs":    []interface{}{}, // Would contain recent logs
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil { // Fix errcheck
		log.Printf("Failed to encode logs response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleHealth returns proxy health status
func (p *Proxy) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Determine overall health status
	status := "healthy"

	// Check if channels are near capacity (warning threshold)
	alertCapacity := float64(len(p.alertChan)) / 100.0 * 100 // Alert channel capacity is 100
	logCapacity := float64(len(p.logChan)) / 1000.0 * 100    // Log channel capacity is 1000

	if alertCapacity > 90 || logCapacity > 90 {
		status = "degraded"
	}

	// Check if channels are at capacity (critical threshold)
	if alertCapacity >= 100 || logCapacity >= 100 {
		status = "critical"
	}

	health := map[string]interface{}{
		"status":             status,
		"timestamp":          time.Now(),
		"proxy_version":      "1.0.0", // Could be from build info
		"target":             p.target.String(),
		"alerts_queue_size":  len(p.alertChan),
		"alerts_queue_usage": fmt.Sprintf("%.1f%%", alertCapacity),
		"logs_queue_size":    len(p.logChan),
		"logs_queue_usage":   fmt.Sprintf("%.1f%%", logCapacity),
		"traffic_analyzer":   p.trafficAnalyzer != nil,
		"alert_processor":    p.alertProcessor != nil,
		"policies_loaded":    len(p.policies),
	}

	// Set appropriate HTTP status code
	switch status {
	case "healthy":
		w.WriteHeader(http.StatusOK)
	case "degraded":
		w.WriteHeader(http.StatusOK) // 200 but with warning status
	case "critical":
		w.WriteHeader(http.StatusServiceUnavailable) // 503
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(health); err != nil { // Fix errcheck
		log.Printf("Failed to encode health response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
