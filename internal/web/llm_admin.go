package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

// LLMAdminServer provides LLM-specific web administration interface
type LLMAdminServer struct {
	policies     map[string]*types.SecurityPolicy
	policyDir    string
	alertHistory []types.SecurityAlert
	llmLogs      []types.LLMProxyLog
	templates    *template.Template
	maxAlerts    int
	maxLogs      int
	provider     string
	tokenUsage   *LLMTokenUsage
	requestStats *LLMRequestStats
}

// LLMTokenUsage tracks token consumption across models
type LLMTokenUsage struct {
	TotalTokens     int64            `json:"total_tokens"`
	TokensByModel   map[string]int64 `json:"tokens_by_model"`
	TokensByHour    map[string]int64 `json:"tokens_by_hour"`
	CostEstimateUSD float64          `json:"cost_estimate_usd"`
	LastUpdated     time.Time        `json:"last_updated"`
	TopModels       []ModelUsage     `json:"top_models"`
	TodayUsage      int64            `json:"today_usage"`
	WeeklyUsage     int64            `json:"weekly_usage"`
}

// ModelUsage represents usage statistics for a specific model
type ModelUsage struct {
	Model     string    `json:"model"`
	Tokens    int64     `json:"tokens"`
	Requests  int64     `json:"requests"`
	LastUsed  time.Time `json:"last_used"`
	AvgTokens float64   `json:"avg_tokens"`
	CostUSD   float64   `json:"cost_usd"`
}

// LLMRequestStats tracks request patterns and performance
type LLMRequestStats struct {
	TotalRequests      int64                    `json:"total_requests"`
	BlockedRequests    int64                    `json:"blocked_requests"`
	AverageLatency     float64                  `json:"average_latency_ms"`
	RequestsByProvider map[string]int64         `json:"requests_by_provider"`
	ThreatsByCategory  map[string]int64         `json:"threats_by_category"`
	HourlyStats        map[string]RequestHourly `json:"hourly_stats"`
	TopThreats         []ThreatSummary          `json:"top_threats"`
	SuccessRate        float64                  `json:"success_rate"`
}

// RequestHourly represents request statistics for a specific hour
type RequestHourly struct {
	Hour      string  `json:"hour"`
	Requests  int64   `json:"requests"`
	Blocked   int64   `json:"blocked"`
	AvgTokens float64 `json:"avg_tokens"`
	Latency   float64 `json:"latency_ms"`
}

// ThreatSummary represents a summary of detected threats
type ThreatSummary struct {
	Category    string    `json:"category"`
	Count       int64     `json:"count"`
	LastSeen    time.Time `json:"last_seen"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
}

// LLMDashboardData aggregates all data for the LLM dashboard
type LLMDashboardData struct {
	Title          string                `json:"title"`
	Provider       string                `json:"provider"`
	TokenUsage     *LLMTokenUsage        `json:"token_usage"`
	RequestStats   *LLMRequestStats      `json:"request_stats"`
	RecentAlerts   []types.SecurityAlert `json:"recent_alerts"`
	ActivePolicies int                   `json:"active_policies"`
	LLMPolicies    int                   `json:"llm_policies"`
	Timestamp      string                `json:"timestamp"`
	HealthStatus   string                `json:"health_status"`
}

// NewLLMAdminServer creates a new LLM-specific web administration server
func NewLLMAdminServer(policies map[string]*types.SecurityPolicy, policyDir string, provider string) *LLMAdminServer {
	admin := &LLMAdminServer{
		policies:     policies,
		policyDir:    policyDir,
		alertHistory: make([]types.SecurityAlert, 0),
		llmLogs:      make([]types.LLMProxyLog, 0),
		maxAlerts:    1000,
		maxLogs:      5000,
		provider:     provider,
		tokenUsage: &LLMTokenUsage{
			TokensByModel: make(map[string]int64),
			TokensByHour:  make(map[string]int64),
			TopModels:     make([]ModelUsage, 0),
		},
		requestStats: &LLMRequestStats{
			RequestsByProvider: make(map[string]int64),
			ThreatsByCategory:  make(map[string]int64),
			HourlyStats:        make(map[string]RequestHourly),
			TopThreats:         make([]ThreatSummary, 0),
		},
	}

	// Initialize with current provider
	admin.requestStats.RequestsByProvider[provider] = 0

	// Load templates
	admin.loadTemplates()

	return admin
}

// loadTemplates loads HTML templates for the LLM web interface
func (a *LLMAdminServer) loadTemplates() {
	templateDir := filepath.Join("web", "templates", "llm")
	if _, err := os.Stat(templateDir); os.IsNotExist(err) {
		log.Printf("LLM template directory not found: %s", templateDir)
		return
	}

	// Define custom template functions
	funcMap := template.FuncMap{
		"mul": func(a, b interface{}) float64 {
			var fa, fb float64
			switch v := a.(type) {
			case int:
				fa = float64(v)
			case int64:
				fa = float64(v)
			case float64:
				fa = v
			case float32:
				fa = float64(v)
			default:
				fa = 0
			}
			switch v := b.(type) {
			case int:
				fb = float64(v)
			case int64:
				fb = float64(v)
			case float64:
				fb = v
			case float32:
				fb = float64(v)
			default:
				fb = 0
			}
			return fa * fb
		},
		"div": func(a, b interface{}) float64 {
			var fa, fb float64
			switch v := a.(type) {
			case int:
				fa = float64(v)
			case int64:
				fa = float64(v)
			case float64:
				fa = v
			case float32:
				fa = float64(v)
			default:
				fa = 0
			}
			switch v := b.(type) {
			case int:
				fb = float64(v)
			case int64:
				fb = float64(v)
			case float64:
				fb = v
			case float32:
				fb = float64(v)
			default:
				fb = 1 // Avoid division by zero
			}
			if fb == 0 {
				return 0
			}
			return fa / fb
		},
		"printf": fmt.Sprintf,
	}

	var err error
	a.templates = template.New("").Funcs(funcMap)
	a.templates, err = a.templates.ParseGlob(filepath.Join(templateDir, "*.html"))
	if err != nil {
		log.Printf("Failed to load LLM templates: %v", err)
	}
}

// AddRoutes adds LLM admin routes to the provided router
func (a *LLMAdminServer) AddRoutes(router *mux.Router) {
	log.Printf("Adding LLM admin routes to router...")

	// LLM-specific web interface routes
	router.HandleFunc("/admin", a.handleLLMDashboard).Methods("GET")
	router.HandleFunc("/admin/llm", a.handleLLMDashboard).Methods("GET")
	router.HandleFunc("/admin/llm/tokens", a.handleTokenUsagePage).Methods("GET")
	router.HandleFunc("/admin/llm/threats", a.handleThreatsPage).Methods("GET")
	router.HandleFunc("/admin/llm/models", a.handleModelsPage).Methods("GET")
	router.HandleFunc("/admin/llm/policies", a.handleLLMPoliciesPage).Methods("GET")
	router.HandleFunc("/admin/alerts", a.handleLLMAlertsPage).Methods("GET")

	// LLM-specific API routes
	router.HandleFunc("/api/llm/dashboard", a.handleGetLLMDashboard).Methods("GET")
	router.HandleFunc("/api/llm/tokens", a.handleGetTokenUsage).Methods("GET")
	router.HandleFunc("/api/llm/stats", a.handleGetRequestStats).Methods("GET")
	router.HandleFunc("/api/llm/threats", a.handleGetThreats).Methods("GET")
	router.HandleFunc("/api/llm/models", a.handleGetModels).Methods("GET")
	router.HandleFunc("/api/llm/logs", a.handleGetLLMLogs).Methods("GET")
	router.HandleFunc("/api/alerts", a.handleGetAlerts).Methods("GET")

	// LLM policy management
	router.HandleFunc("/api/llm/policies", a.handleGetLLMPolicies).Methods("GET")
	router.HandleFunc("/api/llm/policies/reload", a.handleReloadLLMPolicies).Methods("POST")
	router.HandleFunc("/api/llm/violations", a.handleGetLLMViolations).Methods("GET")

	// Static files for LLM interface
	staticDir := filepath.Join("web", "static", "llm")
	if _, err := os.Stat(staticDir); err == nil {
		router.PathPrefix("/static/llm/").Handler(http.StripPrefix("/static/llm/", http.FileServer(http.Dir(staticDir))))
	}
}

// RecordLLMActivity records LLM-specific activity for monitoring
func (a *LLMAdminServer) RecordLLMActivity(log types.LLMProxyLog) {
	a.llmLogs = append(a.llmLogs, log)

	// Keep only the most recent logs
	if len(a.llmLogs) > a.maxLogs {
		a.llmLogs = a.llmLogs[len(a.llmLogs)-a.maxLogs:]
	}

	// Update statistics
	a.updateTokenUsage(log)
	a.updateRequestStats(log)
}

// RecordAlert records a security alert for LLM traffic
func (a *LLMAdminServer) RecordAlert(alert types.SecurityAlert) {
	a.alertHistory = append(a.alertHistory, alert)

	// Keep only the most recent alerts
	if len(a.alertHistory) > a.maxAlerts {
		a.alertHistory = a.alertHistory[len(a.alertHistory)-a.maxAlerts:]
	}

	// Update threat statistics
	a.updateThreatStats(alert)
}

// updateTokenUsage updates token usage statistics
func (a *LLMAdminServer) updateTokenUsage(log types.LLMProxyLog) {
	totalTokens := log.SecurityContext.PromptTokenCount + log.SecurityContext.ResponseTokenCount
	if totalTokens == 0 {
		return
	}

	a.tokenUsage.TotalTokens += int64(totalTokens)

	// Update by model
	if log.Model != "" {
		a.tokenUsage.TokensByModel[log.Model] += int64(totalTokens)
	}

	// Update by hour
	hour := log.Timestamp.Format("2006-01-02 15:00")
	a.tokenUsage.TokensByHour[hour] += int64(totalTokens)

	// Calculate today's usage
	today := time.Now().Format("2006-01-02")
	todayUsage := int64(0)
	for hour, tokens := range a.tokenUsage.TokensByHour {
		if strings.HasPrefix(hour, today) {
			todayUsage += tokens
		}
	}
	a.tokenUsage.TodayUsage = todayUsage

	// Update cost estimate (rough estimation)
	a.tokenUsage.CostEstimateUSD = float64(a.tokenUsage.TotalTokens) * 0.00002 // $0.02 per 1K tokens average
	a.tokenUsage.LastUpdated = time.Now()

	// Update top models
	a.updateTopModels()
}

// updateRequestStats updates request statistics
func (a *LLMAdminServer) updateRequestStats(log types.LLMProxyLog) {
	a.requestStats.TotalRequests++

	if log.Blocked {
		a.requestStats.BlockedRequests++
	}

	// Update provider stats (convert LLMProvider to string)
	a.requestStats.RequestsByProvider[string(log.Provider)]++

	// Calculate total tokens for this request
	totalTokens := log.SecurityContext.PromptTokenCount + log.SecurityContext.ResponseTokenCount
	latencyMs := float64(log.Duration.Milliseconds())

	// Update hourly stats
	hour := log.Timestamp.Format("2006-01-02 15:00")
	if hourly, exists := a.requestStats.HourlyStats[hour]; exists {
		hourly.Requests++
		if log.Blocked {
			hourly.Blocked++
		}
		hourly.AvgTokens = (hourly.AvgTokens*float64(hourly.Requests-1) + float64(totalTokens)) / float64(hourly.Requests)
		hourly.Latency = (hourly.Latency*float64(hourly.Requests-1) + latencyMs) / float64(hourly.Requests)
		a.requestStats.HourlyStats[hour] = hourly
	} else {
		a.requestStats.HourlyStats[hour] = RequestHourly{
			Hour:      hour,
			Requests:  1,
			Blocked:   0,
			AvgTokens: float64(totalTokens),
			Latency:   latencyMs,
		}
		if log.Blocked {
			a.requestStats.HourlyStats[hour] = RequestHourly{
				Hour:      hour,
				Requests:  1,
				Blocked:   1,
				AvgTokens: float64(totalTokens),
				Latency:   latencyMs,
			}
		}
	}

	// Calculate success rate
	if a.requestStats.TotalRequests > 0 {
		a.requestStats.SuccessRate = float64(a.requestStats.TotalRequests-a.requestStats.BlockedRequests) / float64(a.requestStats.TotalRequests) * 100
	}
}

// updateThreatStats updates threat detection statistics
func (a *LLMAdminServer) updateThreatStats(alert types.SecurityAlert) {
	// Extract category from alert type or evidence
	category := "Unknown"
	alertType := strings.ToLower(alert.AlertType)

	if strings.Contains(alertType, "prompt") || strings.Contains(alertType, "injection") {
		category = "Prompt Injection"
	} else if strings.Contains(alertType, "jailbreak") {
		category = "Jailbreaking"
	} else if strings.Contains(alertType, "pii") || strings.Contains(alertType, "personal") {
		category = "PII Exposure"
	} else if strings.Contains(alertType, "secret") || strings.Contains(alertType, "key") {
		category = "Secret Leakage"
	} else if strings.Contains(alertType, "content") {
		category = "Content Policy"
	} else if strings.Contains(alertType, "token") {
		category = "Token Abuse"
	}

	a.requestStats.ThreatsByCategory[category]++

	// Update top threats
	a.updateTopThreats(category, alert)
}

// updateTopModels updates the top models list
func (a *LLMAdminServer) updateTopModels() {
	models := make([]ModelUsage, 0)

	for model, tokens := range a.tokenUsage.TokensByModel {
		// Find request count for this model
		requests := int64(0)
		for _, log := range a.llmLogs {
			if log.Model == model {
				requests++
			}
		}

		avgTokens := float64(0)
		if requests > 0 {
			avgTokens = float64(tokens) / float64(requests)
		}

		costUSD := float64(tokens) * 0.00002 // Rough estimate

		models = append(models, ModelUsage{
			Model:     model,
			Tokens:    tokens,
			Requests:  requests,
			LastUsed:  time.Now(), // Would need to track actual last used time
			AvgTokens: avgTokens,
			CostUSD:   costUSD,
		})
	}

	// Sort by token usage
	sort.Slice(models, func(i, j int) bool {
		return models[i].Tokens > models[j].Tokens
	})

	// Keep top 10
	if len(models) > 10 {
		models = models[:10]
	}

	a.tokenUsage.TopModels = models
}

// updateTopThreats updates the top threats list
func (a *LLMAdminServer) updateTopThreats(category string, alert types.SecurityAlert) {
	// Find existing threat or create new one
	found := false
	for i, threat := range a.requestStats.TopThreats {
		if threat.Category == category {
			a.requestStats.TopThreats[i].Count++
			a.requestStats.TopThreats[i].LastSeen = alert.Timestamp
			found = true
			break
		}
	}

	if !found {
		a.requestStats.TopThreats = append(a.requestStats.TopThreats, ThreatSummary{
			Category:    category,
			Count:       1,
			LastSeen:    alert.Timestamp,
			Severity:    alert.Severity,
			Description: fmt.Sprintf("%s detected in LLM traffic", category),
		})
	}

	// Sort by count and keep top 10
	sort.Slice(a.requestStats.TopThreats, func(i, j int) bool {
		return a.requestStats.TopThreats[i].Count > a.requestStats.TopThreats[j].Count
	})

	if len(a.requestStats.TopThreats) > 10 {
		a.requestStats.TopThreats = a.requestStats.TopThreats[:10]
	}
}

// Dashboard handlers
func (a *LLMAdminServer) handleLLMDashboard(w http.ResponseWriter, r *http.Request) {
	if a.templates == nil {
		a.renderFallbackLLMDashboard(w)
		return
	}

	// Try to use the LLM dashboard template
	data := a.buildDashboardData()

	if err := a.templates.ExecuteTemplate(w, "llm_dashboard.html", data); err != nil {
		log.Printf("LLM template execution error: %v", err)
		a.renderFallbackLLMDashboard(w)
	}
}

// buildDashboardData creates the complete dashboard data structure
func (a *LLMAdminServer) buildDashboardData() LLMDashboardData {
	// Count LLM-specific policies
	llmPolicies := 0
	for _, policy := range a.policies {
		if policy.GetPolicyType() == types.PolicyTypeLLM {
			llmPolicies++
		}
	}

	// Get recent alerts (last 10)
	recentAlerts := make([]types.SecurityAlert, 0)
	if len(a.alertHistory) > 0 {
		start := len(a.alertHistory) - 10
		if start < 0 {
			start = 0
		}
		recentAlerts = a.alertHistory[start:]

		// Reverse to show newest first
		for i, j := 0, len(recentAlerts)-1; i < j; i, j = i+1, j-1 {
			recentAlerts[i], recentAlerts[j] = recentAlerts[j], recentAlerts[i]
		}
	}

	return LLMDashboardData{
		Title:          "LLM Security Dashboard",
		Provider:       cases.Title(language.English).String(a.provider),
		TokenUsage:     a.tokenUsage,
		RequestStats:   a.requestStats,
		RecentAlerts:   recentAlerts,
		ActivePolicies: len(a.policies),
		LLMPolicies:    llmPolicies,
		Timestamp:      time.Now().Format("2006-01-02 15:04:05"),
		HealthStatus:   "healthy", // Would be determined by actual health checks
	}
}

// renderFallbackLLMDashboard renders a basic LLM dashboard when templates aren't available
func (a *LLMAdminServer) renderFallbackLLMDashboard(w http.ResponseWriter) {
	data := a.buildDashboardData()

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>LLM Security Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .nav { background: #34495e; padding: 10px; margin-bottom: 20px; border-radius: 5px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #ecf0f1; padding: 8px 12px; border-radius: 3px; }
        .nav a:hover { background: #2c3e50; }
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .metric { display: flex; justify-content: space-between; align-items: center; margin: 10px 0; }
        .metric-value { font-size: 1.5em; font-weight: bold; color: #2c3e50; }
        .alert { padding: 10px; margin: 5px 0; border-radius: 4px; border-left: 4px solid; }
        .alert-Critical { border-color: #e74c3c; background: #fdf2f2; }
        .alert-High { border-color: #f39c12; background: #fef9e7; }
        .alert-Medium { border-color: #f1c40f; background: #fffdf7; }
        .alert-Low { border-color: #27ae60; background: #f0fff4; }
        .threat-list { max-height: 300px; overflow-y: auto; }
        .model-list { max-height: 250px; overflow-y: auto; }
        .progress-bar { background: #ecf0f1; height: 20px; border-radius: 10px; overflow: hidden; margin: 5px 0; }
        .progress-fill { height: 100%%; background: #3498db; transition: width 0.3s ease; }
        .status-healthy { color: #27ae60; }
        .status-warning { color: #f39c12; }
        .status-critical { color: #e74c3c; }
    </style>
    <script>
        function refreshDashboard() {
            location.reload();
        }
        
        setInterval(refreshDashboard, 30000); // Auto-refresh every 30 seconds
    </script>
</head>
<body>
    <div class="header">
        <h1>🤖 LLM Security Dashboard</h1>
        <p>Provider: <strong>%s</strong> | Last Updated: %s</p>
    </div>
    
    <div class="nav">
        <a href="/admin/llm">Dashboard</a>
        <a href="/admin/llm/tokens">Token Usage</a>
        <a href="/admin/llm/threats">Threat Analysis</a>
        <a href="/admin/llm/models">Model Statistics</a>
        <a href="/admin/llm/policies">LLM Policies</a>
        <a href="/admin/alerts">Security Alerts</a>
    </div>
    
    <div class="cards">
        <div class="card">
            <h3>📊 Request Statistics</h3>
            <div class="metric">
                <span>Total Requests:</span>
                <span class="metric-value">%d</span>
            </div>
            <div class="metric">
                <span>Blocked Requests:</span>
                <span class="metric-value">%d</span>
            </div>
            <div class="metric">
                <span>Success Rate:</span>
                <span class="metric-value">%.1f%%</span>
            </div>
            <div class="metric">
                <span>Health Status:</span>
                <span class="metric-value status-%s">%s</span>
            </div>
        </div>
        
        <div class="card">
            <h3>🪙 Token Usage</h3>
            <div class="metric">
                <span>Total Tokens:</span>
                <span class="metric-value">%s</span>
            </div>
            <div class="metric">
                <span>Today's Usage:</span>
                <span class="metric-value">%s</span>
            </div>
            <div class="metric">
                <span>Estimated Cost:</span>
                <span class="metric-value">$%.2f</span>
            </div>
        </div>
        
        <div class="card">
            <h3>🔒 Security Overview</h3>
            <div class="metric">
                <span>Active Policies:</span>
                <span class="metric-value">%d</span>
            </div>
            <div class="metric">
                <span>LLM Policies:</span>
                <span class="metric-value">%d</span>
            </div>
            <div class="metric">
                <span>Recent Alerts:</span>
                <span class="metric-value">%d</span>
            </div>
        </div>
        
        <div class="card">
            <h3>🚨 Top Threats</h3>
            <div class="threat-list">`,
		data.Provider, data.Timestamp,
		data.RequestStats.TotalRequests, data.RequestStats.BlockedRequests, data.RequestStats.SuccessRate,
		data.HealthStatus, cases.Title(language.English).String(data.HealthStatus),
		formatNumber(data.TokenUsage.TotalTokens), formatNumber(data.TokenUsage.TodayUsage), data.TokenUsage.CostEstimateUSD,
		data.ActivePolicies, data.LLMPolicies, len(data.RecentAlerts))

	// Add top threats
	if len(data.RequestStats.TopThreats) == 0 {
		html += `<p>No threats detected</p>`
	} else {
		for _, threat := range data.RequestStats.TopThreats {
			html += fmt.Sprintf(`
                <div class="metric">
                    <span>%s:</span>
                    <span class="metric-value">%d</span>
                </div>`, threat.Category, threat.Count)
		}
	}

	html += `
            </div>
        </div>
        
        <div class="card">
            <h3>🤖 Top Models</h3>
            <div class="model-list">`

	// Add top models
	if len(data.TokenUsage.TopModels) == 0 {
		html += `<p>No model usage data</p>`
	} else {
		for _, model := range data.TokenUsage.TopModels {
			percentage := float64(model.Tokens) / float64(data.TokenUsage.TotalTokens) * 100
			html += fmt.Sprintf(`
                <div style="margin: 10px 0;">
                    <div class="metric">
                        <span>%s:</span>
                        <span>%s tokens (%.1f%%)</span>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: %.1f%%;"></div>
                    </div>
                </div>`, model.Model, formatNumber(model.Tokens), percentage, percentage)
		}
	}

	html += `
            </div>
        </div>
        
        <div class="card">
            <h3>⚠️ Recent Alerts</h3>`

	// Add recent alerts
	if len(data.RecentAlerts) == 0 {
		html += `<p>No recent alerts</p>`
	} else {
		for _, alert := range data.RecentAlerts {
			html += fmt.Sprintf(`
                <div class="alert alert-%s">
                    <strong>%s</strong><br>
                    %s<br>
                    <small>%s</small>
                </div>`, alert.Severity, alert.AlertType, alert.Description, alert.Timestamp.Format("15:04:05"))
		}
	}

	html += `
        </div>
    </div>
    
    <script>
        // Auto-refresh dashboard every 30 seconds
        setTimeout(function() {
            location.reload();
        }, 30000);
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, html)
}

// Additional handler methods will be implemented in the next part...

// API handlers
func (a *LLMAdminServer) handleGetLLMDashboard(w http.ResponseWriter, r *http.Request) {
	data := a.buildDashboardData()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (a *LLMAdminServer) handleGetTokenUsage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(a.tokenUsage); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (a *LLMAdminServer) handleGetRequestStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(a.requestStats); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (a *LLMAdminServer) handleGetThreats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(a.requestStats.TopThreats); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (a *LLMAdminServer) handleGetModels(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(a.tokenUsage.TopModels); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (a *LLMAdminServer) handleGetLLMLogs(w http.ResponseWriter, r *http.Request) {
	// Limit to recent logs for performance
	logs := a.llmLogs
	if len(logs) > 100 {
		logs = logs[len(logs)-100:]
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(logs); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (a *LLMAdminServer) handleGetLLMPolicies(w http.ResponseWriter, r *http.Request) {
	llmPolicies := make(map[string]*types.SecurityPolicy)
	for name, policy := range a.policies {
		if policy.GetPolicyType() == types.PolicyTypeLLM {
			llmPolicies[name] = policy
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(llmPolicies); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (a *LLMAdminServer) handleReloadLLMPolicies(w http.ResponseWriter, r *http.Request) {
	// This would trigger a policy reload in the main application
	// For now, just return success
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "LLM policies reload requested",
	}); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// Page handlers (these would use templates if available)
func (a *LLMAdminServer) handleTokenUsagePage(w http.ResponseWriter, r *http.Request) {
	if a.templates == nil {
		http.Error(w, "Templates not loaded", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if err := a.templates.ExecuteTemplate(w, "token_usage.html", nil); err != nil {
		log.Printf("Error executing token usage template: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func (a *LLMAdminServer) handleThreatsPage(w http.ResponseWriter, r *http.Request) {
	if a.templates == nil {
		http.Error(w, "Templates not loaded", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if err := a.templates.ExecuteTemplate(w, "threat_analysis.html", nil); err != nil {
		log.Printf("Error executing threat analysis template: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func (a *LLMAdminServer) handleModelsPage(w http.ResponseWriter, r *http.Request) {
	if a.templates == nil {
		http.Error(w, "Templates not loaded", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if err := a.templates.ExecuteTemplate(w, "model_statistics.html", nil); err != nil {
		log.Printf("Error executing model statistics template: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func (a *LLMAdminServer) handleLLMPoliciesPage(w http.ResponseWriter, r *http.Request) {
	if a.templates == nil {
		http.Error(w, "Templates not loaded", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if err := a.templates.ExecuteTemplate(w, "llm_policies.html", nil); err != nil {
		log.Printf("Error executing LLM policies template: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

func (a *LLMAdminServer) handleLLMAlertsPage(w http.ResponseWriter, r *http.Request) {
	if a.templates == nil {
		http.Error(w, "Templates not loaded", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	if err := a.templates.ExecuteTemplate(w, "security_alerts.html", nil); err != nil {
		log.Printf("Error executing security alerts template: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
	}
}

// Helper methods
// handleGetAlerts returns security alerts for the API
func (a *LLMAdminServer) handleGetAlerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(a.alertHistory); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// handleGetLLMViolations returns policy violations for the API
func (a *LLMAdminServer) handleGetLLMViolations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// For now, return violations based on blocked requests from alert history
	violations := make([]map[string]interface{}, 0)

	for _, alert := range a.alertHistory {
		if alert.Action == "Blocked" {
			violation := map[string]interface{}{
				"timestamp":      alert.Timestamp,
				"policy_name":    "llm-security",
				"rule_id":        "AUTO_GENERATED",
				"description":    alert.Description,
				"severity":       alert.Severity,
				"source":         alert.Source,
				"violation_type": alert.AlertType,
				"evidence":       alert.Evidence,
			}
			violations = append(violations, violation)
		}
	}

	if err := json.NewEncoder(w).Encode(violations); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// formatNumber formats large numbers with commas
func formatNumber(n int64) string {
	str := strconv.FormatInt(n, 10)
	if len(str) <= 3 {
		return str
	}

	var result strings.Builder
	for i, r := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result.WriteString(",")
		}
		result.WriteRune(r)
	}
	return result.String()
}
