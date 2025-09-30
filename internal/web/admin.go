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
	"time"

	"github.com/gorilla/mux"
	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

// AdminServer provides web administration interface for MCP proxy
type AdminServer struct {
	policies     map[string]*types.SecurityPolicy
	policyDir    string
	alertHistory []types.SecurityAlert
	templates    *template.Template
	maxAlerts    int
}

// PolicySummary provides a summary view of policies for the UI
type PolicySummary struct {
	Name             string `json:"name"`
	Version          string `json:"version"`
	Description      string `json:"description"`
	Severity         string `json:"severity"`
	RulesCount       int    `json:"rulesCount"`
	BlockedCount     int    `json:"blockedCount"`
	PolymorphicCount int    `json:"polymorphicCount"`
}

// RuleResponse represents a rule for API responses
type RuleResponse struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Patterns    []string `json:"patterns"`
	PolicyName  string   `json:"policyName"`
}

// BlockedPatternResponse represents a blocked pattern for API responses
type BlockedPatternResponse struct {
	Pattern     string `json:"pattern"`
	Type        string `json:"type"`
	Category    string `json:"category"`
	Description string `json:"description"`
	PolicyName  string `json:"policyName"`
}

// NewAdminServer creates a new web administration server
func NewAdminServer(policies map[string]*types.SecurityPolicy, policyDir string) *AdminServer {
	admin := &AdminServer{
		policies:     policies,
		policyDir:    policyDir,
		alertHistory: make([]types.SecurityAlert, 0),
		maxAlerts:    1000, // Keep last 1000 alerts
	}

	// Load templates
	admin.loadTemplates()

	return admin
}

// loadTemplates loads HTML templates for the web interface
func (a *AdminServer) loadTemplates() {
	templateDir := filepath.Join("web", "templates")
	if _, err := os.Stat(templateDir); os.IsNotExist(err) {
		log.Printf("Template directory not found: %s", templateDir)
		return
	}

	var err error
	a.templates, err = template.ParseGlob(filepath.Join(templateDir, "*.html"))
	if err != nil {
		log.Printf("Failed to load templates: %v", err)
	}
}

// AddRoutes adds admin routes to the provided router
func (a *AdminServer) AddRoutes(router *mux.Router) {
	log.Printf("Adding admin routes to router...")
	// Web interface routes
	router.HandleFunc("/admin", a.handleDashboard).Methods("GET")
	router.HandleFunc("/admin/policies", a.handlePoliciesPage).Methods("GET")
	router.HandleFunc("/admin/alerts", a.handleAlertsPage).Methods("GET")
	router.HandleFunc("/admin/health", a.handleHealthPage).Methods("GET")

	// API routes for dynamic content
	router.HandleFunc("/api/policies", a.handleGetPolicies).Methods("GET")
	router.HandleFunc("/api/policies/{name}/rules", a.handleGetRules).Methods("GET")
	router.HandleFunc("/api/policies/{name}/rules", a.handleAddRule).Methods("POST")
	router.HandleFunc("/api/policies/{name}/rules/{id}", a.handleUpdateRule).Methods("PUT")
	router.HandleFunc("/api/policies/{name}/rules/{id}", a.handleDeleteRule).Methods("DELETE")

	router.HandleFunc("/api/policies/{name}/blocked", a.handleGetBlockedPatterns).Methods("GET")
	router.HandleFunc("/api/policies/{name}/blocked", a.handleAddBlockedPattern).Methods("POST")
	router.HandleFunc("/api/policies/{name}/blocked/{index}", a.handleDeleteBlockedPattern).Methods("DELETE")

	router.HandleFunc("/api/alerts", a.handleGetAlerts).Methods("GET")
	router.HandleFunc("/api/alerts/clear", a.handleClearAlerts).Methods("POST")

	// Static files
	staticDir := filepath.Join("web", "static")
	if _, err := os.Stat(staticDir); err == nil {
		router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir))))
	}
}

// RecordAlert records a security alert for display in the admin interface
func (a *AdminServer) RecordAlert(alert types.SecurityAlert) {
	a.alertHistory = append(a.alertHistory, alert)

	// Keep only the most recent alerts to prevent memory issues
	if len(a.alertHistory) > a.maxAlerts {
		a.alertHistory = a.alertHistory[len(a.alertHistory)-a.maxAlerts:]
	}
}

// Dashboard handlers
func (a *AdminServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if a.templates == nil {
		a.renderFallbackDashboard(w)
		return
	}

	data := struct {
		Title       string
		PolicyCount int
		AlertCount  int
		Timestamp   string
	}{
		Title:       "MCP Security Admin",
		PolicyCount: len(a.policies),
		AlertCount:  len(a.alertHistory),
		Timestamp:   time.Now().Format("2006-01-02 15:04:05"),
	}

	if err := a.templates.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		log.Printf("Template execution error: %v", err)
		a.renderFallbackDashboard(w)
	}
}

func (a *AdminServer) renderFallbackDashboard(w http.ResponseWriter) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>MCP Security Admin</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .card { border: 1px solid #ddd; padding: 20px; margin: 20px 0; border-radius: 5px; }
        .nav { background: #f4f4f4; padding: 10px; margin-bottom: 20px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #007cba; }
        .stats { display: flex; gap: 20px; }
        .stat { background: #e7f3ff; padding: 15px; border-radius: 5px; text-align: center; min-width: 120px; }
    </style>
</head>
<body>
    <div class="nav">
        <a href="/admin">Dashboard</a>
        <a href="/admin/policies">Policies</a>
        <a href="/admin/alerts">Alerts</a>
        <a href="/monitor/health">Proxy Health</a>
    </div>
    <h1>MCP Security Scanner Administration</h1>
    <div class="stats">
        <div class="stat">
            <h3>%d</h3>
            <p>Active Policies</p>
        </div>
        <div class="stat">
            <h3>%d</h3>
            <p>Recent Alerts</p>
        </div>
    </div>
    <div class="card">
        <h2>Quick Actions</h2>
        <p><a href="/admin/policies">Manage Security Policies</a></p>
        <p><a href="/admin/alerts">View Security Alerts</a></p>
        <p><a href="/monitor/health">Check Proxy Health</a></p>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, html, len(a.policies), len(a.alertHistory))
}

func (a *AdminServer) handlePoliciesPage(w http.ResponseWriter, r *http.Request) {
	// Read the policies.html file directly since it uses JavaScript to load data
	tmplPath := filepath.Join("web", "templates", "policies.html")
	content, err := os.ReadFile(tmplPath)
	if err != nil {
		log.Printf("Failed to read policies template: %v", err)
		a.renderFallbackPolicies(w)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(content)
}

func (a *AdminServer) renderFallbackPolicies(w http.ResponseWriter) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Security Policies - MCP Admin</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .nav { background: #f4f4f4; padding: 10px; margin-bottom: 20px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #007cba; }
        .policy { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .severity-Critical { border-left: 5px solid #dc3545; }
        .severity-High { border-left: 5px solid #fd7e14; }
        .severity-Medium { border-left: 5px solid #ffc107; }
        .severity-Low { border-left: 5px solid #28a745; }
        .btn { padding: 8px 15px; margin: 5px; text-decoration: none; border-radius: 3px; display: inline-block; }
        .btn-primary { background: #007cba; color: white; }
        .btn-secondary { background: #6c757d; color: white; }
    </style>
    <script>
        async function loadPolicyDetails(policyName) {
            const response = await fetch('/api/policies/' + policyName + '/rules');
            const rules = await response.json();
            
            const blockedResponse = await fetch('/api/policies/' + policyName + '/blocked');
            const blocked = await response.json();
            
            alert('Policy: ' + policyName + '\\nRules: ' + rules.length + '\\nBlocked Patterns: ' + blocked.length);
        }
    </script>
</head>
<body>
    <div class="nav">
        <a href="/admin">Dashboard</a>
        <a href="/admin/policies">Policies</a>
        <a href="/admin/alerts">Alerts</a>
        <a href="/monitor/health">Proxy Health</a>
    </div>
    <h1>Security Policies</h1>`

	for name, policy := range a.policies {
		html += fmt.Sprintf(`
    <div class="policy severity-%s">
        <h3>%s (v%s)</h3>
        <p>%s</p>
        <p><strong>Severity:</strong> %s | <strong>Rules:</strong> %d | <strong>Blocked Patterns:</strong> %d</p>
        <a href="#" onclick="loadPolicyDetails('%s')" class="btn btn-primary">View Details</a>
        <a href="/api/policies/%s/rules" class="btn btn-secondary">Rules API</a>
    </div>`,
			policy.Severity, name, policy.Version, policy.Description,
			policy.Severity, len(policy.Rules), len(policy.BlockedPatterns),
			name, name)
	}

	html += `</body></html>`

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, html)
}

func (a *AdminServer) handleAlertsPage(w http.ResponseWriter, r *http.Request) {
	if a.templates == nil {
		a.renderFallbackAlerts(w)
		return
	}

	// Use the alerts.html template
	tmplPath := filepath.Join("web", "templates", "alerts.html")
	content, err := os.ReadFile(tmplPath)
	if err != nil {
		log.Printf("Failed to read alerts template: %v", err)
		a.renderFallbackAlerts(w)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(content)
}

func (a *AdminServer) renderFallbackAlerts(w http.ResponseWriter) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Security Alerts - MCP Admin</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .nav { background: #f4f4f4; padding: 10px; margin-bottom: 20px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #007cba; }
        .alert { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .severity-Critical { border-left: 5px solid #dc3545; background: #f8d7da; }
        .severity-High { border-left: 5px solid #fd7e14; background: #ffe4d6; }
        .severity-Medium { border-left: 5px solid #ffc107; background: #fff3cd; }
        .severity-Low { border-left: 5px solid #28a745; background: #d4edda; }
        .btn { padding: 8px 15px; margin: 5px; text-decoration: none; border-radius: 3px; display: inline-block; cursor: pointer; }
        .btn-danger { background: #dc3545; color: white; border: none; }
        .timestamp { color: #666; font-size: 0.9em; }
    </style>
    <script>
        async function clearAlerts() {
            if (confirm('Clear all alerts?')) {
                await fetch('/api/alerts/clear', { method: 'POST' });
                location.reload();
            }
        }
        
        async function refreshAlerts() {
            location.reload();
        }
        
        setInterval(refreshAlerts, 30000); // Auto-refresh every 30 seconds
    </script>
</head>
<body>
    <div class="nav">
        <a href="/admin">Dashboard</a>
        <a href="/admin/policies">Policies</a>
        <a href="/admin/alerts">Alerts</a>
        <a href="/monitor/health">Proxy Health</a>
    </div>
    <h1>Security Alerts</h1>
    <button onclick="clearAlerts()" class="btn btn-danger">Clear All Alerts</button>
    <button onclick="refreshAlerts()" class="btn">Refresh</button>`

	// Sort alerts by timestamp (newest first)
	alerts := make([]types.SecurityAlert, len(a.alertHistory))
	copy(alerts, a.alertHistory)
	sort.Slice(alerts, func(i, j int) bool {
		return alerts[i].Timestamp.After(alerts[j].Timestamp)
	})

	if len(alerts) == 0 {
		html += `<p>No alerts recorded.</p>`
	} else {
		for _, alert := range alerts {
			html += fmt.Sprintf(`
    <div class="alert severity-%s">
        <h4>%s</h4>
        <p>%s</p>
        <p><strong>Source:</strong> %s | <strong>Action:</strong> %s</p>
        <p><strong>Evidence:</strong> <code>%s</code></p>
        <p class="timestamp">%s</p>
    </div>`,
				alert.Severity, alert.AlertType, alert.Description,
				alert.Source, alert.Action, alert.Evidence,
				alert.Timestamp.Format("2006-01-02 15:04:05"))
		}
	}

	html += `</body></html>`

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, html)
}

func (a *AdminServer) handleHealthPage(w http.ResponseWriter, r *http.Request) {
	// Read the health.html template file
	tmplPath := filepath.Join("web", "templates", "health.html")
	content, err := os.ReadFile(tmplPath)
	if err != nil {
		log.Printf("Failed to read health template: %v", err)
		a.renderFallbackHealth(w)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(content)
}

func (a *AdminServer) renderFallbackHealth(w http.ResponseWriter) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Proxy Health - MCP Admin</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .nav { background: #f4f4f4; padding: 10px; margin-bottom: 20px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #007cba; }
        .health-card { border: 1px solid #ddd; padding: 20px; margin: 10px 0; border-radius: 5px; }
        .status-healthy { background: #d4edda; border-color: #28a745; }
        .status-degraded { background: #fff3cd; border-color: #ffc107; }
        .status-critical { background: #f8d7da; border-color: #dc3545; }
        .metric { display: inline-block; margin: 10px 15px 10px 0; }
        .btn { padding: 8px 15px; margin: 5px; text-decoration: none; border-radius: 3px; display: inline-block; cursor: pointer; color: white; }
        .btn-primary { background: #007cba; }
    </style>
    <script>
        async function refreshHealth() {
            location.reload();
        }
        
        setInterval(refreshHealth, 10000); // Auto-refresh every 10 seconds
    </script>
</head>
<body>
    <div class="nav">
        <a href="/admin">Dashboard</a>
        <a href="/admin/policies">Policies</a>
        <a href="/admin/alerts">Alerts</a>
        <a href="/admin/health">Proxy Health</a>
    </div>
    <h1>Proxy Health Monitor</h1>
    <button onclick="refreshHealth()" class="btn btn-primary">Refresh</button>
    <div id="healthData">
        <p>Loading health data...</p>
        <p><em>Health data will be fetched from /monitor/health API endpoint.</em></p>
    </div>
    
    <script>
        async function loadHealthData() {
            try {
                const response = await fetch('/monitor/health');
                const health = await response.json();
                displayHealth(health);
            } catch (error) {
                document.getElementById('healthData').innerHTML = '<p style="color: red;">Failed to load health data: ' + error.message + '</p>';
            }
        }
        
        function displayHealth(health) {
            const statusClass = 'status-' + health.status;
            const html = '<div class="health-card ' + statusClass + '">' +
                '<h3>Overall Status: ' + health.status.toUpperCase() + '</h3>' +
                '<div class="metric"><strong>Target:</strong> ' + health.target + '</div>' +
                '<div class="metric"><strong>Version:</strong> ' + health.proxy_version + '</div>' +
                '<div class="metric"><strong>Policies:</strong> ' + health.policies_loaded + '</div>' +
                '<br>' +
                '<div class="metric"><strong>Alert Queue:</strong> ' + health.alerts_queue_size + ' (' + health.alerts_queue_usage + ')</div>' +
                '<div class="metric"><strong>Log Queue:</strong> ' + health.logs_queue_size + ' (' + health.logs_queue_usage + ')</div>' +
                '<br>' +
                '<div class="metric"><strong>Traffic Analyzer:</strong> ' + (health.traffic_analyzer ? 'Active' : 'Inactive') + '</div>' +
                '<div class="metric"><strong>Alert Processor:</strong> ' + (health.alert_processor ? 'Active' : 'Inactive') + '</div>' +
                '<div class="metric"><strong>Last Updated:</strong> ' + new Date(health.timestamp).toLocaleString() + '</div>' +
                '</div>';
            document.getElementById('healthData').innerHTML = html;
        }
        
        // Load health data on page load
        document.addEventListener('DOMContentLoaded', loadHealthData);
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, html)
}

// API handlers
func (a *AdminServer) handleGetPolicies(w http.ResponseWriter, r *http.Request) {
	var summaries []PolicySummary

	for name, policy := range a.policies {
		summary := PolicySummary{
			Name:             name,
			Version:          policy.Version,
			Description:      policy.Description,
			Severity:         policy.Severity,
			RulesCount:       len(policy.Rules),
			BlockedCount:     len(policy.BlockedPatterns),
			PolymorphicCount: len(policy.PolymorphicPatterns),
		}
		summaries = append(summaries, summary)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summaries)
}

func (a *AdminServer) handleGetRules(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyName := vars["name"]

	policy, exists := a.policies[policyName]
	if !exists {
		http.Error(w, "Policy not found", http.StatusNotFound)
		return
	}

	var rules []RuleResponse
	for _, rule := range policy.Rules {
		ruleResp := RuleResponse{
			ID:          rule.ID,
			Name:        rule.Name,
			Description: rule.Description,
			Category:    rule.Category,
			Severity:    rule.Severity,
			Patterns:    rule.Patterns,
			PolicyName:  policyName,
		}
		rules = append(rules, ruleResp)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

func (a *AdminServer) handleAddRule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyName := vars["name"]

	policy, exists := a.policies[policyName]
	if !exists {
		http.Error(w, "Policy not found", http.StatusNotFound)
		return
	}

	var newRule types.SecurityRule
	if err := json.NewDecoder(r.Body).Decode(&newRule); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Add the rule to the policy
	policy.Rules = append(policy.Rules, newRule)

	// Save policy to file
	if err := a.savePolicyToFile(policyName, policy); err != nil {
		http.Error(w, "Failed to save policy", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Rule added"})
}

func (a *AdminServer) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyName := vars["name"]
	ruleID := vars["id"]

	policy, exists := a.policies[policyName]
	if !exists {
		http.Error(w, "Policy not found", http.StatusNotFound)
		return
	}

	var updatedRule types.SecurityRule
	if err := json.NewDecoder(r.Body).Decode(&updatedRule); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Find and update the rule
	found := false
	for i, rule := range policy.Rules {
		if rule.ID == ruleID {
			policy.Rules[i] = updatedRule
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	}

	// Save policy to file
	if err := a.savePolicyToFile(policyName, policy); err != nil {
		http.Error(w, "Failed to save policy", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Rule updated"})
}

func (a *AdminServer) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyName := vars["name"]
	ruleID := vars["id"]

	policy, exists := a.policies[policyName]
	if !exists {
		http.Error(w, "Policy not found", http.StatusNotFound)
		return
	}

	// Find and remove the rule
	found := false
	for i, rule := range policy.Rules {
		if rule.ID == ruleID {
			policy.Rules = append(policy.Rules[:i], policy.Rules[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		http.Error(w, "Rule not found", http.StatusNotFound)
		return
	}

	// Save policy to file
	if err := a.savePolicyToFile(policyName, policy); err != nil {
		http.Error(w, "Failed to save policy", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Rule deleted"})
}

func (a *AdminServer) handleGetBlockedPatterns(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyName := vars["name"]

	policy, exists := a.policies[policyName]
	if !exists {
		http.Error(w, "Policy not found", http.StatusNotFound)
		return
	}

	var patterns []BlockedPatternResponse
	for _, pattern := range policy.BlockedPatterns {
		patternResp := BlockedPatternResponse{
			Pattern:     pattern.Pattern,
			Type:        pattern.Type,
			Category:    pattern.Category,
			Description: pattern.Description,
			PolicyName:  policyName,
		}
		patterns = append(patterns, patternResp)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(patterns)
}

func (a *AdminServer) handleAddBlockedPattern(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyName := vars["name"]

	policy, exists := a.policies[policyName]
	if !exists {
		http.Error(w, "Policy not found", http.StatusNotFound)
		return
	}

	var newPattern types.BlockedPattern
	if err := json.NewDecoder(r.Body).Decode(&newPattern); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Add the pattern to the policy
	policy.BlockedPatterns = append(policy.BlockedPatterns, newPattern)

	// Save policy to file
	if err := a.savePolicyToFile(policyName, policy); err != nil {
		http.Error(w, "Failed to save policy", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Blocked pattern added"})
}

func (a *AdminServer) handleDeleteBlockedPattern(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyName := vars["name"]
	indexStr := vars["index"]

	index, err := strconv.Atoi(indexStr)
	if err != nil {
		http.Error(w, "Invalid index", http.StatusBadRequest)
		return
	}

	policy, exists := a.policies[policyName]
	if !exists {
		http.Error(w, "Policy not found", http.StatusNotFound)
		return
	}

	if index < 0 || index >= len(policy.BlockedPatterns) {
		http.Error(w, "Index out of range", http.StatusBadRequest)
		return
	}

	// Remove the blocked pattern
	policy.BlockedPatterns = append(policy.BlockedPatterns[:index], policy.BlockedPatterns[index+1:]...)

	// Save policy to file
	if err := a.savePolicyToFile(policyName, policy); err != nil {
		http.Error(w, "Failed to save policy", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Blocked pattern deleted"})
}

func (a *AdminServer) handleGetAlerts(w http.ResponseWriter, r *http.Request) {
	// Sort alerts by timestamp (newest first)
	alerts := make([]types.SecurityAlert, len(a.alertHistory))
	copy(alerts, a.alertHistory)
	sort.Slice(alerts, func(i, j int) bool {
		return alerts[i].Timestamp.After(alerts[j].Timestamp)
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

func (a *AdminServer) handleClearAlerts(w http.ResponseWriter, r *http.Request) {
	a.alertHistory = make([]types.SecurityAlert, 0)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Alerts cleared"})
}

// savePolicyToFile saves a policy back to its JSON file
func (a *AdminServer) savePolicyToFile(policyName string, policy *types.SecurityPolicy) error {
	filename := filepath.Join(a.policyDir, policyName+".json")

	// Create a backup first
	backupName := filename + ".backup." + strconv.FormatInt(time.Now().Unix(), 10)
	if _, err := os.Stat(filename); err == nil {
		if err := copyFile(filename, backupName); err != nil {
			log.Printf("Warning: Failed to create backup: %v", err)
		}
	}

	// Save the updated policy
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %v", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write policy file: %v", err)
	}

	log.Printf("Policy %s saved to %s", policyName, filename)
	return nil
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}
