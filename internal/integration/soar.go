package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/syphon1c/mcp-security-scanner/internal/config"
	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

// SOARIntegration handles integration with SOAR platforms
type SOARIntegration struct {
	config     config.SOARConfig
	httpClient *http.Client
}

// NewSOARIntegration creates a new SOAR integration client
func NewSOARIntegration(cfg config.SOARConfig) *SOARIntegration {
	return &SOARIntegration{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SOARIncident represents an incident for SOAR platform ingestion
type SOARIncident struct {
	Title        string                 `json:"title"`
	Description  string                 `json:"description"`
	Severity     string                 `json:"severity"`
	Priority     string                 `json:"priority"`
	Source       string                 `json:"source"`
	Category     string                 `json:"category"`
	Status       string                 `json:"status"`
	AssignedTo   string                 `json:"assigned_to,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	Tags         []string               `json:"tags"`
	Artifacts    []SOARArtifact         `json:"artifacts"`
	CustomFields map[string]interface{} `json:"custom_fields,omitempty"`
	ExternalID   string                 `json:"external_id,omitempty"`
}

// SOARArtifact represents evidence or indicators associated with an incident
type SOARArtifact struct {
	Type        string                 `json:"type"`
	Value       string                 `json:"value"`
	Description string                 `json:"description"`
	Tags        []string               `json:"tags"`
	Source      string                 `json:"source"`
	CreatedAt   time.Time              `json:"created_at"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// CreateIncidentFromAlert creates a SOAR incident from a security alert
func (s *SOARIntegration) CreateIncidentFromAlert(alert types.SecurityAlert) error {
	if !s.config.Enabled {
		return nil // SOAR integration disabled
	}

	if s.config.Endpoint == "" {
		return fmt.Errorf("SOAR endpoint not configured")
	}

	// Convert alert to SOAR incident
	incident := s.convertAlertToIncident(alert)

	// Create incident in SOAR platform
	return s.createIncident(incident)
}

// CreateIncidentFromFindings creates a SOAR incident from high-severity findings
func (s *SOARIntegration) CreateIncidentFromFindings(findings []types.Finding, target string, riskScore int) error {
	if !s.config.Enabled {
		return nil
	}

	if s.config.Endpoint == "" {
		return fmt.Errorf("SOAR endpoint not configured")
	}

	// Only create incidents for high-severity findings
	criticalFindings := s.filterFindingsBySeverity(findings, []string{"Critical", "High"})
	if len(criticalFindings) == 0 {
		return nil // No high-severity findings
	}

	// Convert findings to SOAR incident
	incident := s.convertFindingsToIncident(criticalFindings, target, riskScore)

	// Create incident in SOAR platform
	return s.createIncident(incident)
}

// CreateIncidentFromScanResult creates a SOAR incident from scan results if risk threshold is exceeded
func (s *SOARIntegration) CreateIncidentFromScanResult(result *types.ScanResult) error {
	if !s.config.Enabled {
		return nil
	}

	if s.config.Endpoint == "" {
		return fmt.Errorf("SOAR endpoint not configured")
	}

	// Only create incidents for high-risk scans
	if result.OverallRisk != "Critical" && result.OverallRisk != "High" {
		return nil
	}

	// Convert scan result to SOAR incident
	incident := s.convertScanResultToIncident(result)

	// Create incident in SOAR platform
	return s.createIncident(incident)
}

// convertAlertToIncident converts a security alert to SOAR incident format
func (s *SOARIntegration) convertAlertToIncident(alert types.SecurityAlert) SOARIncident {
	artifacts := []SOARArtifact{
		{
			Type:        "evidence",
			Value:       alert.Evidence,
			Description: "Evidence captured during alert detection",
			Tags:        []string{"evidence", "mcp-proxy"},
			Source:      "mcp-security-proxy",
			CreatedAt:   alert.Timestamp,
		},
		{
			Type:        "source_ip",
			Value:       alert.Source,
			Description: "Source IP address of the security event",
			Tags:        []string{"network", "source"},
			Source:      "mcp-security-proxy",
			CreatedAt:   alert.Timestamp,
		},
	}

	return SOARIncident{
		Title:       fmt.Sprintf("MCP Security Alert: %s", alert.AlertType),
		Description: fmt.Sprintf("Security alert detected by MCP proxy: %s\n\nSource: %s\nAction: %s", alert.Description, alert.Source, alert.Action),
		Severity:    s.mapSeverityToSOAR(alert.Severity),
		Priority:    s.mapSeverityToPriority(alert.Severity),
		Source:      "mcp-security-scanner",
		Category:    "mcp-security",
		Status:      "New",
		CreatedAt:   alert.Timestamp,
		UpdatedAt:   alert.Timestamp,
		Tags:        []string{"mcp-security", "proxy-alert", alert.AlertType},
		Artifacts:   artifacts,
		ExternalID:  fmt.Sprintf("mcp-alert-%d", alert.Timestamp.Unix()),
		CustomFields: map[string]interface{}{
			"alert_type":       alert.AlertType,
			"detection_source": "mcp-proxy",
		},
	}
}

// convertFindingsToIncident converts vulnerability findings to SOAR incident format
func (s *SOARIntegration) convertFindingsToIncident(findings []types.Finding, target string, riskScore int) SOARIncident {
	var artifacts []SOARArtifact

	// Create artifacts from findings
	for _, finding := range findings {
		artifact := SOARArtifact{
			Type:        "vulnerability",
			Value:       finding.ID,
			Description: fmt.Sprintf("%s: %s", finding.Title, finding.Description),
			Tags:        []string{"vulnerability", finding.Severity, finding.Category},
			Source:      "mcp-security-scanner",
			CreatedAt:   finding.Timestamp,
			Metadata: map[string]interface{}{
				"rule_id":     finding.RuleID,
				"location":    finding.Location,
				"line_number": finding.LineNumber,
				"code_line":   finding.CodeLine,
				"remediation": finding.Remediation,
				"evidence":    finding.Evidence,
			},
		}
		artifacts = append(artifacts, artifact)
	}

	// Add target artifact
	artifacts = append(artifacts, SOARArtifact{
		Type:        "target",
		Value:       target,
		Description: "Target MCP server that was scanned",
		Tags:        []string{"target", "mcp-server"},
		Source:      "mcp-security-scanner",
		CreatedAt:   time.Now(),
	})

	severity := "Medium"
	if riskScore >= 50 {
		severity = "Critical"
	} else if riskScore >= 30 {
		severity = "High"
	}

	return SOARIncident{
		Title:       fmt.Sprintf("MCP Security Vulnerabilities Detected: %s", target),
		Description: fmt.Sprintf("Security scan detected %d critical/high vulnerabilities in MCP server %s.\n\nRisk Score: %d\nFindings: %d", len(findings), target, riskScore, len(findings)),
		Severity:    severity,
		Priority:    s.mapSeverityToPriority(severity),
		Source:      "mcp-security-scanner",
		Category:    "vulnerability-management",
		Status:      "New",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Tags:        []string{"mcp-security", "vulnerability-scan", "automated"},
		Artifacts:   artifacts,
		ExternalID:  fmt.Sprintf("mcp-scan-%d", time.Now().Unix()),
		CustomFields: map[string]interface{}{
			"target_server": target,
			"risk_score":    riskScore,
			"finding_count": len(findings),
		},
	}
}

// convertScanResultToIncident converts scan results to SOAR incident format
func (s *SOARIntegration) convertScanResultToIncident(result *types.ScanResult) SOARIncident {
	return s.convertFindingsToIncident(result.Findings, result.Target, result.RiskScore)
}

// createIncident creates an incident in the SOAR platform
func (s *SOARIntegration) createIncident(incident SOARIncident) error {
	// Marshal incident to JSON
	incidentJSON, err := json.Marshal(incident)
	if err != nil {
		return fmt.Errorf("failed to marshal SOAR incident: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", s.config.Endpoint+"/incidents", bytes.NewBuffer(incidentJSON))
	if err != nil {
		return fmt.Errorf("failed to create SOAR request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "MCP-Security-Scanner/1.0")

	// Add authentication
	if s.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.config.APIKey)
	}
	if s.config.Username != "" {
		req.SetBasicAuth(s.config.Username, s.config.APIKey)
	}

	// Send request
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send SOAR incident: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("SOAR endpoint returned status %d", resp.StatusCode)
	}

	log.Printf("Successfully created SOAR incident: %s [%s]", incident.Title, incident.Severity)
	return nil
}

// filterFindingsBySeverity filters findings by severity levels
func (s *SOARIntegration) filterFindingsBySeverity(findings []types.Finding, severities []string) []types.Finding {
	var filtered []types.Finding
	for _, finding := range findings {
		for _, severity := range severities {
			if finding.Severity == severity {
				filtered = append(filtered, finding)
				break
			}
		}
	}
	return filtered
}

// mapSeverityToSOAR maps scanner severity to SOAR severity levels
func (s *SOARIntegration) mapSeverityToSOAR(severity string) string {
	switch severity {
	case "Critical":
		return "Critical"
	case "High":
		return "High"
	case "Medium":
		return "Medium"
	case "Low":
		return "Low"
	default:
		return "Info"
	}
}

// mapSeverityToPriority maps severity to SOAR priority levels
func (s *SOARIntegration) mapSeverityToPriority(severity string) string {
	switch severity {
	case "Critical":
		return "Critical"
	case "High":
		return "High"
	case "Medium":
		return "Medium"
	case "Low":
		return "Low"
	default:
		return "Low"
	}
}

// IsEnabled returns whether SOAR integration is enabled
func (s *SOARIntegration) IsEnabled() bool {
	return s.config.Enabled && s.config.Endpoint != ""
}

// ValidateConfiguration validates the SOAR configuration
func (s *SOARIntegration) ValidateConfiguration() error {
	if !s.config.Enabled {
		return nil
	}

	if s.config.Endpoint == "" {
		return fmt.Errorf("SOAR endpoint is required when SOAR integration is enabled")
	}

	if s.config.APIKey == "" && s.config.Username == "" {
		return fmt.Errorf("SOAR authentication (API key or username) is required when SOAR integration is enabled")
	}

	return nil
}
