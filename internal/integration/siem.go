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

// SIEMIntegration handles integration with SIEM systems
type SIEMIntegration struct {
	config     config.SIEMConfig
	httpClient *http.Client
}

// NewSIEMIntegration creates a new SIEM integration client
func NewSIEMIntegration(cfg config.SIEMConfig) *SIEMIntegration {
	return &SIEMIntegration{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SIEMEvent represents a security event for SIEM ingestion
type SIEMEvent struct {
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
	EventType string                 `json:"event_type"`
	Severity  string                 `json:"severity"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details"`
	Index     string                 `json:"index,omitempty"`
	Tags      []string               `json:"tags,omitempty"`
	Host      string                 `json:"host"`
	SourceIP  string                 `json:"source_ip,omitempty"`
	TargetIP  string                 `json:"target_ip,omitempty"`
	RuleID    string                 `json:"rule_id,omitempty"`
	Category  string                 `json:"category,omitempty"`
	RiskScore int                    `json:"risk_score,omitempty"`
	Evidence  string                 `json:"evidence,omitempty"`
}

// SendAlert sends a security alert to the SIEM system
func (s *SIEMIntegration) SendAlert(alert types.SecurityAlert) error {
	if !s.config.Enabled {
		return nil // SIEM integration disabled
	}

	if s.config.Endpoint == "" {
		return fmt.Errorf("SIEM endpoint not configured")
	}

	// Convert security alert to SIEM event format
	siemEvent := s.convertAlertToSIEMEvent(alert)

	// Send to SIEM
	return s.sendEventToSIEM(siemEvent)
}

// SendFinding sends a vulnerability finding to the SIEM system
func (s *SIEMIntegration) SendFinding(finding types.Finding, target string) error {
	if !s.config.Enabled {
		return nil
	}

	if s.config.Endpoint == "" {
		return fmt.Errorf("SIEM endpoint not configured")
	}

	// Convert finding to SIEM event format
	siemEvent := s.convertFindingToSIEMEvent(finding, target)

	// Send to SIEM
	return s.sendEventToSIEM(siemEvent)
}

// SendScanResult sends complete scan results to the SIEM system
func (s *SIEMIntegration) SendScanResult(result *types.ScanResult) error {
	if !s.config.Enabled {
		return nil
	}

	if s.config.Endpoint == "" {
		return fmt.Errorf("SIEM endpoint not configured")
	}

	// Send scan summary event
	summaryEvent := SIEMEvent{
		Timestamp: result.Timestamp,
		Source:    "mcp-security-scanner",
		EventType: "scan_completed",
		Severity:  s.mapRiskToSeverity(result.OverallRisk),
		Message:   fmt.Sprintf("MCP security scan completed for %s", result.Target),
		Index:     s.config.Index,
		Tags:      []string{"mcp-security", "vulnerability-scan", "summary"},
		Host:      "mcp-scanner",
		Details: map[string]interface{}{
			"target":         result.Target,
			"policy_used":    result.PolicyUsed,
			"total_findings": len(result.Findings),
			"critical_count": s.countFindingsBySeverity(result.Findings, "Critical"),
			"high_count":     s.countFindingsBySeverity(result.Findings, "High"),
			"medium_count":   s.countFindingsBySeverity(result.Findings, "Medium"),
			"low_count":      s.countFindingsBySeverity(result.Findings, "Low"),
			"overall_risk":   result.OverallRisk,
			"risk_score":     result.RiskScore,
			"scan_duration":  time.Since(result.Timestamp).String(),
		},
		RiskScore: result.RiskScore,
	}

	if err := s.sendEventToSIEM(summaryEvent); err != nil {
		return fmt.Errorf("failed to send scan summary to SIEM: %w", err)
	}

	// Send individual findings as separate events
	for _, finding := range result.Findings {
		if err := s.SendFinding(finding, result.Target); err != nil {
			log.Printf("Warning: Failed to send finding %s to SIEM: %v", finding.ID, err)
		}
	}

	return nil
}

// convertAlertToSIEMEvent converts a security alert to SIEM event format
func (s *SIEMIntegration) convertAlertToSIEMEvent(alert types.SecurityAlert) SIEMEvent {
	return SIEMEvent{
		Timestamp: alert.Timestamp,
		Source:    "mcp-security-proxy",
		EventType: "security_alert",
		Severity:  alert.Severity,
		Message:   alert.Description,
		Index:     s.config.Index,
		Tags:      []string{"mcp-security", "proxy", "real-time", alert.AlertType},
		Host:      "mcp-proxy",
		SourceIP:  alert.Source,
		Category:  alert.AlertType,
		Details: map[string]interface{}{
			"alert_type": alert.AlertType,
			"evidence":   alert.Evidence,
			"action":     alert.Action,
		},
	}
}

// convertFindingToSIEMEvent converts a vulnerability finding to SIEM event format
func (s *SIEMIntegration) convertFindingToSIEMEvent(finding types.Finding, target string) SIEMEvent {
	return SIEMEvent{
		Timestamp: finding.Timestamp,
		Source:    "mcp-security-scanner",
		EventType: "vulnerability_found",
		Severity:  finding.Severity,
		Message:   finding.Description,
		Index:     s.config.Index,
		Tags:      []string{"mcp-security", "vulnerability", "static-analysis", finding.Category},
		Host:      "mcp-scanner",
		RuleID:    finding.RuleID,
		Category:  finding.Category,
		Evidence:  finding.Evidence,
		Details: map[string]interface{}{
			"finding_id":   finding.ID,
			"rule_id":      finding.RuleID,
			"location":     finding.Location,
			"line_number":  finding.LineNumber,
			"code_line":    finding.CodeLine,
			"code_context": finding.CodeContext,
			"target":       target,
			"remediation":  finding.Remediation,
		},
	}
}

// sendEventToSIEM sends a SIEM event to the configured SIEM endpoint
func (s *SIEMIntegration) sendEventToSIEM(event SIEMEvent) error {
	// Marshal event to JSON
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal SIEM event: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", s.config.Endpoint, bytes.NewBuffer(eventJSON))
	if err != nil {
		return fmt.Errorf("failed to create SIEM request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "MCP-Security-Scanner/1.0")

	// Add authentication if API key is provided
	if s.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.config.APIKey)
		// Alternative for some SIEM systems that use different auth headers
		req.Header.Set("X-API-Key", s.config.APIKey)
	}

	// Send request
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send SIEM event: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("SIEM endpoint returned status %d", resp.StatusCode)
	}

	log.Printf("Successfully sent SIEM event: %s [%s]", event.EventType, event.Severity)
	return nil
}

// mapRiskToSeverity maps risk levels to SIEM severity levels
func (s *SIEMIntegration) mapRiskToSeverity(risk string) string {
	switch risk {
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

// countFindingsBySeverity counts findings by severity level
func (s *SIEMIntegration) countFindingsBySeverity(findings []types.Finding, severity string) int {
	count := 0
	for _, finding := range findings {
		if finding.Severity == severity {
			count++
		}
	}
	return count
}

// IsEnabled returns whether SIEM integration is enabled
func (s *SIEMIntegration) IsEnabled() bool {
	return s.config.Enabled && s.config.Endpoint != ""
}

// ValidateConfiguration validates the SIEM configuration
func (s *SIEMIntegration) ValidateConfiguration() error {
	if !s.config.Enabled {
		return nil
	}

	if s.config.Endpoint == "" {
		return fmt.Errorf("SIEM endpoint is required when SIEM integration is enabled")
	}

	if s.config.Index == "" {
		return fmt.Errorf("SIEM index is required when SIEM integration is enabled")
	}

	return nil
}
