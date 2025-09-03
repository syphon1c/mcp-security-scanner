package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/syphon1c/mcp-security-scanner/internal/config"
	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

// SlackIntegration handles integration with Slack for notifications
type SlackIntegration struct {
	config     config.SlackConfig
	httpClient *http.Client
}

// NewSlackIntegration creates a new Slack integration client
func NewSlackIntegration(cfg config.SlackConfig) *SlackIntegration {
	return &SlackIntegration{
		config: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SlackMessage represents a Slack webhook message
type SlackMessage struct {
	Channel     string            `json:"channel,omitempty"`
	Username    string            `json:"username,omitempty"`
	IconEmoji   string            `json:"icon_emoji,omitempty"`
	Text        string            `json:"text,omitempty"`
	Attachments []SlackAttachment `json:"attachments,omitempty"`
}

// SlackAttachment represents a Slack message attachment
type SlackAttachment struct {
	Color      string       `json:"color,omitempty"`
	Title      string       `json:"title,omitempty"`
	Text       string       `json:"text,omitempty"`
	Fields     []SlackField `json:"fields,omitempty"`
	Footer     string       `json:"footer,omitempty"`
	Timestamp  int64        `json:"ts,omitempty"`
	MarkdownIn []string     `json:"mrkdwn_in,omitempty"`
}

// SlackField represents a field in a Slack attachment
type SlackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// SendAlert sends a security alert notification to Slack
func (s *SlackIntegration) SendAlert(alert types.SecurityAlert) error {
	if !s.config.Enabled {
		return nil // Slack integration disabled
	}

	if s.config.WebhookURL == "" {
		return fmt.Errorf("Slack webhook URL not configured")
	}

	// Check severity threshold
	if !s.shouldSendAlert(alert.Severity) {
		return nil // Below minimum severity threshold
	}

	// Create Slack message for alert
	message := s.createAlertMessage(alert)

	// Send to Slack
	return s.sendMessage(message)
}

// SendScanSummary sends a scan completion summary to Slack
func (s *SlackIntegration) SendScanSummary(result *types.ScanResult) error {
	if !s.config.Enabled {
		return nil
	}

	if s.config.WebhookURL == "" {
		return fmt.Errorf("Slack webhook URL not configured")
	}

	// Check if scan has significant findings
	if !s.shouldSendScanSummary(result) {
		return nil
	}

	// Create Slack message for scan summary
	message := s.createScanSummaryMessage(result)

	// Send to Slack
	return s.sendMessage(message)
}

// SendCriticalFindings sends individual critical findings to Slack
func (s *SlackIntegration) SendCriticalFindings(findings []types.Finding, target string) error {
	if !s.config.Enabled {
		return nil
	}

	if s.config.WebhookURL == "" {
		return fmt.Errorf("Slack webhook URL not configured")
	}

	// Filter for critical findings only
	criticalFindings := s.filterCriticalFindings(findings)
	if len(criticalFindings) == 0 {
		return nil
	}

	// Create message for critical findings
	message := s.createCriticalFindingsMessage(criticalFindings, target)

	// Send to Slack
	return s.sendMessage(message)
}

// createAlertMessage creates a Slack message for security alerts
func (s *SlackIntegration) createAlertMessage(alert types.SecurityAlert) SlackMessage {
	color := s.getSeverityColor(alert.Severity)
	icon := s.getSeverityIcon(alert.Severity)

	attachment := SlackAttachment{
		Color:     color,
		Title:     fmt.Sprintf("%s Security Alert: %s", icon, alert.AlertType),
		Text:      alert.Description,
		Timestamp: alert.Timestamp.Unix(),
		Footer:    "MCP Security Scanner",
		Fields: []SlackField{
			{
				Title: "Severity",
				Value: alert.Severity,
				Short: true,
			},
			{
				Title: "Source",
				Value: alert.Source,
				Short: true,
			},
			{
				Title: "Action Taken",
				Value: alert.Action,
				Short: true,
			},
			{
				Title: "Time",
				Value: alert.Timestamp.Format("2006-01-02 15:04:05 UTC"),
				Short: true,
			},
		},
		MarkdownIn: []string{"text", "fields"},
	}

	if alert.Evidence != "" {
		attachment.Fields = append(attachment.Fields, SlackField{
			Title: "Evidence",
			Value: fmt.Sprintf("```%s```", s.truncateText(alert.Evidence, 500)),
			Short: false,
		})
	}

	return SlackMessage{
		Channel:     s.config.Channel,
		Username:    s.config.Username,
		IconEmoji:   s.config.IconEmoji,
		Text:        fmt.Sprintf("🚨 *MCP Security Alert* - %s", alert.Severity),
		Attachments: []SlackAttachment{attachment},
	}
}

// createScanSummaryMessage creates a Slack message for scan summaries
func (s *SlackIntegration) createScanSummaryMessage(result *types.ScanResult) SlackMessage {
	color := s.getRiskColor(result.OverallRisk)
	icon := s.getRiskIcon(result.OverallRisk)

	attachment := SlackAttachment{
		Color:     color,
		Title:     fmt.Sprintf("%s MCP Security Scan Completed", icon),
		Text:      fmt.Sprintf("Security scan completed for `%s`", result.Target),
		Timestamp: result.Timestamp.Unix(),
		Footer:    "MCP Security Scanner",
		Fields: []SlackField{
			{
				Title: "Target",
				Value: result.Target,
				Short: true,
			},
			{
				Title: "Overall Risk",
				Value: result.OverallRisk,
				Short: true,
			},
			{
				Title: "Risk Score",
				Value: fmt.Sprintf("%d", result.RiskScore),
				Short: true,
			},
			{
				Title: "Policy Used",
				Value: result.PolicyUsed,
				Short: true,
			},
			{
				Title: "Total Findings",
				Value: fmt.Sprintf("%d", len(result.Findings)),
				Short: true,
			},
			{
				Title: "Critical/High",
				Value: fmt.Sprintf("%d/%d", result.Summary.CriticalFindings, result.Summary.HighFindings),
				Short: true,
			},
		},
		MarkdownIn: []string{"text", "fields"},
	}

	return SlackMessage{
		Channel:     s.config.Channel,
		Username:    s.config.Username,
		IconEmoji:   s.config.IconEmoji,
		Text:        fmt.Sprintf("📊 *MCP Security Scan Summary* - %s Risk", result.OverallRisk),
		Attachments: []SlackAttachment{attachment},
	}
}

// createCriticalFindingsMessage creates a Slack message for critical findings
func (s *SlackIntegration) createCriticalFindingsMessage(findings []types.Finding, target string) SlackMessage {
	attachment := SlackAttachment{
		Color:     "danger",
		Title:     "🚨 Critical Security Vulnerabilities Detected",
		Text:      fmt.Sprintf("Found %d critical vulnerabilities in `%s`", len(findings), target),
		Timestamp: time.Now().Unix(),
		Footer:    "MCP Security Scanner",
		Fields: []SlackField{
			{
				Title: "Target",
				Value: target,
				Short: true,
			},
			{
				Title: "Critical Findings",
				Value: fmt.Sprintf("%d", len(findings)),
				Short: true,
			},
		},
		MarkdownIn: []string{"text", "fields"},
	}

	// Add individual findings (limit to first 5 to avoid message size limits)
	findingsText := ""
	maxFindings := 5
	for i, finding := range findings {
		if i >= maxFindings {
			findingsText += fmt.Sprintf("\n_...and %d more findings_", len(findings)-maxFindings)
			break
		}
		findingsText += fmt.Sprintf("\n• *%s* (%s): %s", finding.Title, finding.Category, s.truncateText(finding.Description, 100))
	}

	if findingsText != "" {
		attachment.Fields = append(attachment.Fields, SlackField{
			Title: "Findings",
			Value: findingsText,
			Short: false,
		})
	}

	return SlackMessage{
		Channel:     s.config.Channel,
		Username:    s.config.Username,
		IconEmoji:   s.config.IconEmoji,
		Text:        "🚨 *Critical MCP Security Vulnerabilities*",
		Attachments: []SlackAttachment{attachment},
	}
}

// sendMessage sends a message to Slack via webhook
func (s *SlackIntegration) sendMessage(message SlackMessage) error {
	// Marshal message to JSON
	messageJSON, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal Slack message: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", s.config.WebhookURL, bytes.NewBuffer(messageJSON))
	if err != nil {
		return fmt.Errorf("failed to create Slack request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "MCP-Security-Scanner/1.0")

	// Send request
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send Slack message: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != 200 {
		return fmt.Errorf("Slack webhook returned status %d", resp.StatusCode)
	}

	log.Printf("Successfully sent Slack notification")
	return nil
}

// shouldSendAlert checks if alert meets severity threshold
func (s *SlackIntegration) shouldSendAlert(severity string) bool {
	severityLevels := map[string]int{
		"Critical": 4,
		"High":     3,
		"Medium":   2,
		"Low":      1,
		"Info":     0,
	}

	alertLevel := severityLevels[severity]
	minLevel := severityLevels[s.config.MinSeverity]

	return alertLevel >= minLevel
}

// shouldSendScanSummary checks if scan results warrant a summary notification
func (s *SlackIntegration) shouldSendScanSummary(result *types.ScanResult) bool {
	// Send summary for Medium risk and above, or if there are any Critical/High findings
	return result.OverallRisk == "Critical" || result.OverallRisk == "High" || result.OverallRisk == "Medium" ||
		result.Summary.CriticalFindings > 0 || result.Summary.HighFindings > 0
}

// filterCriticalFindings filters findings to only include Critical severity
func (s *SlackIntegration) filterCriticalFindings(findings []types.Finding) []types.Finding {
	var critical []types.Finding
	for _, finding := range findings {
		if finding.Severity == "Critical" {
			critical = append(critical, finding)
		}
	}
	return critical
}

// getSeverityColor returns Slack color for severity level
func (s *SlackIntegration) getSeverityColor(severity string) string {
	switch severity {
	case "Critical":
		return "danger"
	case "High":
		return "warning"
	case "Medium":
		return "#ff9900"
	case "Low":
		return "good"
	default:
		return "#cccccc"
	}
}

// getRiskColor returns Slack color for risk level
func (s *SlackIntegration) getRiskColor(risk string) string {
	switch risk {
	case "Critical":
		return "danger"
	case "High":
		return "warning"
	case "Medium":
		return "#ff9900"
	case "Low":
		return "good"
	default:
		return "#cccccc"
	}
}

// getSeverityIcon returns emoji icon for severity level
func (s *SlackIntegration) getSeverityIcon(severity string) string {
	switch severity {
	case "Critical":
		return "💥"
	case "High":
		return "🚨"
	case "Medium":
		return "⚠️"
	case "Low":
		return "ℹ️"
	default:
		return "📋"
	}
}

// getRiskIcon returns emoji icon for risk level
func (s *SlackIntegration) getRiskIcon(risk string) string {
	switch risk {
	case "Critical":
		return "💥"
	case "High":
		return "🚨"
	case "Medium":
		return "⚠️"
	case "Low":
		return "✅"
	default:
		return "📋"
	}
}

// truncateText truncates text to specified length with ellipsis
func (s *SlackIntegration) truncateText(text string, maxLength int) string {
	if len(text) <= maxLength {
		return text
	}
	return text[:maxLength-3] + "..."
}

// IsEnabled returns whether Slack integration is enabled
func (s *SlackIntegration) IsEnabled() bool {
	return s.config.Enabled && s.config.WebhookURL != ""
}

// ValidateConfiguration validates the Slack configuration
func (s *SlackIntegration) ValidateConfiguration() error {
	if !s.config.Enabled {
		return nil
	}

	if s.config.WebhookURL == "" {
		return fmt.Errorf("Slack webhook URL is required when Slack integration is enabled")
	}

	if !strings.HasPrefix(s.config.WebhookURL, "https://hooks.slack.com/") {
		return fmt.Errorf("invalid Slack webhook URL format")
	}

	validSeverities := []string{"Critical", "High", "Medium", "Low", "Info"}
	validSeverity := false
	for _, severity := range validSeverities {
		if s.config.MinSeverity == severity {
			validSeverity = true
			break
		}
	}
	if !validSeverity {
		return fmt.Errorf("invalid minimum severity level: %s", s.config.MinSeverity)
	}

	return nil
}
