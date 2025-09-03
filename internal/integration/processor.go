package integration

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/syphon1c/mcp-security-scanner/internal/config"
	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

// AlertProcessor manages all integration endpoints and orchestrates alert processing
type AlertProcessor struct {
	siemIntegration  *SIEMIntegration
	soarIntegration  *SOARIntegration
	slackIntegration *SlackIntegration
	config           config.IntegrationSettings
	mu               sync.RWMutex
}

// NewAlertProcessor creates a new alert processor with all configured integrations
func NewAlertProcessor(cfg config.IntegrationSettings) *AlertProcessor {
	processor := &AlertProcessor{
		config: cfg,
	}

	// Initialize integrations based on configuration
	processor.siemIntegration = NewSIEMIntegration(cfg.SIEM)
	processor.soarIntegration = NewSOARIntegration(cfg.SOAR)
	processor.slackIntegration = NewSlackIntegration(cfg.Slack)

	return processor
}

// ProcessAlert processes a security alert through all enabled integrations
func (ap *AlertProcessor) ProcessAlert(alert types.SecurityAlert) {
	ap.mu.RLock()
	defer ap.mu.RUnlock()

	var wg sync.WaitGroup
	errors := make(chan error, 3)

	// Process SIEM integration
	if ap.siemIntegration.IsEnabled() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ap.siemIntegration.SendAlert(alert); err != nil {
				errors <- fmt.Errorf("SIEM integration failed: %w", err)
			}
		}()
	}

	// Process SOAR integration
	if ap.soarIntegration.IsEnabled() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ap.soarIntegration.CreateIncidentFromAlert(alert); err != nil {
				errors <- fmt.Errorf("SOAR integration failed: %w", err)
			}
		}()
	}

	// Process Slack integration
	if ap.slackIntegration.IsEnabled() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ap.slackIntegration.SendAlert(alert); err != nil {
				errors <- fmt.Errorf("Slack integration failed: %w", err)
			}
		}()
	}

	// Wait for all integrations to complete
	go func() {
		wg.Wait()
		close(errors)
	}()

	// Log any errors
	for err := range errors {
		log.Printf("Alert processing error: %v", err)
	}

	log.Printf("Processed security alert [%s] through %d integrations", alert.Severity, ap.getEnabledIntegrationsCount())
}

// ProcessScanResult processes scan results through all enabled integrations
func (ap *AlertProcessor) ProcessScanResult(result *types.ScanResult) {
	ap.mu.RLock()
	defer ap.mu.RUnlock()

	var wg sync.WaitGroup
	errors := make(chan error, 3)

	// Process SIEM integration
	if ap.siemIntegration.IsEnabled() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ap.siemIntegration.SendScanResult(result); err != nil {
				errors <- fmt.Errorf("SIEM scan result processing failed: %w", err)
			}
		}()
	}

	// Process SOAR integration
	if ap.soarIntegration.IsEnabled() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ap.soarIntegration.CreateIncidentFromScanResult(result); err != nil {
				errors <- fmt.Errorf("SOAR scan result processing failed: %w", err)
			}
		}()
	}

	// Process Slack integration
	if ap.slackIntegration.IsEnabled() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Send scan summary
			if err := ap.slackIntegration.SendScanSummary(result); err != nil {
				errors <- fmt.Errorf("Slack scan summary failed: %w", err)
				return
			}
			// Send critical findings separately
			if err := ap.slackIntegration.SendCriticalFindings(result.Findings, result.Target); err != nil {
				errors <- fmt.Errorf("Slack critical findings failed: %w", err)
			}
		}()
	}

	// Wait for all integrations to complete
	go func() {
		wg.Wait()
		close(errors)
	}()

	// Log any errors
	for err := range errors {
		log.Printf("Scan result processing error: %v", err)
	}

	log.Printf("Processed scan result for %s through %d integrations (Risk: %s, Findings: %d)",
		result.Target, ap.getEnabledIntegrationsCount(), result.OverallRisk, len(result.Findings))
}

// ProcessFinding processes individual critical findings
func (ap *AlertProcessor) ProcessFinding(finding types.Finding, target string) {
	ap.mu.RLock()
	defer ap.mu.RUnlock()

	// Only process critical and high severity findings
	if finding.Severity != "Critical" && finding.Severity != "High" {
		return
	}

	var wg sync.WaitGroup
	errors := make(chan error, 2)

	// Process SIEM integration
	if ap.siemIntegration.IsEnabled() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := ap.siemIntegration.SendFinding(finding, target); err != nil {
				errors <- fmt.Errorf("SIEM finding processing failed: %w", err)
			}
		}()
	}

	// Process SOAR integration for critical findings
	if ap.soarIntegration.IsEnabled() && finding.Severity == "Critical" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			findings := []types.Finding{finding}
			if err := ap.soarIntegration.CreateIncidentFromFindings(findings, target, 50); err != nil {
				errors <- fmt.Errorf("SOAR finding processing failed: %w", err)
			}
		}()
	}

	// Wait for all integrations to complete
	go func() {
		wg.Wait()
		close(errors)
	}()

	// Log any errors
	for err := range errors {
		log.Printf("Finding processing error: %v", err)
	}
}

// ValidateIntegrations validates all integration configurations
func (ap *AlertProcessor) ValidateIntegrations() []error {
	var errors []error

	// Validate SIEM integration
	if err := ap.siemIntegration.ValidateConfiguration(); err != nil {
		errors = append(errors, fmt.Errorf("SIEM configuration error: %w", err))
	}

	// Validate SOAR integration
	if err := ap.soarIntegration.ValidateConfiguration(); err != nil {
		errors = append(errors, fmt.Errorf("SOAR configuration error: %w", err))
	}

	// Validate Slack integration
	if err := ap.slackIntegration.ValidateConfiguration(); err != nil {
		errors = append(errors, fmt.Errorf("Slack configuration error: %w", err))
	}

	return errors
}

// GetIntegrationStatus returns the status of all integrations
func (ap *AlertProcessor) GetIntegrationStatus() map[string]bool {
	ap.mu.RLock()
	defer ap.mu.RUnlock()

	return map[string]bool{
		"siem":  ap.siemIntegration.IsEnabled(),
		"soar":  ap.soarIntegration.IsEnabled(),
		"slack": ap.slackIntegration.IsEnabled(),
	}
}

// GetEnabledIntegrations returns a list of enabled integration names
func (ap *AlertProcessor) GetEnabledIntegrations() []string {
	ap.mu.RLock()
	defer ap.mu.RUnlock()

	var enabled []string
	if ap.siemIntegration.IsEnabled() {
		enabled = append(enabled, "SIEM")
	}
	if ap.soarIntegration.IsEnabled() {
		enabled = append(enabled, "SOAR")
	}
	if ap.slackIntegration.IsEnabled() {
		enabled = append(enabled, "Slack")
	}
	return enabled
}

// getEnabledIntegrationsCount returns the number of enabled integrations
func (ap *AlertProcessor) getEnabledIntegrationsCount() int {
	count := 0
	if ap.siemIntegration.IsEnabled() {
		count++
	}
	if ap.soarIntegration.IsEnabled() {
		count++
	}
	if ap.slackIntegration.IsEnabled() {
		count++
	}
	return count
}

// TestIntegrations tests connectivity to all enabled integrations
func (ap *AlertProcessor) TestIntegrations() map[string]error {
	ap.mu.RLock()
	defer ap.mu.RUnlock()

	results := make(map[string]error)

	// Test SIEM integration
	if ap.siemIntegration.IsEnabled() {
		// Create a test alert
		testAlert := types.SecurityAlert{
			Timestamp:   time.Now(),
			Severity:    "Low",
			AlertType:   "integration_test",
			Description: "Integration connectivity test",
			Source:      "integration_test",
			Evidence:    "Test evidence",
			Action:      "test",
		}
		results["siem"] = ap.siemIntegration.SendAlert(testAlert)
	}

	// Test SOAR integration (skip to avoid creating test incidents)
	if ap.soarIntegration.IsEnabled() {
		results["soar"] = ap.soarIntegration.ValidateConfiguration()
	}

	// Test Slack integration
	if ap.slackIntegration.IsEnabled() {
		results["slack"] = ap.slackIntegration.ValidateConfiguration()
	}

	return results
}

// ReloadConfiguration reloads integration configurations
func (ap *AlertProcessor) ReloadConfiguration(cfg config.IntegrationSettings) {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	ap.config = cfg
	ap.siemIntegration = NewSIEMIntegration(cfg.SIEM)
	ap.soarIntegration = NewSOARIntegration(cfg.SOAR)
	ap.slackIntegration = NewSlackIntegration(cfg.Slack)

	log.Printf("Reloaded integration configurations")
}
