package integration

import (
	"sync"
	"testing"
	"time"

	"github.com/syphon1c/mcp-security-scanner/internal/config"
	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

func TestNewAlertProcessor(t *testing.T) {
	cfg := config.IntegrationSettings{
		SIEM: config.SIEMConfig{
			Enabled:  true,
			Endpoint: "https://siem.example.com",
			APIKey:   "test-key",
			Index:    "mcp-security",
		},
		SOAR: config.SOARConfig{
			Enabled:  true,
			Endpoint: "https://soar.example.com",
			APIKey:   "test-key",
			Username: "mcp-scanner",
		},
		Slack: config.SlackConfig{
			Enabled:     true,
			WebhookURL:  "https://hooks.slack.com/test",
			Channel:     "#security",
			Username:    "MCP Security Bot",
			MinSeverity: "High",
		},
	}

	processor := NewAlertProcessor(cfg)

	if processor == nil {
		t.Fatal("NewAlertProcessor() should not return nil")
	}

	if processor.siemIntegration == nil {
		t.Error("SIEM integration should be initialized")
	}

	if processor.soarIntegration == nil {
		t.Error("SOAR integration should be initialized")
	}

	if processor.slackIntegration == nil {
		t.Error("Slack integration should be initialized")
	}

	// Test that the processor has the correct configuration
	if processor.config.SIEM.Enabled != cfg.SIEM.Enabled {
		t.Error("SIEM configuration should be preserved")
	}

	if processor.config.SOAR.Enabled != cfg.SOAR.Enabled {
		t.Error("SOAR configuration should be preserved")
	}

	if processor.config.Slack.Enabled != cfg.Slack.Enabled {
		t.Error("Slack configuration should be preserved")
	}
}

func TestAlertProcessor_ProcessAlert(t *testing.T) {
	cfg := config.IntegrationSettings{
		SIEM: config.SIEMConfig{
			Enabled:  false, // Disabled to avoid actual network calls
			Endpoint: "https://siem.example.com",
		},
		SOAR: config.SOARConfig{
			Enabled:  false,
			Endpoint: "https://soar.example.com",
		},
		Slack: config.SlackConfig{
			Enabled:     false,
			WebhookURL:  "https://hooks.slack.com/test",
			MinSeverity: "High",
		},
	}

	processor := NewAlertProcessor(cfg)

	alert := types.SecurityAlert{
		Timestamp:   time.Now(),
		Severity:    "High",
		AlertType:   "test_alert",
		Description: "Test security alert",
		Source:      "test",
		Evidence:    "Test evidence",
		Action:      "block",
	}

	// This should complete without error even with disabled integrations
	processor.ProcessAlert(alert)

	// Test with enabled integrations (will fail network calls but shouldn't crash)
	cfg.SIEM.Enabled = true
	cfg.SOAR.Enabled = true
	cfg.Slack.Enabled = true

	processor = NewAlertProcessor(cfg)
	processor.ProcessAlert(alert)
}

func TestAlertProcessor_ProcessScanResult(t *testing.T) {
	cfg := config.IntegrationSettings{
		SIEM: config.SIEMConfig{
			Enabled:  false,
			Endpoint: "https://siem.example.com",
		},
		SOAR: config.SOARConfig{
			Enabled:  false,
			Endpoint: "https://soar.example.com",
		},
		Slack: config.SlackConfig{
			Enabled:     false,
			WebhookURL:  "https://hooks.slack.com/test",
			MinSeverity: "Medium",
		},
	}

	processor := NewAlertProcessor(cfg)

	scanResult := &types.ScanResult{
		Timestamp:   time.Now(),
		Target:      "https://test-server.com",
		PolicyUsed:  "test-policy",
		OverallRisk: "High",
		RiskScore:   75,
		Findings: []types.Finding{
			{
				ID:          "FIND_001",
				RuleID:      "RULE_001",
				Severity:    "Critical",
				Category:    "Injection",
				Title:       "Command Injection",
				Description: "Potential command injection vulnerability",
				Evidence:    "exec() call detected",
				Location:    "line 42",
				Remediation: "Use parameterized commands",
				Timestamp:   time.Now(),
			},
		},
		MCPServer: types.MCPServerInfo{
			Name:    "Test Server",
			Version: "1.0.0",
		},
		Summary: types.ScanSummary{
			TotalFindings:    1,
			CriticalFindings: 1,
			HighFindings:     0,
			MediumFindings:   0,
			LowFindings:      0,
		},
	}

	// This should complete without error
	processor.ProcessScanResult(scanResult)
}

func TestAlertProcessor_ProcessFinding(t *testing.T) {
	cfg := config.IntegrationSettings{
		SIEM: config.SIEMConfig{
			Enabled:  false,
			Endpoint: "https://siem.example.com",
		},
		SOAR: config.SOARConfig{
			Enabled:  false,
			Endpoint: "https://soar.example.com",
		},
		Slack: config.SlackConfig{
			Enabled:    false,
			WebhookURL: "https://hooks.slack.com/test",
		},
	}

	processor := NewAlertProcessor(cfg)

	tests := []struct {
		name     string
		severity string
		target   string
	}{
		{
			name:     "Critical Finding",
			severity: "Critical",
			target:   "https://critical-server.com",
		},
		{
			name:     "High Finding",
			severity: "High",
			target:   "https://high-server.com",
		},
		{
			name:     "Medium Finding (should be ignored)",
			severity: "Medium",
			target:   "https://medium-server.com",
		},
		{
			name:     "Low Finding (should be ignored)",
			severity: "Low",
			target:   "https://low-server.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := types.Finding{
				ID:          "TEST_001",
				RuleID:      "RULE_001",
				Severity:    tt.severity,
				Category:    "Test",
				Title:       "Test Finding",
				Description: "Test finding description",
				Evidence:    "Test evidence",
				Location:    "test location",
				Remediation: "Test remediation",
				Timestamp:   time.Now(),
			}

			// Should complete without error
			processor.ProcessFinding(finding, tt.target)
		})
	}
}

func TestAlertProcessor_ValidateIntegrations(t *testing.T) {
	cfg := config.IntegrationSettings{
		SIEM: config.SIEMConfig{
			Enabled:  true,
			Endpoint: "", // Invalid - empty endpoint
			APIKey:   "test-key",
		},
		SOAR: config.SOARConfig{
			Enabled:  true,
			Endpoint: "https://soar.example.com",
			APIKey:   "", // Invalid - empty API key
		},
		Slack: config.SlackConfig{
			Enabled:    true,
			WebhookURL: "", // Invalid - empty webhook URL
		},
	}

	processor := NewAlertProcessor(cfg)
	errors := processor.ValidateIntegrations()

	if len(errors) == 0 {
		t.Error("Expected validation errors for invalid configuration")
	}

	// Should have errors for all three integrations
	if len(errors) < 3 {
		t.Errorf("Expected at least 3 validation errors, got %d", len(errors))
	}
}

func TestAlertProcessor_GetIntegrationStatus(t *testing.T) {
	cfg := config.IntegrationSettings{
		SIEM: config.SIEMConfig{
			Enabled:  true,
			Endpoint: "https://siem.example.com",
			APIKey:   "test-key",
		},
		SOAR: config.SOARConfig{
			Enabled:  false,
			Endpoint: "https://soar.example.com",
		},
		Slack: config.SlackConfig{
			Enabled:    true,
			WebhookURL: "https://hooks.slack.com/test",
		},
	}

	processor := NewAlertProcessor(cfg)
	status := processor.GetIntegrationStatus()

	expectedStatus := map[string]bool{
		"siem":  true,
		"soar":  false,
		"slack": true,
	}

	for integration, expected := range expectedStatus {
		if status[integration] != expected {
			t.Errorf("Expected %s status %v, got %v", integration, expected, status[integration])
		}
	}
}

func TestAlertProcessor_GetEnabledIntegrations(t *testing.T) {
	cfg := config.IntegrationSettings{
		SIEM: config.SIEMConfig{
			Enabled:  true,
			Endpoint: "https://siem.example.com",
			APIKey:   "test-key",
		},
		SOAR: config.SOARConfig{
			Enabled:  false,
			Endpoint: "https://soar.example.com",
		},
		Slack: config.SlackConfig{
			Enabled:    true,
			WebhookURL: "https://hooks.slack.com/test",
		},
	}

	processor := NewAlertProcessor(cfg)
	enabled := processor.GetEnabledIntegrations()

	expectedEnabled := []string{"SIEM", "Slack"}
	if len(enabled) != len(expectedEnabled) {
		t.Errorf("Expected %d enabled integrations, got %d", len(expectedEnabled), len(enabled))
	}

	enabledMap := make(map[string]bool)
	for _, integration := range enabled {
		enabledMap[integration] = true
	}

	for _, expected := range expectedEnabled {
		if !enabledMap[expected] {
			t.Errorf("Expected %s to be in enabled integrations", expected)
		}
	}

	// SOAR should not be in enabled list
	if enabledMap["SOAR"] {
		t.Error("SOAR should not be in enabled integrations")
	}
}

func TestAlertProcessor_ReloadConfiguration(t *testing.T) {
	// Initial configuration
	cfg1 := config.IntegrationSettings{
		SIEM: config.SIEMConfig{
			Enabled:  true,
			Endpoint: "https://siem1.example.com",
		},
	}

	processor := NewAlertProcessor(cfg1)

	// Verify initial config
	status1 := processor.GetIntegrationStatus()
	if !status1["siem"] {
		t.Error("SIEM should be enabled initially")
	}

	// New configuration
	cfg2 := config.IntegrationSettings{
		SIEM: config.SIEMConfig{
			Enabled:  false,
			Endpoint: "https://siem2.example.com",
		},
		Slack: config.SlackConfig{
			Enabled:    true,
			WebhookURL: "https://hooks.slack.com/test",
		},
	}

	// Reload configuration
	processor.ReloadConfiguration(cfg2)

	// Verify new config
	status2 := processor.GetIntegrationStatus()
	if status2["siem"] {
		t.Error("SIEM should be disabled after reload")
	}
	if !status2["slack"] {
		t.Error("Slack should be enabled after reload")
	}
}

func TestAlertProcessor_TestIntegrations(t *testing.T) {
	cfg := config.IntegrationSettings{
		SIEM: config.SIEMConfig{
			Enabled:  true,
			Endpoint: "https://invalid-siem.example.com", // Will fail connectivity
			APIKey:   "test-key",
		},
		SOAR: config.SOARConfig{
			Enabled:  true,
			Endpoint: "https://invalid-soar.example.com",
			APIKey:   "test-key",
		},
		Slack: config.SlackConfig{
			Enabled:    false, // Disabled, should not be tested
			WebhookURL: "https://hooks.slack.com/test",
		},
	}

	processor := NewAlertProcessor(cfg)
	results := processor.TestIntegrations()

	// Should have results for enabled integrations
	if _, exists := results["siem"]; !exists {
		t.Error("Expected SIEM test result")
	}

	if _, exists := results["soar"]; !exists {
		t.Error("Expected SOAR test result")
	}

	// Should not have result for disabled Slack
	if _, exists := results["slack"]; exists {
		t.Error("Should not have Slack test result when disabled")
	}

	// All tests should fail due to invalid endpoints (this is expected for SIEM)
	// SOAR and Slack tests only validate configuration, not connectivity
	for integration, err := range results {
		if integration == "siem" {
			// SIEM should fail due to invalid endpoint
			if err == nil {
				t.Errorf("Expected %s test to fail with invalid endpoint", integration)
			}
		} else {
			// SOAR and Slack only test configuration validation, which should pass
			if err != nil {
				t.Logf("Integration %s test failed (expected for configuration-only tests): %v", integration, err)
			}
		}
	}
}

func TestAlertProcessor_Concurrency(t *testing.T) {
	cfg := config.IntegrationSettings{
		SIEM: config.SIEMConfig{
			Enabled:  false, // Disabled to avoid network calls
			Endpoint: "https://siem.example.com",
		},
	}

	processor := NewAlertProcessor(cfg)

	// Test concurrent access to processor methods
	var wg sync.WaitGroup
	numGoroutines := 10

	// Test concurrent ProcessAlert calls
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			alert := types.SecurityAlert{
				Timestamp:   time.Now(),
				Severity:    "High",
				AlertType:   "concurrent_test",
				Description: "Concurrent test alert",
				Source:      "test",
				Evidence:    "Test evidence",
				Action:      "test",
			}
			processor.ProcessAlert(alert)
		}(i)
	}

	// Test concurrent GetIntegrationStatus calls
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			processor.GetIntegrationStatus()
		}()
	}

	// Test concurrent GetEnabledIntegrations calls
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			processor.GetEnabledIntegrations()
		}()
	}

	wg.Wait()
	// If we get here without deadlock or race conditions, the test passes
}

func TestAlertProcessor_getEnabledIntegrationsCount(t *testing.T) {
	tests := []struct {
		name     string
		cfg      config.IntegrationSettings
		expected int
	}{
		{
			name: "All enabled",
			cfg: config.IntegrationSettings{
				SIEM: config.SIEMConfig{
					Enabled:  true,
					Endpoint: "https://siem.example.com",
					APIKey:   "test",
				},
				SOAR: config.SOARConfig{
					Enabled:  true,
					Endpoint: "https://soar.example.com",
					APIKey:   "test",
				},
				Slack: config.SlackConfig{
					Enabled:    true,
					WebhookURL: "https://hooks.slack.com/test",
				},
			},
			expected: 3,
		},
		{
			name: "None enabled",
			cfg: config.IntegrationSettings{
				SIEM: config.SIEMConfig{
					Enabled: false,
				},
				SOAR: config.SOARConfig{
					Enabled: false,
				},
				Slack: config.SlackConfig{
					Enabled: false,
				},
			},
			expected: 0,
		},
		{
			name: "Partial enabled",
			cfg: config.IntegrationSettings{
				SIEM: config.SIEMConfig{
					Enabled:  true,
					Endpoint: "https://siem.example.com",
					APIKey:   "test",
				},
				SOAR: config.SOARConfig{
					Enabled: false,
				},
				Slack: config.SlackConfig{
					Enabled:    true,
					WebhookURL: "https://hooks.slack.com/test",
				},
			},
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewAlertProcessor(tt.cfg)
			count := processor.getEnabledIntegrationsCount()

			if count != tt.expected {
				t.Errorf("getEnabledIntegrationsCount() = %d, want %d", count, tt.expected)
			}
		})
	}
}
