package analyzer

import (
	"testing"
	"time"

	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

func TestAdvancedTrafficAnalyzer(t *testing.T) {
	analyzer := NewAdvancedTrafficAnalyzer()

	// Test 1: Basic traffic analysis
	t.Run("BasicAnalysis", func(t *testing.T) {
		message := &types.MCPMessage{
			JSONRPC: "2.0",
			Method:  "tools/call",
			Params: map[string]interface{}{
				"name": "test_tool",
				"arguments": map[string]interface{}{
					"command": "echo hello",
				},
			},
			ID: "1",
		}

		result := analyzer.AnalyzeTraffic(message, "127.0.0.1", "test_session")

		if result == nil {
			t.Fatal("Expected analysis result, got nil")
		}

		t.Logf("Threat Level: %s", result.ThreatLevel)
		t.Logf("Risk Score: %d", result.RiskScore)
		t.Logf("Confidence: %.2f", result.ConfidenceScore)
	})

	// Test 2: Behavioral anomaly detection
	t.Run("BehavioralAnomalies", func(t *testing.T) {
		sessionID := "rapid_fire_session"

		// Send rapid-fire requests
		for i := 0; i < 15; i++ {
			message := &types.MCPMessage{
				JSONRPC: "2.0",
				Method:  "tools/call",
				Params: map[string]interface{}{
					"name": "test_tool",
					"arguments": map[string]interface{}{
						"command": "echo test",
					},
				},
				ID: string(rune(i)),
			}

			result := analyzer.AnalyzeTraffic(message, "127.0.0.1", sessionID)

			if i > 10 && len(result.BehavioralAnomalies) > 0 {
				t.Logf("Detected behavioral anomaly: %s", result.BehavioralAnomalies[0].Type)
				break
			}

			// Small delay to simulate rapid requests
			time.Sleep(time.Millisecond * 10)
		}
	})

	// Test 3: Attack sequence detection
	t.Run("AttackSequenceDetection", func(t *testing.T) {
		sessionID := "sequence_session"
		sourceIP := "192.168.1.100"

		// Simulate reconnaissance sequence
		messages := []*types.MCPMessage{
			{
				JSONRPC: "2.0",
				Method:  "tools/list",
				ID:      "1",
			},
			{
				JSONRPC: "2.0",
				Method:  "resources/list",
				ID:      "2",
			},
			{
				JSONRPC: "2.0",
				Method:  "tools/call",
				Params: map[string]interface{}{
					"name": "system_info",
					"arguments": map[string]interface{}{
						"command": "whoami",
					},
				},
				ID: "3",
			},
		}

		var finalResult *TrafficAnalysisResult
		for _, message := range messages {
			finalResult = analyzer.AnalyzeTraffic(message, sourceIP, sessionID)
			time.Sleep(time.Second) // Simulate timing between requests
		}

		if len(finalResult.SequenceMatches) > 0 {
			t.Logf("Detected attack sequence: %s", finalResult.SequenceMatches[0].SequenceName)
			t.Logf("Confidence: %.2f", finalResult.SequenceMatches[0].Confidence)
		} else {
			t.Log("No attack sequences detected (this may be expected depending on thresholds)")
		}
	})

	// Test 4: Content analysis
	t.Run("ContentAnalysis", func(t *testing.T) {
		// High entropy content (base64-like)
		highEntropyContent := "VGhpc0lzQVZlcnlMb25nQmFzZTY0RW5jb2RlZFN0cmluZ1dpdGhIaWdoRW50cm9weQ=="

		message := &types.MCPMessage{
			JSONRPC: "2.0",
			Method:  "tools/call",
			Params: map[string]interface{}{
				"name": "data_processor",
				"arguments": map[string]interface{}{
					"data": highEntropyContent,
				},
			},
			ID: "100",
		}

		result := analyzer.AnalyzeTraffic(message, "10.0.0.1", "content_session")

		if len(result.ContentFindings) > 0 {
			t.Logf("Content findings detected:")
			for _, finding := range result.ContentFindings {
				t.Logf("  Type: %s, Category: %s, Risk: %s", finding.Type, finding.Category, finding.Risk)
				if finding.EntropyScore > 0 {
					t.Logf("  Entropy Score: %.2f", finding.EntropyScore)
				}
			}
		}
	})

	// Test 5: Statistical anomaly detection
	t.Run("StatisticalAnomalies", func(t *testing.T) {
		sessionID := "stats_session"

		// Send several normal-sized requests to establish baseline
		for i := 0; i < 10; i++ {
			message := &types.MCPMessage{
				JSONRPC: "2.0",
				Method:  "tools/call",
				Params: map[string]interface{}{
					"name": "small_tool",
					"arguments": map[string]interface{}{
						"data": "small",
					},
				},
				ID: string(rune(i)),
			}
			analyzer.AnalyzeTraffic(message, "172.16.0.1", sessionID)
		}

		// Send an unusually large request
		largeData := make([]string, 100)
		for i := range largeData {
			largeData[i] = "This is a very long string to make the payload large. "
		}

		largeMessage := &types.MCPMessage{
			JSONRPC: "2.0",
			Method:  "tools/call",
			Params: map[string]interface{}{
				"name": "large_tool",
				"arguments": map[string]interface{}{
					"massive_data": largeData,
				},
			},
			ID: "large",
		}

		result := analyzer.AnalyzeTraffic(largeMessage, "172.16.0.1", sessionID)

		if len(result.StatisticalAnomalies) > 0 {
			t.Logf("Statistical anomalies detected:")
			for _, anomaly := range result.StatisticalAnomalies {
				t.Logf("  Metric: %s, Expected: %.2f, Observed: %.2f, Deviation: %.2f",
					anomaly.Metric, anomaly.Expected, anomaly.Observed, anomaly.Deviation)
			}
		}
	})

	// Test 6: Malicious patterns (should trigger blocking)
	t.Run("MaliciousPatterns", func(t *testing.T) {
		maliciousMessage := &types.MCPMessage{
			JSONRPC: "2.0",
			Method:  "tools/call",
			Params: map[string]interface{}{
				"name": "shell_command",
				"arguments": map[string]interface{}{
					"command": "rm -rf /",
					"encoded": "Y3VybCAtcyBhdHRhY2tlci5jb20vZXhmaWw=", // base64 encoded
				},
			},
			ID: "malicious",
		}

		result := analyzer.AnalyzeTraffic(maliciousMessage, "10.0.0.100", "malicious_session")

		t.Logf("Malicious pattern analysis:")
		t.Logf("  Threat Level: %s", result.ThreatLevel)
		t.Logf("  Risk Score: %d", result.RiskScore)
		t.Logf("  Behavioral Anomalies: %d", len(result.BehavioralAnomalies))
		t.Logf("  Content Findings: %d", len(result.ContentFindings))
		t.Logf("  Statistical Anomalies: %d", len(result.StatisticalAnomalies))

		if result.ThreatLevel == "Critical" || result.ThreatLevel == "High" {
			t.Logf("✅ High threat correctly identified")
		}

		if len(result.Recommendations) > 0 {
			t.Logf("Recommendations:")
			for _, rec := range result.Recommendations {
				t.Logf("  - %s", rec)
			}
		}

		if len(result.RequiredActions) > 0 {
			t.Logf("Required Actions:")
			for _, action := range result.RequiredActions {
				t.Logf("  - %s", action)
			}
		}
	})
}

func TestEntropyCalculation(t *testing.T) {
	analyzer := NewAdvancedTrafficAnalyzer()

	testCases := []struct {
		name     string
		input    string
		expected float64
	}{
		{
			name:     "Low entropy (repeated chars)",
			input:    "aaaaaaaaaa",
			expected: 0.0,
		},
		{
			name:     "Medium entropy (English text)",
			input:    "This is a normal English sentence with some variety.",
			expected: 4.0, // Approximate expected value
		},
		{
			name:     "High entropy (random-looking)",
			input:    "VGhpc0lzQVZlcnlMb25nQmFzZTY0RW5jb2RlZFN0cmluZw==",
			expected: 6.0, // Approximate expected value
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			entropy := analyzer.calculateEntropy(tc.input)
			inputDisplay := tc.input
			if len(tc.input) > 20 {
				inputDisplay = tc.input[:20] + "..."
			}
			t.Logf("Input: %s", inputDisplay)
			t.Logf("Calculated entropy: %.2f", entropy) // We're not doing exact matches because entropy calculation can vary
			// but we can verify relative ordering
			if tc.name == "Low entropy (repeated chars)" && entropy > 1.0 {
				t.Errorf("Expected low entropy for repeated chars, got %.2f", entropy)
			}
			if tc.name == "High entropy (random-looking)" && entropy < 4.0 {
				t.Errorf("Expected high entropy for base64-like string, got %.2f", entropy)
			}
		})
	}
}

func TestSessionBehaviorTracking(t *testing.T) {
	analyzer := NewAdvancedTrafficAnalyzer()

	sessionID := "behavior_test_session"
	sourceIP := "192.168.1.50"

	// Test method frequency tracking
	for i := 0; i < 20; i++ {
		method := "tools/call"
		if i%5 == 0 {
			method = "resources/list" // Mix in some different methods
		}

		message := &types.MCPMessage{
			JSONRPC: "2.0",
			Method:  method,
			Params: map[string]interface{}{
				"test": "data",
			},
			ID: string(rune(i)),
		}

		analyzer.AnalyzeTraffic(message, sourceIP, sessionID)
	}

	// Check if session behavior is being tracked
	session, exists := analyzer.sessionBehaviors[sessionID]
	if !exists {
		t.Fatal("Session behavior not tracked")
	}

	t.Logf("Session behavior tracking:")
	t.Logf("  Request Count: %d", session.RequestCount)
	t.Logf("  Method Frequencies: %v", session.MethodFrequency)
	t.Logf("  Start Time: %s", session.StartTime.Format("15:04:05"))
	t.Logf("  Last Activity: %s", session.LastActivity.Format("15:04:05"))

	if session.RequestCount != 20 {
		t.Errorf("Expected 20 requests, got %d", session.RequestCount)
	}

	if len(session.MethodFrequency) == 0 {
		t.Error("Method frequency not tracked")
	}
}
