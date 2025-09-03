package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	// Test loading default configuration
	config, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("Failed to load default config: %v", err)
	}

	// Verify default values are set
	if config.Scanner.PolicyDirectory == "" {
		t.Error("Expected policy directory to be set")
	}

	if config.Scanner.Timeout <= 0 {
		t.Error("Expected timeout to be positive")
	}

	if config.Proxy.Port <= 0 {
		t.Error("Expected proxy port to be positive")
	}
}

func TestEnvironmentVariableSubstitution(t *testing.T) {
	// Set test environment variables
	os.Setenv("TEST_API_KEY", "test-key-123")
	os.Setenv("TEST_ENDPOINT", "https://api.example.com")
	defer os.Unsetenv("TEST_API_KEY")
	defer os.Unsetenv("TEST_ENDPOINT")

	testCases := []struct {
		input    string
		expected string
	}{
		{"${TEST_API_KEY}", "test-key-123"},
		{"${TEST_ENDPOINT}/v1", "https://api.example.com/v1"},
		{"${UNDEFINED_VAR:default_value}", "default_value"},
		{"${UNDEFINED_VAR}", "${UNDEFINED_VAR}"}, // Should remain unchanged
		{"normal text", "normal text"},
	}

	for _, tc := range testCases {
		result := substituteEnvVars(tc.input)
		if result != tc.expected {
			t.Errorf("substituteEnvVars(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
}

func TestValidateConfig(t *testing.T) {
	validConfig := &AppConfig{
		Scanner: ScannerSettings{
			PolicyDirectory: "./policies",
			Timeout:         30 * time.Second,
			MaxRetries:      3,
		},
		Proxy: ProxySettings{
			Port: 8080,
		},
	}

	// Test valid configuration
	if err := validateConfig(validConfig); err != nil {
		t.Errorf("Expected valid config to pass validation, got: %v", err)
	}

	// Test invalid policy directory
	invalidConfig := *validConfig
	invalidConfig.Scanner.PolicyDirectory = ""
	if err := validateConfig(&invalidConfig); err == nil {
		t.Error("Expected empty policy directory to fail validation")
	}

	// Test invalid timeout
	invalidConfig = *validConfig
	invalidConfig.Scanner.Timeout = 0
	if err := validateConfig(&invalidConfig); err == nil {
		t.Error("Expected zero timeout to fail validation")
	}

	// Test invalid port
	invalidConfig = *validConfig
	invalidConfig.Proxy.Port = 0
	if err := validateConfig(&invalidConfig); err == nil {
		t.Error("Expected zero port to fail validation")
	}
}

func TestToScannerConfig(t *testing.T) {
	appConfig := &AppConfig{
		Scanner: ScannerSettings{
			PolicyDirectory: "./test-policies",
			Timeout:         45 * time.Second,
			MaxRetries:      5,
			UserAgent:       "Test-Agent/1.0",
			LogLevel:        "DEBUG",
			Output: OutputConfig{
				DefaultFormat: "json",
			},
		},
		Proxy: ProxySettings{
			Port: 9090,
		},
	}

	scannerConfig := appConfig.ToScannerConfig()

	// Verify conversion
	if scannerConfig.PolicyDirectory != "./test-policies" {
		t.Errorf("Expected policy directory './test-policies', got %q", scannerConfig.PolicyDirectory)
	}

	if scannerConfig.Timeout != 45*time.Second {
		t.Errorf("Expected timeout 45s, got %v", scannerConfig.Timeout)
	}

	if scannerConfig.MaxRetries != 5 {
		t.Errorf("Expected max retries 5, got %d", scannerConfig.MaxRetries)
	}

	if scannerConfig.UserAgent != "Test-Agent/1.0" {
		t.Errorf("Expected user agent 'Test-Agent/1.0', got %q", scannerConfig.UserAgent)
	}

	if scannerConfig.ProxyPort != 9090 {
		t.Errorf("Expected proxy port 9090, got %d", scannerConfig.ProxyPort)
	}
}

func TestGetConfigPath(t *testing.T) {
	// Test default path
	defaultPath := GetConfigPath()
	if !strings.HasSuffix(defaultPath, "configs/config.yaml") {
		t.Errorf("Expected default path to end with 'configs/config.yaml', got %q", defaultPath)
	}

	// Test environment variable override
	os.Setenv("MCP_SECURITY_CONFIG", "/custom/path/config.yaml")
	defer os.Unsetenv("MCP_SECURITY_CONFIG")

	customPath := GetConfigPath()
	if customPath != "/custom/path/config.yaml" {
		t.Errorf("Expected custom path '/custom/path/config.yaml', got %q", customPath)
	}
}
