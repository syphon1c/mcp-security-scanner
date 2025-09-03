package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/syphon1c/mcp-security-scanner/pkg/types"
	"gopkg.in/yaml.v3"
)

// AppConfig represents the complete application configuration
type AppConfig struct {
	Scanner     ScannerSettings     `yaml:"scanner"`
	Proxy       ProxySettings       `yaml:"proxy"`
	Integration IntegrationSettings `yaml:"integration"`
	Logging     LoggingSettings     `yaml:"logging"`
}

// ScannerSettings maps to scanner configuration section
type ScannerSettings struct {
	PolicyDirectory   string        `yaml:"policy_directory"`
	DefaultPolicy     string        `yaml:"default_policy"`
	MaxConcurrentJobs int           `yaml:"max_concurrent_jobs"`
	Timeout           time.Duration `yaml:"timeout"`
	MaxRetries        int           `yaml:"max_retries"`
	UserAgent         string        `yaml:"user_agent"`
	LogLevel          string        `yaml:"log_level"`
	Output            OutputConfig  `yaml:"output"`
}

// OutputConfig handles output format settings
type OutputConfig struct {
	DefaultFormat string `yaml:"default_format"`
	Directory     string `yaml:"directory"`
	FilenameBase  string `yaml:"filename_base"`
}

// ProxySettings handles proxy configuration
type ProxySettings struct {
	Host         string        `yaml:"host"`
	Port         int           `yaml:"port"`
	Timeout      time.Duration `yaml:"timeout"`
	MaxBufferMB  int           `yaml:"max_buffer_mb"`
	EnableTLS    bool          `yaml:"enable_tls"`
	CertFile     string        `yaml:"cert_file"`
	KeyFile      string        `yaml:"key_file"`
	AlertWebhook string        `yaml:"alert_webhook"`
}

// IntegrationSettings handles external system integrations
type IntegrationSettings struct {
	SIEM  SIEMConfig  `yaml:"siem"`
	SOAR  SOARConfig  `yaml:"soar"`
	Slack SlackConfig `yaml:"slack"`
}

// SIEMConfig handles SIEM integration
type SIEMConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
	APIKey   string `yaml:"api_key"`
	Index    string `yaml:"index"`
}

// SOARConfig handles SOAR integration
type SOARConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
	APIKey   string `yaml:"api_key"`
	Username string `yaml:"username"`
}

// SlackConfig handles Slack notifications
type SlackConfig struct {
	Enabled     bool   `yaml:"enabled"`
	WebhookURL  string `yaml:"webhook_url"`
	Channel     string `yaml:"channel"`
	Username    string `yaml:"username"`
	IconEmoji   string `yaml:"icon_emoji"`
	MinSeverity string `yaml:"min_severity"`
}

// LoggingSettings handles logging configuration
type LoggingSettings struct {
	Level      string `yaml:"level"`
	Format     string `yaml:"format"`
	Output     string `yaml:"output"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxBackups int    `yaml:"max_backups"`
	MaxAge     int    `yaml:"max_age"`
}

var (
	// Default configuration values
	defaultConfig = AppConfig{
		Scanner: ScannerSettings{
			PolicyDirectory:   "./policies",
			DefaultPolicy:     "standard-security",
			MaxConcurrentJobs: 5,
			Timeout:           30 * time.Second,
			MaxRetries:        3,
			UserAgent:         "MCP-Security-Scanner/1.0.0",
			LogLevel:          "INFO",
			Output: OutputConfig{
				DefaultFormat: "json",
				Directory:     "./reports",
				FilenameBase:  "mcp_security_report",
			},
		},
		Proxy: ProxySettings{
			Host:         "localhost",
			Port:         8080,
			Timeout:      30 * time.Second,
			MaxBufferMB:  10,
			EnableTLS:    false,
			AlertWebhook: "",
		},
		Integration: IntegrationSettings{
			SIEM: SIEMConfig{
				Enabled: false,
				Index:   "mcp-security",
			},
			SOAR: SOARConfig{
				Enabled: false,
			},
			Slack: SlackConfig{
				Enabled:     false,
				Channel:     "#security-alerts",
				Username:    "MCP Security Scanner",
				IconEmoji:   ":shield:",
				MinSeverity: "HIGH",
			},
		},
		Logging: LoggingSettings{
			Level:      "INFO",
			Format:     "json",
			Output:     "stdout",
			MaxSizeMB:  100,
			MaxBackups: 3,
			MaxAge:     30,
		},
	}

	// Regex pattern for environment variable substitution
	envVarPattern = regexp.MustCompile(`\$\{([^}]+)\}`)
)

// LoadConfig loads configuration from YAML file with environment variable substitution
func LoadConfig(configPath string) (*AppConfig, error) {
	// Start with default configuration
	config := defaultConfig

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Printf("⚠️  Configuration file not found: %s. Using defaults.\n", configPath)
		return &config, nil
	}

	// Read YAML file
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	// Substitute environment variables
	processedData := substituteEnvVars(string(data))

	// Parse YAML
	if err := yaml.Unmarshal([]byte(processedData), &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML config: %w", err)
	}

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &config, nil
}

// substituteEnvVars replaces ${VAR_NAME} patterns with environment variable values
func substituteEnvVars(content string) string {
	return envVarPattern.ReplaceAllStringFunc(content, func(match string) string {
		// Extract variable name (remove ${ and })
		varName := match[2 : len(match)-1]

		// Handle default values (VAR_NAME:default_value)
		parts := strings.SplitN(varName, ":", 2)
		envVar := parts[0]
		defaultVal := ""
		if len(parts) > 1 {
			defaultVal = parts[1]
		}

		// Get environment variable value
		if value := os.Getenv(envVar); value != "" {
			return value
		}

		// Return default value if provided, otherwise return original pattern
		if defaultVal != "" {
			return defaultVal
		}

		return match // Keep original if no value found and no default
	})
}

// validateConfig performs basic validation on loaded configuration
func validateConfig(config *AppConfig) error {
	// Validate scanner settings
	if config.Scanner.PolicyDirectory == "" {
		return fmt.Errorf("scanner.policy_directory cannot be empty")
	}

	if config.Scanner.Timeout <= 0 {
		return fmt.Errorf("scanner.timeout must be positive")
	}

	if config.Scanner.MaxRetries < 0 {
		return fmt.Errorf("scanner.max_retries cannot be negative")
	}

	// Validate proxy settings
	if config.Proxy.Port <= 0 || config.Proxy.Port > 65535 {
		return fmt.Errorf("proxy.port must be between 1 and 65535")
	}

	// Validate TLS settings if enabled
	if config.Proxy.EnableTLS {
		if config.Proxy.CertFile == "" || config.Proxy.KeyFile == "" {
			return fmt.Errorf("proxy.cert_file and proxy.key_file required when TLS is enabled")
		}
	}

	// Validate output directory
	if config.Scanner.Output.Directory == "" {
		config.Scanner.Output.Directory = "./reports"
	}

	return nil
}

// ToScannerConfig converts AppConfig to types.ScannerConfig for backward compatibility
func (c *AppConfig) ToScannerConfig() types.ScannerConfig {
	return types.ScannerConfig{
		PolicyDirectory: c.Scanner.PolicyDirectory,
		Timeout:         c.Scanner.Timeout,
		MaxRetries:      c.Scanner.MaxRetries,
		UserAgent:       c.Scanner.UserAgent,
		LogLevel:        c.Scanner.LogLevel,
		OutputFormat:    c.Scanner.Output.DefaultFormat,
		EnableProxy:     false, // This will be set separately for proxy operations
		ProxyPort:       c.Proxy.Port,
	}
}

// GetConfigPath returns the default config path or user-specified path
func GetConfigPath() string {
	if configPath := os.Getenv("MCP_SECURITY_CONFIG"); configPath != "" {
		return configPath
	}
	return "./configs/config.yaml"
}

// LoadDefaultConfig loads configuration from the default location
func LoadDefaultConfig() (*AppConfig, error) {
	return LoadConfig(GetConfigPath())
}

// PrintConfigSummary displays a summary of loaded configuration (for debugging)
func PrintConfigSummary(config *AppConfig) {
	fmt.Printf("📋 Configuration Summary:\n")
	fmt.Printf("   Policy Directory: %s\n", config.Scanner.PolicyDirectory)
	fmt.Printf("   Default Policy: %s\n", config.Scanner.DefaultPolicy)
	fmt.Printf("   Scanner Timeout: %v\n", config.Scanner.Timeout)
	fmt.Printf("   Output Directory: %s\n", config.Scanner.Output.Directory)
	fmt.Printf("   Proxy Port: %d\n", config.Proxy.Port)

	if config.Integration.SIEM.Enabled {
		fmt.Printf("   SIEM Integration: Enabled (%s)\n", config.Integration.SIEM.Endpoint)
	}

	if config.Integration.Slack.Enabled {
		fmt.Printf("   Slack Notifications: Enabled\n")
	}
}
