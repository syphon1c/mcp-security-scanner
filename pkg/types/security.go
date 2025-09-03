package types

import (
	"regexp"
	"time"
)

// Core MCP Protocol Structures
type MCPMessage struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Method  string      `json:"method,omitempty"`
	Params  interface{} `json:"params,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *MCPError   `json:"error,omitempty"`
}

type MCPError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type MCPTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

type MCPResource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MimeType    string `json:"mimeType,omitempty"`
}

type MCPServerInfo struct {
	Name         string        `json:"name"`
	Version      string        `json:"version"`
	Protocol     string        `json:"protocol"`
	Capabilities []string      `json:"capabilities"`
	Tools        []MCPTool     `json:"tools"`
	Resources    []MCPResource `json:"resources"`
}

// Security Policy Structures
type SecurityPolicy struct {
	Version             string               `json:"version"`
	PolicyName          string               `json:"policyName"`
	Description         string               `json:"description"`
	Severity            string               `json:"severity"`
	Rules               []SecurityRule       `json:"rules"`
	BlockedPatterns     []BlockedPattern     `json:"blockedPatterns"`
	PolymorphicPatterns []PolymorphicPattern `json:"polymorphicPatterns,omitempty"`
	BehavioralPatterns  []BehavioralPattern  `json:"behavioralPatterns,omitempty"`
	AllowedTools        []string             `json:"allowedTools,omitempty"`
	RiskThresholds      RiskThresholds       `json:"riskThresholds"`
}

type SecurityRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Patterns    []string `json:"patterns"`
	Conditions  []string `json:"conditions"`
}

// PatternVariant represents a single pattern variant with optional weight and context
type PatternVariant struct {
	Pattern  string  `json:"pattern"`            // The regex pattern
	Weight   float64 `json:"weight,omitempty"`   // Weight for this pattern (default: 1.0)
	Context  string  `json:"context,omitempty"`  // Context hint for better detection
	Severity string  `json:"severity,omitempty"` // Override pattern severity if needed
}

// PolymorphicPattern represents a collection of pattern variants for detecting polymorphic attacks
type PolymorphicPattern struct {
	Name             string           `json:"name"`
	Description      string           `json:"description"`
	Severity         string           `json:"severity"`
	Category         string           `json:"category"`
	Variants         []string         `json:"variants,omitempty"`         // Legacy string array support
	WeightedVariants []PatternVariant `json:"weightedVariants,omitempty"` // Weighted variants
	Threshold        int              `json:"threshold"`                  // Minimum variants to trigger detection
	WeightThreshold  float64          `json:"weightThreshold,omitempty"`  // Minimum weighted score to trigger
	MaxMatches       int              `json:"maxMatches,omitempty"`       // Maximum matches to process (performance)
}

// PatternCache represents compiled regex patterns for performance optimization
type PatternCache struct {
	CompiledPatterns map[string]*regexp.Regexp // Pattern string -> compiled regex
	CacheHits        int64                     // Performance metrics
	CacheMisses      int64                     // Performance metrics
}

// PolymorphicMatchResult represents the result of polymorphic pattern matching
type PolymorphicMatchResult struct {
	PatternName     string         `json:"patternName"`
	TotalScore      float64        `json:"totalScore"`
	WeightedScore   float64        `json:"weightedScore"`
	MatchCount      int            `json:"matchCount"`
	MatchedVariants []VariantMatch `json:"matchedVariants"`
	Evidence        []string       `json:"evidence"`
	Confidence      float64        `json:"confidence"`
}

// VariantMatch represents a single variant match with its details
type VariantMatch struct {
	Pattern  string   `json:"pattern"`
	Weight   float64  `json:"weight"`
	Matches  []string `json:"matches"`
	Context  string   `json:"context,omitempty"`
	Severity string   `json:"severity,omitempty"`
}

type BehavioralPattern struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Patterns    []string `json:"patterns"`
	Threshold   int      `json:"threshold"` // Minimum pattern matches to trigger
}

type BlockedPattern struct {
	Pattern     string `json:"pattern"`
	Type        string `json:"type"` // "regex", "exact", "contains"
	Category    string `json:"category"`
	Description string `json:"description"`
}

type RiskThresholds struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// Scan Results
type ScanResult struct {
	Timestamp   time.Time     `json:"timestamp"`
	Target      string        `json:"target"`
	PolicyUsed  string        `json:"policyUsed"`
	OverallRisk string        `json:"overallRisk"`
	RiskScore   int           `json:"riskScore"`
	Findings    []Finding     `json:"findings"`
	MCPServer   MCPServerInfo `json:"mcpServer"`
	Summary     ScanSummary   `json:"summary"`
}

type Finding struct {
	ID          string    `json:"id"`
	RuleID      string    `json:"ruleId"`
	Severity    string    `json:"severity"`
	Category    string    `json:"category"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Evidence    string    `json:"evidence"`
	Location    string    `json:"location"`
	LineNumber  int       `json:"lineNumber,omitempty"`  // Line number where issue was found
	CodeLine    string    `json:"codeLine,omitempty"`    // The actual line of code
	CodeContext []string  `json:"codeContext,omitempty"` // Lines around the finding for context
	Remediation string    `json:"remediation"`
	Timestamp   time.Time `json:"timestamp"`
}

type ScanSummary struct {
	TotalFindings    int `json:"totalFindings"`
	CriticalFindings int `json:"criticalFindings"`
	HighFindings     int `json:"highFindings"`
	MediumFindings   int `json:"mediumFindings"`
	LowFindings      int `json:"lowFindings"`
}

// Configuration structures
type ScannerConfig struct {
	Timeout         time.Duration `json:"timeout"`
	MaxRetries      int           `json:"maxRetries"`
	UserAgent       string        `json:"userAgent"`
	EnableProxy     bool          `json:"enableProxy"`
	ProxyPort       int           `json:"proxyPort"`
	LogLevel        string        `json:"logLevel"`
	OutputFormat    string        `json:"outputFormat"`
	PolicyDirectory string        `json:"policyDirectory"`
}

// Proxy monitoring structures
type SecurityAlert struct {
	Timestamp   time.Time `json:"timestamp"`
	Severity    string    `json:"severity"`
	AlertType   string    `json:"alertType"`
	Description string    `json:"description"`
	Source      string    `json:"source"`
	Evidence    string    `json:"evidence"`
	Action      string    `json:"action"`
}

type ProxyLog struct {
	Timestamp time.Time     `json:"timestamp"`
	Method    string        `json:"method"`
	Request   interface{}   `json:"request"`
	Response  interface{}   `json:"response"`
	Duration  time.Duration `json:"duration"`
	Risk      string        `json:"risk"`
}
