package analyzer

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

// AdvancedTrafficAnalyzer provides sophisticated traffic analysis capabilities
type AdvancedTrafficAnalyzer struct {
	// Behavioral tracking
	sessionBehaviors map[string]*SessionBehavior
	globalStatistics *GlobalStatistics

	// Pattern detection
	sequenceDetector *SequenceDetector
	anomalyDetector  *AnomalyDetector

	// Machine learning models (simple implementations)
	frequencyAnalyzer *FrequencyAnalyzer
	contentAnalyzer   *ContentAnalyzer
}

// SessionBehavior tracks per-session behavior patterns
type SessionBehavior struct {
	SessionID       string
	StartTime       time.Time
	LastActivity    time.Time
	RequestCount    int
	ErrorCount      int
	SuspiciousCount int

	// Pattern tracking
	MethodFrequency   map[string]int
	ParameterPatterns map[string][]string
	TimingPatterns    []time.Duration

	// Risk indicators
	RapidFireRequests     bool
	EscalatingActions     bool
	ReconnaissancePattern bool

	// Behavioral scores
	NormalityScore  float64
	ThreatScore     float64
	ConfidenceScore float64
}

// GlobalStatistics tracks system-wide patterns
type GlobalStatistics struct {
	TotalRequests    int64
	UniqueSourceIPs  map[string]bool
	CommonMethods    map[string]int64
	ErrorRates       map[string]float64
	PeakTrafficHours map[int]int64

	// Baseline establishment
	BaselineEstablished bool
	NormalRequestRate   float64
	NormalMethodMix     map[string]float64
	NormalTimingProfile map[string]time.Duration
}

// SequenceDetector identifies suspicious request sequences
type SequenceDetector struct {
	KnownAttackSequences []AttackSequence
	RecentRequests       []TimestampedRequest
	MaxHistorySize       int
}

// AttackSequence defines a known attack pattern sequence
type AttackSequence struct {
	Name        string
	Description string
	Pattern     []SequenceStep
	Severity    string
	Confidence  float64
}

// SequenceStep represents one step in an attack sequence
type SequenceStep struct {
	Method     string
	Parameters map[string]string
	Timing     time.Duration
	Optional   bool
	Variations []string
}

// TimestampedRequest tracks request with timing information
type TimestampedRequest struct {
	Timestamp  time.Time
	Method     string
	Parameters map[string]interface{}
	SourceIP   string
	SessionID  string
	Response   *types.MCPMessage
}

// AnomalyDetector identifies statistical anomalies in traffic
type AnomalyDetector struct {
	// Statistical models
	RequestRateModel *StatisticalModel
	PayloadSizeModel *StatisticalModel
	TimingModel      *StatisticalModel
	ParameterModel   *StatisticalModel

	// Thresholds
	SigmaThreshold     float64
	ConfidenceInterval float64
}

// StatisticalModel provides basic statistical analysis
type StatisticalModel struct {
	Mean        float64
	StandardDev float64
	Min         float64
	Max         float64
	SampleCount int64
	Values      []float64
	MaxSamples  int
}

// FrequencyAnalyzer provides frequency-based analysis
type FrequencyAnalyzer struct {
	MethodFrequencies    map[string]*FrequencyStats
	ParameterFrequencies map[string]*FrequencyStats
	NGramAnalyzer        *NGramAnalyzer
}

// FrequencyStats tracks frequency statistics
type FrequencyStats struct {
	Count     int64
	FirstSeen time.Time
	LastSeen  time.Time
	Frequency float64
	Trend     string // "increasing", "decreasing", "stable"
}

// NGramAnalyzer provides n-gram analysis for content patterns
type NGramAnalyzer struct {
	UnigramFreqs map[string]int
	BigramFreqs  map[string]int
	TrigramFreqs map[string]int
	MaxNGrams    int
}

// ContentAnalyzer provides sophisticated content analysis
type ContentAnalyzer struct {
	// Entropy analysis
	EntropyThreshold float64

	// Pattern libraries
	EncodingPatterns    map[string]*regexp.Regexp
	ObfuscationPatterns map[string]*regexp.Regexp
	PayloadPatterns     map[string]*regexp.Regexp

	// Content classification
	ContentClassifier *ContentClassifier
}

// ContentClassifier classifies content into categories
type ContentClassifier struct {
	Categories map[string]*ContentCategory
}

// ContentCategory defines content classification rules
type ContentCategory struct {
	Name       string
	Patterns   []string
	Weight     float64
	RiskLevel  string
	Indicators []string
}

// TrafficAnalysisResult contains comprehensive analysis results
type TrafficAnalysisResult struct {
	// Overall assessment
	ThreatLevel     string
	ConfidenceScore float64
	RiskScore       int

	// Specific findings
	BehavioralAnomalies  []BehavioralAnomaly
	SequenceMatches      []SequenceMatch
	StatisticalAnomalies []StatisticalAnomaly
	ContentFindings      []ContentFinding

	// Session analysis
	SessionRisk        map[string]float64
	SuspiciousSessions []string

	// Recommendations
	Recommendations []string
	RequiredActions []string
}

// BehavioralAnomaly represents detected behavioral anomalies
type BehavioralAnomaly struct {
	Type        string
	Description string
	Severity    string
	Evidence    interface{}
	SessionID   string
	Confidence  float64
}

// SequenceMatch represents detected attack sequence patterns
type SequenceMatch struct {
	SequenceName string
	Confidence   float64
	Steps        []string
	Timeline     []time.Time
	SessionID    string
	Severity     string
}

// StatisticalAnomaly represents statistical deviations
type StatisticalAnomaly struct {
	Metric       string
	Expected     float64
	Observed     float64
	Deviation    float64
	Significance string
	Context      string
}

// ContentFinding represents content analysis findings
type ContentFinding struct {
	Type         string
	Category     string
	Content      string
	EntropyScore float64
	Patterns     []string
	Risk         string
}

// NewAdvancedTrafficAnalyzer creates a new sophisticated traffic analyzer
func NewAdvancedTrafficAnalyzer() *AdvancedTrafficAnalyzer {
	analyzer := &AdvancedTrafficAnalyzer{
		sessionBehaviors: make(map[string]*SessionBehavior),
		globalStatistics: &GlobalStatistics{
			UniqueSourceIPs:     make(map[string]bool),
			CommonMethods:       make(map[string]int64),
			ErrorRates:          make(map[string]float64),
			PeakTrafficHours:    make(map[int]int64),
			NormalMethodMix:     make(map[string]float64),
			NormalTimingProfile: make(map[string]time.Duration),
		},
		sequenceDetector: &SequenceDetector{
			MaxHistorySize: 1000,
			RecentRequests: make([]TimestampedRequest, 0),
		},
		anomalyDetector: &AnomalyDetector{
			SigmaThreshold:     2.5,
			ConfidenceInterval: 0.95,
		},
		frequencyAnalyzer: &FrequencyAnalyzer{
			MethodFrequencies:    make(map[string]*FrequencyStats),
			ParameterFrequencies: make(map[string]*FrequencyStats),
			NGramAnalyzer: &NGramAnalyzer{
				UnigramFreqs: make(map[string]int),
				BigramFreqs:  make(map[string]int),
				TrigramFreqs: make(map[string]int),
				MaxNGrams:    10000,
			},
		},
		contentAnalyzer: &ContentAnalyzer{
			EntropyThreshold:    7.0, // High entropy threshold
			EncodingPatterns:    make(map[string]*regexp.Regexp),
			ObfuscationPatterns: make(map[string]*regexp.Regexp),
			PayloadPatterns:     make(map[string]*regexp.Regexp),
		},
	}

	// Initialize attack sequence detection
	analyzer.initializeAttackSequences()

	// Initialize content patterns
	analyzer.initializeContentPatterns()

	// Initialize statistical models
	analyzer.initializeStatisticalModels()

	return analyzer
}

// AnalyzeTraffic performs comprehensive traffic analysis
func (a *AdvancedTrafficAnalyzer) AnalyzeTraffic(message *types.MCPMessage, sourceIP, sessionID string) *TrafficAnalysisResult {
	result := &TrafficAnalysisResult{
		BehavioralAnomalies:  make([]BehavioralAnomaly, 0),
		SequenceMatches:      make([]SequenceMatch, 0),
		StatisticalAnomalies: make([]StatisticalAnomaly, 0),
		ContentFindings:      make([]ContentFinding, 0),
		SessionRisk:          make(map[string]float64),
		SuspiciousSessions:   make([]string, 0),
		Recommendations:      make([]string, 0),
		RequiredActions:      make([]string, 0),
	}

	// Update tracking
	a.updateSessionBehavior(message, sourceIP, sessionID)
	a.updateGlobalStatistics(message, sourceIP)
	a.updateSequenceHistory(message, sourceIP, sessionID)

	// Perform analysis
	result.BehavioralAnomalies = a.detectBehavioralAnomalies(sessionID)
	result.SequenceMatches = a.detectAttackSequences(sessionID)
	result.StatisticalAnomalies = a.detectStatisticalAnomalies(message)
	result.ContentFindings = a.analyzeContent(message)

	// Calculate overall assessment
	result.ThreatLevel, result.ConfidenceScore, result.RiskScore = a.calculateOverallThreat(result)

	// Generate recommendations
	result.Recommendations = a.generateRecommendations(result)
	result.RequiredActions = a.generateRequiredActions(result)

	return result
}

// calculateEntropy calculates Shannon entropy of content
func (a *AdvancedTrafficAnalyzer) calculateEntropy(content string) float64 {
	if len(content) == 0 {
		return 0
	}

	frequency := make(map[rune]int)
	for _, char := range content {
		frequency[char]++
	}

	entropy := 0.0
	length := float64(len(content))

	for _, freq := range frequency {
		probability := float64(freq) / length
		if probability > 0 {
			entropy -= probability * math.Log2(probability)
		}
	}

	return entropy
}

// initializeAttackSequences sets up known attack sequence patterns
func (a *AdvancedTrafficAnalyzer) initializeAttackSequences() {
	a.sequenceDetector.KnownAttackSequences = []AttackSequence{
		{
			Name:        "Reconnaissance Sequence",
			Description: "Pattern indicating systematic reconnaissance",
			Severity:    "Medium",
			Confidence:  0.8,
			Pattern: []SequenceStep{
				{Method: "tools/list", Timing: time.Second * 5},
				{Method: "resources/list", Timing: time.Second * 3},
				{Method: "tools/call", Parameters: map[string]string{"name": ".*info.*"}, Timing: time.Second * 2},
			},
		},
		{
			Name:        "Privilege Escalation",
			Description: "Sequence suggesting privilege escalation attempt",
			Severity:    "High",
			Confidence:  0.9,
			Pattern: []SequenceStep{
				{Method: "tools/call", Parameters: map[string]string{"command": "whoami"}},
				{Method: "tools/call", Parameters: map[string]string{"command": "sudo.*"}},
				{Method: "tools/call", Parameters: map[string]string{"command": "su.*"}},
			},
		},
		{
			Name:        "Data Exfiltration",
			Description: "Pattern indicating potential data exfiltration",
			Severity:    "Critical",
			Confidence:  0.85,
			Pattern: []SequenceStep{
				{Method: "resources/read", Parameters: map[string]string{"uri": ".*config.*"}},
				{Method: "resources/read", Parameters: map[string]string{"uri": ".*secret.*"}},
				{Method: "tools/call", Parameters: map[string]string{"command": ".*curl.*|.*wget.*"}},
			},
		},
	}
}

// initializeContentPatterns sets up content analysis patterns
func (a *AdvancedTrafficAnalyzer) initializeContentPatterns() {
	// Encoding detection patterns
	a.contentAnalyzer.EncodingPatterns["base64"] = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	a.contentAnalyzer.EncodingPatterns["hex"] = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	a.contentAnalyzer.EncodingPatterns["url"] = regexp.MustCompile(`%[0-9a-fA-F]{2}`)

	// Obfuscation patterns
	a.contentAnalyzer.ObfuscationPatterns["unicode"] = regexp.MustCompile(`\\u[0-9a-fA-F]{4}`)
	a.contentAnalyzer.ObfuscationPatterns["escaped"] = regexp.MustCompile(`\\[x][0-9a-fA-F]{2}`)
	a.contentAnalyzer.ObfuscationPatterns["concatenation"] = regexp.MustCompile(`\+\s*"|\"\s*\+`)

	// Payload patterns
	a.contentAnalyzer.PayloadPatterns["shellcode"] = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	a.contentAnalyzer.PayloadPatterns["script_injection"] = regexp.MustCompile(`<script|javascript:|data:text/html`)
	a.contentAnalyzer.PayloadPatterns["command_injection"] = regexp.MustCompile(`[;&|]\s*(cat|ls|dir|whoami|id)`)
}

// initializeStatisticalModels sets up statistical analysis models
func (a *AdvancedTrafficAnalyzer) initializeStatisticalModels() {
	a.anomalyDetector.RequestRateModel = &StatisticalModel{MaxSamples: 1000, Values: make([]float64, 0)}
	a.anomalyDetector.PayloadSizeModel = &StatisticalModel{MaxSamples: 1000, Values: make([]float64, 0)}
	a.anomalyDetector.TimingModel = &StatisticalModel{MaxSamples: 1000, Values: make([]float64, 0)}
	a.anomalyDetector.ParameterModel = &StatisticalModel{MaxSamples: 1000, Values: make([]float64, 0)}
}

// Additional methods would continue here for the complete implementation...
// This is a comprehensive foundation for sophisticated traffic analysis

// updateSessionBehavior updates behavioral tracking for a session
func (a *AdvancedTrafficAnalyzer) updateSessionBehavior(message *types.MCPMessage, sourceIP, sessionID string) {
	if _, exists := a.sessionBehaviors[sessionID]; !exists {
		a.sessionBehaviors[sessionID] = &SessionBehavior{
			SessionID:         sessionID,
			StartTime:         time.Now(),
			MethodFrequency:   make(map[string]int),
			ParameterPatterns: make(map[string][]string),
			TimingPatterns:    make([]time.Duration, 0),
		}
	}

	session := a.sessionBehaviors[sessionID]
	session.LastActivity = time.Now()
	session.RequestCount++

	if message.Method != "" {
		session.MethodFrequency[message.Method]++
	}

	// Analyze request timing patterns
	if len(session.TimingPatterns) > 0 {
		timeSinceLastRequest := time.Since(session.LastActivity)
		session.TimingPatterns = append(session.TimingPatterns, timeSinceLastRequest)

		// Detect rapid-fire requests (less than 100ms between requests)
		if timeSinceLastRequest < time.Millisecond*100 {
			session.RapidFireRequests = true
		}
	}
}

// updateGlobalStatistics updates system-wide statistics
func (a *AdvancedTrafficAnalyzer) updateGlobalStatistics(message *types.MCPMessage, sourceIP string) {
	a.globalStatistics.TotalRequests++
	a.globalStatistics.UniqueSourceIPs[sourceIP] = true

	if message.Method != "" {
		a.globalStatistics.CommonMethods[message.Method]++
	}

	// Track peak traffic hours
	currentHour := time.Now().Hour()
	a.globalStatistics.PeakTrafficHours[currentHour]++
}

// updateSequenceHistory maintains request sequence history
func (a *AdvancedTrafficAnalyzer) updateSequenceHistory(message *types.MCPMessage, sourceIP, sessionID string) {
	var params map[string]interface{}
	if message.Params != nil {
		if p, ok := message.Params.(map[string]interface{}); ok {
			params = p
		}
	}
	if params == nil {
		params = make(map[string]interface{})
	}

	request := TimestampedRequest{
		Timestamp:  time.Now(),
		Method:     message.Method,
		Parameters: params,
		SourceIP:   sourceIP,
		SessionID:  sessionID,
	}

	a.sequenceDetector.RecentRequests = append(a.sequenceDetector.RecentRequests, request)

	// Maintain maximum history size
	if len(a.sequenceDetector.RecentRequests) > a.sequenceDetector.MaxHistorySize {
		a.sequenceDetector.RecentRequests = a.sequenceDetector.RecentRequests[1:]
	}
}

// detectBehavioralAnomalies identifies unusual behavioral patterns
func (a *AdvancedTrafficAnalyzer) detectBehavioralAnomalies(sessionID string) []BehavioralAnomaly {
	anomalies := make([]BehavioralAnomaly, 0)

	session, exists := a.sessionBehaviors[sessionID]
	if !exists {
		return anomalies
	}

	// Check for rapid-fire requests
	if session.RapidFireRequests {
		anomalies = append(anomalies, BehavioralAnomaly{
			Type:        "RapidFire",
			Description: "Unusually rapid request sequence detected",
			Severity:    "Medium",
			SessionID:   sessionID,
			Confidence:  0.8,
			Evidence:    session.TimingPatterns,
		})
	}

	// Check for method frequency anomalies
	totalRequests := session.RequestCount
	for method, count := range session.MethodFrequency {
		frequency := float64(count) / float64(totalRequests)

		// Flag if a single method comprises more than 80% of requests
		if frequency > 0.8 && totalRequests > 10 {
			anomalies = append(anomalies, BehavioralAnomaly{
				Type:        "MethodDomination",
				Description: fmt.Sprintf("Method '%s' dominates session requests", method),
				Severity:    "Medium",
				SessionID:   sessionID,
				Confidence:  0.7,
				Evidence:    map[string]interface{}{"method": method, "frequency": frequency},
			})
		}
	}

	return anomalies
}

// detectAttackSequences identifies known attack patterns in request sequences
func (a *AdvancedTrafficAnalyzer) detectAttackSequences(sessionID string) []SequenceMatch {
	matches := make([]SequenceMatch, 0)

	// Get recent requests for this session
	sessionRequests := make([]TimestampedRequest, 0)
	for _, req := range a.sequenceDetector.RecentRequests {
		if req.SessionID == sessionID {
			sessionRequests = append(sessionRequests, req)
		}
	}

	// Check each known attack sequence
	for _, sequence := range a.sequenceDetector.KnownAttackSequences {
		if match := a.matchSequence(sequence, sessionRequests); match != nil {
			matches = append(matches, *match)
		}
	}

	return matches
}

// matchSequence checks if a request sequence matches a known attack pattern
func (a *AdvancedTrafficAnalyzer) matchSequence(sequence AttackSequence, requests []TimestampedRequest) *SequenceMatch {
	if len(requests) < len(sequence.Pattern) {
		return nil
	}

	// Simple pattern matching implementation
	// In a real implementation, this would be more sophisticated
	matchedSteps := make([]string, 0)
	timeline := make([]time.Time, 0)

	stepIndex := 0
	for _, request := range requests {
		if stepIndex >= len(sequence.Pattern) {
			break
		}

		step := sequence.Pattern[stepIndex]

		// Check method match
		if step.Method != "" && request.Method == step.Method {
			matchedSteps = append(matchedSteps, request.Method)
			timeline = append(timeline, request.Timestamp)
			stepIndex++
		}
	}

	// Consider it a match if we found most of the steps
	if len(matchedSteps) >= len(sequence.Pattern)*2/3 {
		return &SequenceMatch{
			SequenceName: sequence.Name,
			Confidence:   sequence.Confidence * (float64(len(matchedSteps)) / float64(len(sequence.Pattern))),
			Steps:        matchedSteps,
			Timeline:     timeline,
			Severity:     sequence.Severity,
		}
	}

	return nil
}

// detectStatisticalAnomalies identifies statistical deviations from normal patterns
func (a *AdvancedTrafficAnalyzer) detectStatisticalAnomalies(message *types.MCPMessage) []StatisticalAnomaly {
	anomalies := make([]StatisticalAnomaly, 0)

	// Analyze payload size
	messageBytes, _ := json.Marshal(message)
	payloadSize := float64(len(messageBytes))

	if a.anomalyDetector.PayloadSizeModel.SampleCount > 10 {
		deviation := math.Abs(payloadSize - a.anomalyDetector.PayloadSizeModel.Mean)
		if a.anomalyDetector.PayloadSizeModel.StandardDev > 0 {
			sigmaDeviation := deviation / a.anomalyDetector.PayloadSizeModel.StandardDev

			if sigmaDeviation > a.anomalyDetector.SigmaThreshold {
				anomalies = append(anomalies, StatisticalAnomaly{
					Metric:       "PayloadSize",
					Expected:     a.anomalyDetector.PayloadSizeModel.Mean,
					Observed:     payloadSize,
					Deviation:    sigmaDeviation,
					Significance: "High",
					Context:      "Unusual message size detected",
				})
			}
		}
	}

	// Update the model with new data
	a.updateStatisticalModel(a.anomalyDetector.PayloadSizeModel, payloadSize)

	return anomalies
}

// updateStatisticalModel updates a statistical model with new data point
func (a *AdvancedTrafficAnalyzer) updateStatisticalModel(model *StatisticalModel, value float64) {
	model.Values = append(model.Values, value)
	model.SampleCount++

	// Maintain maximum sample size
	if len(model.Values) > model.MaxSamples {
		model.Values = model.Values[1:]
	}

	// Recalculate statistics
	if len(model.Values) > 0 {
		sum := 0.0
		model.Min = model.Values[0]
		model.Max = model.Values[0]

		for _, v := range model.Values {
			sum += v
			if v < model.Min {
				model.Min = v
			}
			if v > model.Max {
				model.Max = v
			}
		}

		model.Mean = sum / float64(len(model.Values))

		// Calculate standard deviation
		varianceSum := 0.0
		for _, v := range model.Values {
			diff := v - model.Mean
			varianceSum += diff * diff
		}
		variance := varianceSum / float64(len(model.Values))
		model.StandardDev = math.Sqrt(variance)
	}
}

// analyzeContent performs sophisticated content analysis
func (a *AdvancedTrafficAnalyzer) analyzeContent(message *types.MCPMessage) []ContentFinding {
	findings := make([]ContentFinding, 0)

	// Convert message to string for analysis
	messageBytes, _ := json.Marshal(message)
	content := string(messageBytes)

	// Entropy analysis
	entropy := a.calculateEntropy(content)
	if entropy > a.contentAnalyzer.EntropyThreshold {
		findings = append(findings, ContentFinding{
			Type:         "HighEntropy",
			Category:     "Encoding",
			Content:      content[:min(100, len(content))], // First 100 chars
			EntropyScore: entropy,
			Risk:         "Medium",
		})
	}

	// Pattern analysis
	for patternType, pattern := range a.contentAnalyzer.EncodingPatterns {
		if pattern.MatchString(content) {
			findings = append(findings, ContentFinding{
				Type:     "EncodedContent",
				Category: patternType,
				Content:  content[:min(100, len(content))],
				Patterns: []string{patternType},
				Risk:     "Low",
			})
		}
	}

	for patternType, pattern := range a.contentAnalyzer.ObfuscationPatterns {
		if pattern.MatchString(content) {
			findings = append(findings, ContentFinding{
				Type:     "ObfuscatedContent",
				Category: patternType,
				Content:  content[:min(100, len(content))],
				Patterns: []string{patternType},
				Risk:     "Medium",
			})
		}
	}

	for patternType, pattern := range a.contentAnalyzer.PayloadPatterns {
		if pattern.MatchString(content) {
			findings = append(findings, ContentFinding{
				Type:     "SuspiciousPayload",
				Category: patternType,
				Content:  content[:min(100, len(content))],
				Patterns: []string{patternType},
				Risk:     "High",
			})
		}
	}

	return findings
}

// calculateOverallThreat calculates overall threat assessment
func (a *AdvancedTrafficAnalyzer) calculateOverallThreat(result *TrafficAnalysisResult) (string, float64, int) {
	riskScore := 0
	confidenceScore := 0.0
	totalFindings := 0

	// Score behavioral anomalies
	for _, anomaly := range result.BehavioralAnomalies {
		switch anomaly.Severity {
		case "Critical":
			riskScore += 50
		case "High":
			riskScore += 30
		case "Medium":
			riskScore += 15
		case "Low":
			riskScore += 5
		}
		confidenceScore += anomaly.Confidence
		totalFindings++
	}

	// Score sequence matches
	for _, match := range result.SequenceMatches {
		switch match.Severity {
		case "Critical":
			riskScore += 40
		case "High":
			riskScore += 25
		case "Medium":
			riskScore += 10
		}
		confidenceScore += match.Confidence
		totalFindings++
	}

	// Score content findings
	for _, finding := range result.ContentFindings {
		switch finding.Risk {
		case "High":
			riskScore += 20
		case "Medium":
			riskScore += 10
		case "Low":
			riskScore += 3
		}
		totalFindings++
	}

	// Calculate average confidence
	if totalFindings > 0 {
		confidenceScore /= float64(totalFindings)
	}

	// Determine threat level
	threatLevel := "Minimal"
	if riskScore >= 50 {
		threatLevel = "Critical"
	} else if riskScore >= 30 {
		threatLevel = "High"
	} else if riskScore >= 15 {
		threatLevel = "Medium"
	} else if riskScore >= 5 {
		threatLevel = "Low"
	}

	return threatLevel, confidenceScore, riskScore
}

// generateRecommendations generates actionable recommendations
func (a *AdvancedTrafficAnalyzer) generateRecommendations(result *TrafficAnalysisResult) []string {
	recommendations := make([]string, 0)

	if len(result.BehavioralAnomalies) > 0 {
		recommendations = append(recommendations, "Implement rate limiting to prevent rapid-fire requests")
		recommendations = append(recommendations, "Consider implementing CAPTCHA for suspicious sessions")
	}

	if len(result.SequenceMatches) > 0 {
		recommendations = append(recommendations, "Review and strengthen access controls")
		recommendations = append(recommendations, "Implement sequence-based blocking rules")
	}

	if len(result.ContentFindings) > 0 {
		recommendations = append(recommendations, "Enhance input validation and sanitization")
		recommendations = append(recommendations, "Consider implementing content filtering")
	}

	return recommendations
}

// generateRequiredActions generates required immediate actions
func (a *AdvancedTrafficAnalyzer) generateRequiredActions(result *TrafficAnalysisResult) []string {
	actions := make([]string, 0)

	if result.ThreatLevel == "Critical" {
		actions = append(actions, "IMMEDIATE: Block source IP address")
		actions = append(actions, "IMMEDIATE: Notify security team")
		actions = append(actions, "IMMEDIATE: Review all recent activity from this source")
	}

	if result.ThreatLevel == "High" {
		actions = append(actions, "Increase monitoring for this session")
		actions = append(actions, "Consider temporary restrictions")
	}

	return actions
}

// Helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
