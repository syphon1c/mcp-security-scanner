package reporting

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
	"github.com/syphon1c/mcp-security-scanner/pkg/types"
)

// PDFReporter with professional visual design
type PDFReporter struct {
	pdf *gofpdf.Fpdf
}

// NewPDFReporter creates a new PDF reporter
func NewPDFReporter() (*PDFReporter, error) {
	return &PDFReporter{}, nil
}

// GenerateReport generates a PDF report
func (r *PDFReporter) GenerateReport(result *types.ScanResult, outputPath string) error {
	// Create output directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Initialize PDF with settings
	r.pdf = gofpdf.New("P", "mm", "A4", "")
	r.pdf.SetMargins(15, 20, 15)
	r.pdf.SetAutoPageBreak(true, 15)

	// Generate PDF content
	if err := r.generatePDFContent(result); err != nil {
		return fmt.Errorf("failed to generate PDF content: %w", err)
	}

	// Save PDF to file
	if err := r.pdf.OutputFileAndClose(outputPath); err != nil {
		return fmt.Errorf("failed to save PDF file: %w", err)
	}

	return nil
}

// generatePDFContent creates the PDF content
func (r *PDFReporter) generatePDFContent(result *types.ScanResult) error {
	// Add cover page with gradient header
	r.pdf.AddPage()
	r.addCoverPage(result)

	// Executive summary with visual elements
	r.pdf.AddPage()
	r.addExecutiveSummary(result)

	// Risk assessment with charts
	r.addRiskAssessment(result)

	// Detailed findings with layout
	if len(result.Findings) > 0 {
		r.pdf.AddPage()
		r.addDetailedFindings(result)
	}

	// Recommendations with visual hierarchy
	r.pdf.AddPage()
	r.addRecommendations(result)

	return nil
}

// addCoverPage creates a professional cover page
func (r *PDFReporter) addCoverPage(result *types.ScanResult) {
	// Add header background
	r.addHeaderBackground()

	// Title section
	r.pdf.SetFont("Arial", "B", 28)
	r.pdf.SetTextColor(255, 255, 255) // White text
	r.pdf.SetY(40)
	r.pdf.CellFormat(0, 15, "MCP Security Assessment", "", 1, "C", false, 0, "")

	r.pdf.SetFont("Arial", "", 18)
	r.pdf.SetY(60)
	r.pdf.CellFormat(0, 10, "Comprehensive Security Analysis Report", "", 1, "C", false, 0, "")

	// Reset text color
	r.pdf.SetTextColor(0, 0, 0)

	// Target information box
	r.addInfoBox("Target Information", 90, []string{
		fmt.Sprintf("Target: %s", result.Target),
		fmt.Sprintf("Policy: %s", result.PolicyUsed),
		fmt.Sprintf("Scan Date: %s", result.Timestamp.Format("2006-01-02 15:04:05")),
		fmt.Sprintf("Report Generated: %s", time.Now().Format("2006-01-02 15:04:05")),
	})

	// Risk overview box
	riskColor := r.getRiskColor(result.OverallRisk)
	r.addRiskOverviewBox(result, 150, riskColor)

	// Summary statistics
	r.addSummaryStatistics(result, 200)

	// Footer
	r.addFooter()
}

// addHeaderBackground creates a gradient-like header background
func (r *PDFReporter) addHeaderBackground() {
	// Dark header background
	r.pdf.SetFillColor(31, 41, 55) // Dark gray
	r.pdf.Rect(0, 0, 210, 80, "F")

	// Accent line
	r.pdf.SetFillColor(37, 99, 235) // Primary blue
	r.pdf.Rect(0, 76, 210, 4, "F")
}

// addInfoBox creates a styled information box
func (r *PDFReporter) addInfoBox(title string, y float64, items []string) {
	// Box background
	r.pdf.SetFillColor(249, 250, 251) // Light gray background
	r.pdf.SetDrawColor(229, 231, 235) // Border color
	r.pdf.Rect(20, y, 170, float64(len(items)*8+15), "FD")

	// Title
	r.pdf.SetFont("Arial", "B", 14)
	r.pdf.SetTextColor(55, 65, 81) // Dark gray
	r.pdf.SetXY(25, y+5)
	r.pdf.CellFormat(0, 8, title, "", 1, "L", false, 0, "")

	// Items
	r.pdf.SetFont("Arial", "", 11)
	r.pdf.SetTextColor(0, 0, 0)
	for i, item := range items {
		r.pdf.SetXY(25, y+15+float64(i*8))
		r.pdf.CellFormat(0, 6, item, "", 1, "L", false, 0, "")
	}
}

// addRiskOverviewBox creates a risk level overview with color coding
func (r *PDFReporter) addRiskOverviewBox(result *types.ScanResult, y float64, riskColor []int) {
	// Risk box background
	r.pdf.SetFillColor(riskColor[0], riskColor[1], riskColor[2])
	r.pdf.Rect(20, y, 170, 35, "F")

	// Risk level text
	r.pdf.SetFont("Arial", "B", 24)
	r.pdf.SetTextColor(255, 255, 255) // White text
	r.pdf.SetXY(25, y+8)
	r.pdf.CellFormat(0, 12, fmt.Sprintf("RISK LEVEL: %s", strings.ToUpper(result.OverallRisk)), "", 1, "C", false, 0, "")

	// Risk score
	r.pdf.SetFont("Arial", "B", 16)
	r.pdf.SetXY(25, y+22)
	r.pdf.CellFormat(0, 8, fmt.Sprintf("Risk Score: %d/100", result.RiskScore), "", 1, "C", false, 0, "")
}

// addSummaryStatistics creates a visual summary of findings
func (r *PDFReporter) addSummaryStatistics(result *types.ScanResult, y float64) {
	r.pdf.SetTextColor(0, 0, 0)
	r.pdf.SetFont("Arial", "B", 14)
	r.pdf.SetXY(20, y)
	r.pdf.CellFormat(0, 8, "Findings Summary", "", 1, "L", false, 0, "")

	// Create mini chart boxes for each severity
	boxWidth := 40.0
	boxHeight := 30.0
	startX := 25.0
	chartY := y + 15

	severities := []struct {
		name  string
		count int
		color []int
	}{
		{"Critical", result.Summary.CriticalFindings, []int{220, 38, 38}},
		{"High", result.Summary.HighFindings, []int{234, 88, 12}},
		{"Medium", result.Summary.MediumFindings, []int{217, 119, 6}},
		{"Low", result.Summary.LowFindings, []int{5, 150, 105}},
	}

	for i, sev := range severities {
		x := startX + float64(i)*boxWidth

		// Box background
		r.pdf.SetFillColor(sev.color[0], sev.color[1], sev.color[2])
		r.pdf.Rect(x, chartY, boxWidth-5, boxHeight, "F")

		// Count text
		r.pdf.SetFont("Arial", "B", 18)
		r.pdf.SetTextColor(255, 255, 255)
		r.pdf.SetXY(x, chartY+5)
		r.pdf.CellFormat(boxWidth-5, 10, fmt.Sprintf("%d", sev.count), "", 1, "C", false, 0, "")

		// Label
		r.pdf.SetFont("Arial", "", 10)
		r.pdf.SetXY(x, chartY+18)
		r.pdf.CellFormat(boxWidth-5, 6, sev.name, "", 1, "C", false, 0, "")
	}
}

// addExecutiveSummary creates the executive summary page
func (r *PDFReporter) addExecutiveSummary(result *types.ScanResult) {
	r.addPageHeader("Executive Summary")

	y := 40.0

	// Overview section
	r.addSectionHeader("Security Assessment Overview", y)
	y += 15

	overview := []string{
		fmt.Sprintf("Target System: %s", result.Target),
		fmt.Sprintf("Assessment Policy: %s", result.PolicyUsed),
		fmt.Sprintf("Total Security Findings: %d", result.Summary.TotalFindings),
		fmt.Sprintf("Overall Risk Rating: %s (%d/100)", result.OverallRisk, result.RiskScore),
	}

	for _, item := range overview {
		r.pdf.SetFont("Arial", "", 11)
		r.pdf.SetXY(20, y)
		r.pdf.CellFormat(0, 6, "• "+item, "", 1, "L", false, 0, "")
		y += 8
	}

	y += 10

	// Risk breakdown
	r.addSectionHeader("Risk Breakdown", y)
	y += 15

	if result.Summary.TotalFindings > 0 {
		// Create a visual risk breakdown chart
		r.addRiskBreakdownChart(result, y)
		y += 80
	} else {
		r.pdf.SetFont("Arial", "", 11)
		r.pdf.SetXY(20, y)
		r.pdf.CellFormat(0, 6, "No security vulnerabilities detected.", "", 1, "L", false, 0, "")
		y += 20
	}

	// Key recommendations
	r.addSectionHeader("Key Recommendations", y)
	y += 15

	recommendations := r.getKeyRecommendations(result)
	for i, rec := range recommendations {
		r.pdf.SetFont("Arial", "", 11)
		r.pdf.SetXY(20, y)
		r.pdf.CellFormat(0, 6, fmt.Sprintf("%d. %s", i+1, rec), "", 1, "L", false, 0, "")
		y += 8
	}
}

// addRiskBreakdownChart creates a visual chart for risk breakdown
func (r *PDFReporter) addRiskBreakdownChart(result *types.ScanResult, y float64) {
	total := float64(result.Summary.TotalFindings)
	if total == 0 {
		return
	}

	chartWidth := 170.0
	chartHeight := 20.0
	startX := 20.0

	// Calculate proportions
	criticalWidth := chartWidth * float64(result.Summary.CriticalFindings) / total
	highWidth := chartWidth * float64(result.Summary.HighFindings) / total
	mediumWidth := chartWidth * float64(result.Summary.MediumFindings) / total
	lowWidth := chartWidth * float64(result.Summary.LowFindings) / total

	currentX := startX

	// Draw segments
	segments := []struct {
		width float64
		color []int
		label string
		count int
	}{
		{criticalWidth, []int{220, 38, 38}, "Critical", result.Summary.CriticalFindings},
		{highWidth, []int{234, 88, 12}, "High", result.Summary.HighFindings},
		{mediumWidth, []int{217, 119, 6}, "Medium", result.Summary.MediumFindings},
		{lowWidth, []int{5, 150, 105}, "Low", result.Summary.LowFindings},
	}

	for _, seg := range segments {
		if seg.width > 0 {
			r.pdf.SetFillColor(seg.color[0], seg.color[1], seg.color[2])
			r.pdf.Rect(currentX, y, seg.width, chartHeight, "F")
			currentX += seg.width
		}
	}

	// Add legend
	legendY := y + 30
	legendX := startX
	for _, seg := range segments {
		if seg.count > 0 {
			// Color box
			r.pdf.SetFillColor(seg.color[0], seg.color[1], seg.color[2])
			r.pdf.Rect(legendX, legendY, 4, 4, "F")

			// Label
			r.pdf.SetFont("Arial", "", 10)
			r.pdf.SetTextColor(0, 0, 0)
			r.pdf.SetXY(legendX+6, legendY-1)
			r.pdf.CellFormat(0, 6, fmt.Sprintf("%s: %d", seg.label, seg.count), "", 0, "L", false, 0, "")

			legendX += 42
		}
	}
}

// addRiskAssessment creates a detailed risk assessment page
func (r *PDFReporter) addRiskAssessment(result *types.ScanResult) {
	if r.pdf.GetY() > 200 {
		r.pdf.AddPage()
	}

	r.addSectionHeader("Risk Assessment Matrix", r.pdf.GetY()+10)
	y := r.pdf.GetY() + 20

	// Risk matrix visualization
	r.addRiskMatrix(result, y)
}

// addRiskMatrix creates a visual risk assessment matrix
func (r *PDFReporter) addRiskMatrix(result *types.ScanResult, y float64) {
	matrixSize := 100.0
	cellSize := matrixSize / 4

	startX := 55.0

	// Matrix background
	r.pdf.SetFillColor(240, 240, 240)
	r.pdf.Rect(startX, y, matrixSize, matrixSize, "F")

	// Draw grid and color cells based on risk
	colors := [][]int{
		{5, 150, 105}, // Low (green)
		{217, 119, 6}, // Medium (yellow)
		{234, 88, 12}, // High (orange)
		{220, 38, 38}, // Critical (red)
	}

	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			x := startX + float64(i)*cellSize
			cellY := y + float64(j)*cellSize

			colorIndex := int(math.Min(3, float64(i+j)/2))
			r.pdf.SetFillColor(colors[colorIndex][0], colors[colorIndex][1], colors[colorIndex][2])
			r.pdf.SetDrawColor(200, 200, 200)
			r.pdf.Rect(x, cellY, cellSize, cellSize, "FD")
		}
	}

	// Add labels
	r.pdf.SetFont("Arial", "B", 10)
	r.pdf.SetTextColor(0, 0, 0)

	// Severity labels (vertical)
	labels := []string{"Low", "Medium", "High", "Critical"}
	for i, label := range labels {
		r.pdf.SetXY(30, y+float64(i)*cellSize+cellSize/2-2)
		r.pdf.CellFormat(20, 4, label, "", 0, "R", false, 0, "")
	}

	// Impact labels (horizontal)
	for i, label := range labels {
		r.pdf.SetXY(startX+float64(i)*cellSize+cellSize/2-10, y+matrixSize+5)
		r.pdf.CellFormat(20, 4, label, "", 0, "C", false, 0, "")
	}

	// Add axis titles
	r.pdf.SetFont("Arial", "B", 12)
	r.pdf.SetXY(10, y+matrixSize/2-3)
	r.pdf.CellFormat(15, 6, "Severity", "", 0, "C", false, 0, "")

	r.pdf.SetXY(startX+matrixSize/2-15, y+matrixSize+15)
	r.pdf.CellFormat(30, 6, "Impact", "", 0, "C", false, 0, "")
}

// addDetailedFindings creates the detailed findings section
func (r *PDFReporter) addDetailedFindings(result *types.ScanResult) {
	r.addPageHeader("Detailed Security Findings")

	for i, finding := range result.Findings {
		if r.pdf.GetY() > 240 {
			r.pdf.AddPage()
		}

		r.addFindingBox(i+1, finding)
		r.pdf.Ln(8)
	}
}

// addFindingBox creates a styled box for each finding
func (r *PDFReporter) addFindingBox(index int, finding types.Finding) {
	startY := r.pdf.GetY()

	// Get severity color
	severityColor := r.getSeverityColor(finding.Severity)

	// Severity header bar
	r.pdf.SetFillColor(severityColor[0], severityColor[1], severityColor[2])
	r.pdf.Rect(20, startY, 170, 8, "F")

	// Title with index
	r.pdf.SetFont("Arial", "B", 12)
	r.pdf.SetTextColor(255, 255, 255)
	r.pdf.SetXY(22, startY+1)
	r.pdf.CellFormat(0, 6, fmt.Sprintf("%d. %s [%s]", index, finding.Title, finding.Severity), "", 1, "L", false, 0, "")

	// Main content box
	r.pdf.SetFillColor(249, 250, 251)
	r.pdf.SetDrawColor(229, 231, 235)
	currentY := startY + 8

	// Content area
	r.pdf.SetTextColor(0, 0, 0)
	r.pdf.SetFont("Arial", "", 10)

	contentY := currentY + 3
	r.pdf.SetXY(22, contentY)

	// Category and location
	r.pdf.SetFont("Arial", "B", 9)
	r.pdf.Cell(0, 5, fmt.Sprintf("Category: %s", finding.Category))
	r.pdf.Ln(5)
	r.pdf.SetX(22)
	r.pdf.Cell(0, 5, fmt.Sprintf("Location: %s", finding.Location))

	if finding.LineNumber > 0 {
		r.pdf.Ln(5)
		r.pdf.SetX(22)
		r.pdf.Cell(0, 5, fmt.Sprintf("Line: %d", finding.LineNumber))
	}

	// Description
	r.pdf.Ln(7)
	r.pdf.SetX(22)
	r.pdf.SetFont("Arial", "", 9)
	descLines := r.wrapText(finding.Description, 160)
	for _, line := range descLines {
		r.pdf.Cell(0, 4, line)
		r.pdf.Ln(4)
		r.pdf.SetX(22)
	}

	// Evidence (if available)
	if finding.Evidence != "" {
		r.pdf.Ln(2)
		r.pdf.SetX(22)
		r.pdf.SetFont("Arial", "B", 9)
		r.pdf.Cell(0, 4, "Evidence:")
		r.pdf.Ln(4)
		r.pdf.SetX(22)
		r.pdf.SetFont("Arial", "", 8)
		r.pdf.SetTextColor(100, 100, 100)
		evidenceText := r.truncateText(finding.Evidence, 100)
		evidenceLines := r.wrapText(evidenceText, 160)
		for _, line := range evidenceLines {
			r.pdf.Cell(0, 4, line)
			r.pdf.Ln(4)
			r.pdf.SetX(22)
		}
	}

	// Calculate actual box height
	endY := r.pdf.GetY()
	actualHeight := endY - startY + 3

	// Draw the content box
	r.pdf.SetDrawColor(229, 231, 235)
	r.pdf.Rect(20, startY+8, 170, actualHeight-8, "D")

	r.pdf.SetY(endY + 3)
}

// addRecommendations creates the recommendations section
func (r *PDFReporter) addRecommendations(result *types.ScanResult) {
	r.addPageHeader("Security Recommendations")

	y := 40.0
	r.addSectionHeader("Immediate Actions Required", y)
	y += 15

	recommendations := []string{
		"Address all Critical and High severity findings immediately",
		"Implement comprehensive input validation and output encoding",
		"Use parameterised queries to prevent SQL injection attacks",
		"Apply principle of least privilege for system access",
		"Implement proper error handling and logging mechanisms",
		"Conduct regular security assessments and code reviews",
		"Keep all dependencies and frameworks up to date",
		"Integrate security testing into CI/CD pipeline",
	}

	for i, rec := range recommendations {
		// Priority indicator
		priority := "High"
		if i > 2 {
			priority = "Medium"
		}
		if i > 5 {
			priority = "Low"
		}

		r.addRecommendationItem(fmt.Sprintf("%d. %s", i+1, rec), priority, y)
		y += 12
	}

	// Compliance section
	y += 20
	r.addSectionHeader("Compliance Considerations", y)
	y += 15

	compliance := []string{
		"OWASP Top 10 compliance validation required",
		"Data protection regulations (GDPR, CCPA) assessment needed",
		"Industry-specific security standards review",
		"Regular penetration testing schedule establishment",
	}

	for _, item := range compliance {
		r.pdf.SetFont("Arial", "", 10)
		r.pdf.SetXY(20, y)
		r.pdf.CellFormat(0, 6, "• "+item, "", 1, "L", false, 0, "")
		y += 8
	}
}

// addRecommendationItem creates a styled recommendation item
func (r *PDFReporter) addRecommendationItem(text, priority string, y float64) {
	// Priority color indicator
	priorityColor := []int{5, 150, 105} // Default green
	if priority == "High" {
		priorityColor = []int{220, 38, 38} // Red
	} else if priority == "Medium" {
		priorityColor = []int{234, 88, 12} // Orange
	}

	// Priority indicator circle
	r.pdf.SetFillColor(priorityColor[0], priorityColor[1], priorityColor[2])
	r.pdf.Circle(23, y+2, 2, "F")

	// Recommendation text
	r.pdf.SetFont("Arial", "", 10)
	r.pdf.SetTextColor(0, 0, 0)
	r.pdf.SetXY(28, y)

	lines := r.wrapText(text, 155)
	for i, line := range lines {
		r.pdf.SetXY(28, y+float64(i*5))
		r.pdf.CellFormat(0, 5, line, "", 1, "L", false, 0, "")
	}
}

// Helper functions for styling and layout

// addPageHeader creates a consistent page header
func (r *PDFReporter) addPageHeader(title string) {
	// Header background
	r.pdf.SetFillColor(249, 250, 251)
	r.pdf.Rect(0, 0, 210, 25, "F")

	// Title
	r.pdf.SetFont("Arial", "B", 16)
	r.pdf.SetTextColor(55, 65, 81)
	r.pdf.SetXY(20, 8)
	r.pdf.CellFormat(0, 8, title, "", 1, "L", false, 0, "")

	// Accent line
	r.pdf.SetFillColor(37, 99, 235)
	r.pdf.Rect(0, 23, 210, 2, "F")

	r.pdf.SetY(35)
}

// addSectionHeader creates a section header
func (r *PDFReporter) addSectionHeader(title string, y float64) {
	r.pdf.SetFont("Arial", "B", 14)
	r.pdf.SetTextColor(55, 65, 81)
	r.pdf.SetXY(20, y)
	r.pdf.CellFormat(0, 8, title, "", 1, "L", false, 0, "")

	// Underline
	r.pdf.SetDrawColor(229, 231, 235)
	r.pdf.Line(20, y+9, 190, y+9)
}

// addFooter creates a page footer
func (r *PDFReporter) addFooter() {
	r.pdf.SetY(260)
	r.pdf.SetFont("Arial", "", 8)
	r.pdf.SetTextColor(150, 150, 150)
	r.pdf.CellFormat(0, 4, fmt.Sprintf("Generated by MCP Security Scanner - %s", time.Now().Format("2006-01-02 15:04:05")), "", 1, "C", false, 0, "")
}

// getRiskColor returns RGB color values for risk levels
func (r *PDFReporter) getRiskColor(risk string) []int {
	switch strings.ToLower(risk) {
	case "critical":
		return []int{220, 38, 38} // Red
	case "high":
		return []int{234, 88, 12} // Orange
	case "medium":
		return []int{217, 119, 6} // Yellow
	case "low":
		return []int{5, 150, 105} // Green
	default:
		return []int{107, 114, 128} // Gray
	}
}

// getSeverityColor returns RGB color values for severity levels
func (r *PDFReporter) getSeverityColor(severity string) []int {
	return r.getRiskColor(severity)
}

// getKeyRecommendations returns prioritized recommendations based on findings
func (r *PDFReporter) getKeyRecommendations(result *types.ScanResult) []string {
	recommendations := []string{}

	if result.Summary.CriticalFindings > 0 {
		recommendations = append(recommendations, "Immediate remediation of critical vulnerabilities required")
	}
	if result.Summary.HighFindings > 0 {
		recommendations = append(recommendations, "High-priority security issues need urgent attention")
	}

	// Add general recommendations
	baseRecommendations := []string{
		"Implement comprehensive input validation",
		"Establish regular security testing schedule",
		"Update security policies and procedures",
	}

	return append(recommendations, baseRecommendations...)
}

// wrapText wraps text to fit within specified width
func (r *PDFReporter) wrapText(text string, maxWidth float64) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}

	var lines []string
	var currentLine string

	for _, word := range words {
		testLine := currentLine
		if testLine != "" {
			testLine += " "
		}
		testLine += word

		if r.pdf.GetStringWidth(testLine) <= maxWidth {
			currentLine = testLine
		} else {
			if currentLine != "" {
				lines = append(lines, currentLine)
			}
			currentLine = word
		}
	}

	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	return lines
}

// truncateText truncates text to specified length
func (r *PDFReporter) truncateText(text string, maxLength int) string {
	if len(text) <= maxLength {
		return text
	}
	return text[:maxLength] + "..."
}

// GeneratePDFReportWithTimestamp generates a PDF report with timestamp in filename
func GeneratePDFReportWithTimestamp(result *types.ScanResult, baseDir string) (string, error) {
	reporter, err := NewPDFReporter()
	if err != nil {
		return "", err
	}

	// Create timestamped filename
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("mcp_security_report_%s.pdf", timestamp)
	outputPath := filepath.Join(baseDir, filename)

	err = reporter.GenerateReport(result, outputPath)
	if err != nil {
		return "", err
	}

	return outputPath, nil
}

// CheckPDFDependencies checks if required dependencies for PDF generation are available
// NOTE: This function is deprecated and always returns nil since we now use pure Go PDF generation
// No external dependencies (like wkhtmltopdf) are required anymore
func CheckPDFDependencies() error {
	// No external dependencies needed with pure Go implementation
	return nil
}
