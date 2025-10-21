package output

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"github.com/victorstaflin/bountytxt-cli/internal/core"
)

// Formatter interface for different output formats
type Formatter interface {
	Format(data interface{}) (string, error)
}

// TableFormatter formats output as a table
type TableFormatter struct {
	ShowHeaders bool
	Separator   string
}

// NewTableFormatter creates a new table formatter
func NewTableFormatter() *TableFormatter {
	return &TableFormatter{
		ShowHeaders: true,
		Separator:   " | ",
	}
}

// Format formats data as a table
func (f *TableFormatter) Format(data interface{}) (string, error) {
	switch v := data.(type) {
	case *core.DiscoveryResult:
		return f.formatDiscoveryResult(v), nil
	case []core.DiscoveryResult:
		return f.formatDiscoveryResults(v), nil
	case *core.LintReport:
		return f.formatLintReport(v), nil
	case []core.LintReport:
		return f.formatLintReports(v), nil
	case *core.SecurityTxt:
		return f.formatSecurityTxt(v), nil
	case []core.SecurityTxt:
		return f.formatSecurityTxts(v), nil
	case []core.Platform:
		return f.formatPlatforms(v), nil
	case []core.ContactIntelligence:
		return f.formatContactIntelligence(v), nil
	case *core.BulkResult:
		return f.formatBulkResult(v), nil
	case []core.BulkResult:
		return f.formatBulkResults(v), nil
	case map[string]interface{}:
		// Check if this is contacts output, hunt output, or CI output
		if _, hasContacts := v["contacts"]; hasContacts {
			return f.formatContactsOutput(v), nil
		} else if _, hasResults := v["results"]; hasResults {
			return f.formatHuntOutput(v), nil
		} else if _, hasPassed := v["passed"]; hasPassed {
			return f.formatCIOutput(v), nil
		}
		return "", fmt.Errorf("unsupported map data type for table format")
	default:
		return "", fmt.Errorf("unsupported data type for table format")
	}
}

// formatDiscoveryResult formats a single discovery result as a table
func (f *TableFormatter) formatDiscoveryResult(result *core.DiscoveryResult) string {
	var output strings.Builder

	if f.ShowHeaders {
		output.WriteString("DOMAIN" + f.Separator + "FOUND" + f.Separator + "SOURCE URL" + f.Separator + "DISCOVERED AT\n")
		output.WriteString(strings.Repeat("-", 80) + "\n")
	}

	found := "No"
	if result.Found {
		found = "Yes"
	}

	sourceURL := result.SourceURL
	if sourceURL == "" {
		sourceURL = "N/A"
	}

	output.WriteString(fmt.Sprintf("%s%s%s%s%s%s%s\n",
		result.Domain,
		f.Separator,
		found,
		f.Separator,
		sourceURL,
		f.Separator,
		result.DiscoveredAt.Format("2006-01-02 15:04:05"),
	))

	// If security.txt was found, show its details
	if result.Found && result.SecurityTxt != nil {
		output.WriteString("\nSecurity.txt Details:\n")
		output.WriteString(strings.Repeat("-", 50) + "\n")
		output.WriteString(f.formatSecurityTxt(result.SecurityTxt))
	}

	return output.String()
}

// formatDiscoveryResults formats multiple discovery results as a table
func (f *TableFormatter) formatDiscoveryResults(results []core.DiscoveryResult) string {
	var output strings.Builder

	if f.ShowHeaders {
		output.WriteString("DOMAIN" + f.Separator + "FOUND" + f.Separator + "SOURCE URL" + f.Separator + "DISCOVERED AT\n")
		output.WriteString(strings.Repeat("-", 80) + "\n")
	}

	for _, result := range results {
		found := "No"
		if result.Found {
			found = "Yes"
		}

		sourceURL := result.SourceURL
		if sourceURL == "" {
			sourceURL = "N/A"
		}

		output.WriteString(fmt.Sprintf("%s%s%s%s%s%s%s\n",
			result.Domain,
			f.Separator,
			found,
			f.Separator,
			sourceURL,
			f.Separator,
			result.DiscoveredAt.Format("2006-01-02 15:04:05"),
		))
	}

	return output.String()
}

// formatLintReport formats a single lint report as a table
func (f *TableFormatter) formatLintReport(report *core.LintReport) string {
	var result strings.Builder

	// Header
	if f.ShowHeaders {
		result.WriteString("DOMAIN" + f.Separator + "SCORE" + f.Separator + "GRADE" + f.Separator + "ISSUES" + f.Separator + "STATUS\n")
		result.WriteString(strings.Repeat("-", 80) + "\n")
	}

	// Data
	status := "Valid"
	if !report.Found {
		status = "Not Found"
	} else if len(report.Issues) > 0 {
		for _, issue := range report.Issues {
			if issue.Severity == "error" {
				status = "Invalid"
				break
			}
		}
	}

	result.WriteString(fmt.Sprintf("%s%s%d%s%s%s%d%s%s\n",
		report.Domain,
		f.Separator,
		report.Score,
		f.Separator,
		report.Grade,
		f.Separator,
		len(report.Issues),
		f.Separator,
		status,
	))

	return result.String()
}

// formatLintReports formats multiple lint reports as a table
func (f *TableFormatter) formatLintReports(reports []core.LintReport) string {
	var result strings.Builder

	// Header
	if f.ShowHeaders {
		result.WriteString("DOMAIN" + f.Separator + "SCORE" + f.Separator + "GRADE" + f.Separator + "ISSUES" + f.Separator + "STATUS\n")
		result.WriteString(strings.Repeat("-", 80) + "\n")
	}

	// Data
	for _, report := range reports {
		status := "Valid"
		if !report.Found {
			status = "Not Found"
		} else if len(report.Issues) > 0 {
			for _, issue := range report.Issues {
				if issue.Severity == "error" {
					status = "Invalid"
					break
				}
			}
		}

		result.WriteString(fmt.Sprintf("%s%s%d%s%s%s%d%s%s\n",
			report.Domain,
			f.Separator,
			report.Score,
			f.Separator,
			report.Grade,
			f.Separator,
			len(report.Issues),
			f.Separator,
			status,
		))
	}

	return result.String()
}

// formatSecurityTxt formats a security.txt as a table
func (f *TableFormatter) formatSecurityTxt(securityTxt *core.SecurityTxt) string {
	var result strings.Builder

	if f.ShowHeaders {
		result.WriteString("FIELD" + f.Separator + "VALUE\n")
		result.WriteString(strings.Repeat("-", 50) + "\n")
	}

	// Contact
	for _, contact := range securityTxt.Contact {
		result.WriteString(fmt.Sprintf("Contact%s%s\n", f.Separator, contact))
	}

	// Expires
	if securityTxt.Expires != nil {
		result.WriteString(fmt.Sprintf("Expires%s%s\n", f.Separator, securityTxt.Expires.Format(time.RFC3339)))
	}

	// Encryption
	for _, encryption := range securityTxt.Encryption {
		result.WriteString(fmt.Sprintf("Encryption%s%s\n", f.Separator, encryption))
	}

	// Acknowledgments
	for _, ack := range securityTxt.Acknowledgments {
		result.WriteString(fmt.Sprintf("Acknowledgments%s%s\n", f.Separator, ack))
	}

	// Canonical
	for _, canonical := range securityTxt.Canonical {
		result.WriteString(fmt.Sprintf("Canonical%s%s\n", f.Separator, canonical))
	}

	// Policy
	for _, policy := range securityTxt.Policy {
		result.WriteString(fmt.Sprintf("Policy%s%s\n", f.Separator, policy))
	}

	// Hiring
	for _, hiring := range securityTxt.Hiring {
		result.WriteString(fmt.Sprintf("Hiring%s%s\n", f.Separator, hiring))
	}

	return result.String()
}

// formatSecurityTxts formats multiple security.txt files as a table
func (f *TableFormatter) formatSecurityTxts(securityTxts []core.SecurityTxt) string {
	var result strings.Builder

	if f.ShowHeaders {
		result.WriteString("DOMAIN" + f.Separator + "CONTACTS" + f.Separator + "EXPIRES" + f.Separator + "PLATFORMS\n")
		result.WriteString(strings.Repeat("-", 80) + "\n")
	}

	for _, securityTxt := range securityTxts {
		domain := "Unknown"
		if len(securityTxt.Canonical) > 0 {
			domain = extractDomainFromURL(securityTxt.Canonical[0])
		}

		contacts := fmt.Sprintf("%d", len(securityTxt.Contact))
		expires := "None"
		if securityTxt.Expires != nil {
			expires = securityTxt.Expires.Format("2006-01-02")
		}

		platforms := "0"

		result.WriteString(fmt.Sprintf("%s%s%s%s%s%s%s\n",
			domain,
			f.Separator,
			contacts,
			f.Separator,
			expires,
			f.Separator,
			platforms,
		))
	}

	return result.String()
}

// formatPlatforms formats platforms as a table
func (f *TableFormatter) formatPlatforms(platforms []core.Platform) string {
	var result strings.Builder

	if f.ShowHeaders {
		result.WriteString("PLATFORM" + f.Separator + "TYPE" + f.Separator + "PROGRAM" + f.Separator + "CONFIDENCE" + f.Separator + "URL\n")
		result.WriteString(strings.Repeat("-", 100) + "\n")
	}

	for _, platform := range platforms {
		confidence := fmt.Sprintf("%.1f%%", platform.Confidence*100)
		url := platform.URL
		if len(url) > 50 {
			url = url[:47] + "..."
		}

		result.WriteString(fmt.Sprintf("%s%s%s%s%s%s%s%s%s\n",
			platform.Name,
			f.Separator,
			platform.Type,
			f.Separator,
			platform.Program,
			f.Separator,
			confidence,
			f.Separator,
			url,
		))
	}

	return result.String()
}

// formatContactIntelligence formats contact intelligence as a table
func (f *TableFormatter) formatContactIntelligence(intelligence []core.ContactIntelligence) string {
	var result strings.Builder

	if f.ShowHeaders {
		result.WriteString("CONTACT" + f.Separator + "TYPE" + f.Separator + "CONFIDENCE" + f.Separator + "METADATA\n")
		result.WriteString(strings.Repeat("-", 100) + "\n")
	}

	for _, intel := range intelligence {
		confidence := fmt.Sprintf("%.1f%%", intel.Confidence*100)
		contact := intel.Contact
		if len(contact) > 40 {
			contact = contact[:37] + "..."
		}

		metadata := ""
		for k, v := range intel.Metadata {
			if metadata != "" {
				metadata += ", "
			}
			metadata += fmt.Sprintf("%s=%s", k, v)
		}
		if len(metadata) > 30 {
			metadata = metadata[:27] + "..."
		}

		result.WriteString(fmt.Sprintf("%s%s%s%s%s%s%s\n",
			contact,
			f.Separator,
			intel.Type,
			f.Separator,
			confidence,
			f.Separator,
			metadata,
		))
	}

	return result.String()
}

// JSONFormatter formats output as JSON
type JSONFormatter struct {
	Pretty bool
}

// NewJSONFormatter creates a new JSON formatter
func NewJSONFormatter(pretty bool) *JSONFormatter {
	return &JSONFormatter{Pretty: pretty}
}

// Format formats data as JSON
func (f *JSONFormatter) Format(data interface{}) (string, error) {
	var result []byte
	var err error

	if f.Pretty {
		result, err = json.MarshalIndent(data, "", "  ")
	} else {
		result, err = json.Marshal(data)
	}

	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return string(result), nil
}

// JSONLFormatter formats output as JSON Lines (one JSON object per line)
type JSONLFormatter struct{}

// NewJSONLFormatter creates a new JSONL formatter
func NewJSONLFormatter() *JSONLFormatter {
	return &JSONLFormatter{}
}

// Format formats data as JSONL
func (f *JSONLFormatter) Format(data interface{}) (string, error) {
	var result strings.Builder

	switch v := data.(type) {
	case []core.LintReport:
		for _, report := range v {
			line, err := json.Marshal(report)
			if err != nil {
				return "", fmt.Errorf("failed to marshal JSONL: %w", err)
			}
			result.Write(line)
			result.WriteString("\n")
		}
	case []core.SecurityTxt:
		for _, securityTxt := range v {
			line, err := json.Marshal(securityTxt)
			if err != nil {
				return "", fmt.Errorf("failed to marshal JSONL: %w", err)
			}
			result.Write(line)
			result.WriteString("\n")
		}
	case []core.Platform:
		for _, platform := range v {
			line, err := json.Marshal(platform)
			if err != nil {
				return "", fmt.Errorf("failed to marshal JSONL: %w", err)
			}
			result.Write(line)
			result.WriteString("\n")
		}
	default:
		// For single objects, just marshal as JSON
		line, err := json.Marshal(data)
		if err != nil {
			return "", fmt.Errorf("failed to marshal JSONL: %w", err)
		}
		result.Write(line)
		result.WriteString("\n")
	}

	return result.String(), nil
}

// YAMLFormatter formats output as YAML
type YAMLFormatter struct{}

// NewYAMLFormatter creates a new YAML formatter
func NewYAMLFormatter() *YAMLFormatter {
	return &YAMLFormatter{}
}

// Format formats data as YAML
func (f *YAMLFormatter) Format(data interface{}) (string, error) {
	result, err := yaml.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal YAML: %w", err)
	}

	return string(result), nil
}

// CSVFormatter formats output as CSV
type CSVFormatter struct {
	writer *csv.Writer
	buffer *strings.Builder
}

// NewCSVFormatter creates a new CSV formatter
func NewCSVFormatter() *CSVFormatter {
	buffer := &strings.Builder{}
	writer := csv.NewWriter(buffer)
	return &CSVFormatter{
		writer: writer,
		buffer: buffer,
	}
}

// Format formats data as CSV
func (f *CSVFormatter) Format(data interface{}) (string, error) {
	f.buffer.Reset()

	switch v := data.(type) {
	case []core.LintReport:
		return f.formatLintReportsCSV(v)
	case []core.SecurityTxt:
		return f.formatSecurityTxtsCSV(v)
	case []core.Platform:
		return f.formatPlatformsCSV(v)
	default:
		return "", fmt.Errorf("unsupported data type for CSV format")
	}
}

// formatLintReportsCSV formats lint reports as CSV
func (f *CSVFormatter) formatLintReportsCSV(reports []core.LintReport) (string, error) {
	// Header
	if err := f.writer.Write([]string{"Domain", "Score", "Grade", "Issues", "Status", "ValidatedAt"}); err != nil {
		return "", err
	}

	// Data
	for _, report := range reports {
		status := "Valid"
		if !report.Found {
			status = "Not Found"
		} else if len(report.Issues) > 0 {
			for _, issue := range report.Issues {
				if issue.Severity == "error" {
					status = "Invalid"
					break
				}
			}
		}

		record := []string{
			report.Domain,
			strconv.Itoa(report.Score),
			report.Grade,
			strconv.Itoa(len(report.Issues)),
			status,
			report.ValidatedAt.Format(time.RFC3339),
		}

		if err := f.writer.Write(record); err != nil {
			return "", err
		}
	}

	f.writer.Flush()
	return f.buffer.String(), f.writer.Error()
}

// formatSecurityTxtsCSV formats security.txt files as CSV
func (f *CSVFormatter) formatSecurityTxtsCSV(securityTxts []core.SecurityTxt) (string, error) {
	// Header
	if err := f.writer.Write([]string{"Domain", "Contacts", "Expires", "Encryption", "Policy", "Acknowledgments"}); err != nil {
		return "", err
	}

	// Data
	for _, securityTxt := range securityTxts {
		domain := "Unknown"
		if len(securityTxt.Canonical) > 0 {
			domain = extractDomainFromURL(securityTxt.Canonical[0])
		}

		contacts := strings.Join(securityTxt.Contact, "; ")
		expires := ""
		if securityTxt.Expires != nil {
			expires = securityTxt.Expires.Format(time.RFC3339)
		}
		encryption := strings.Join(securityTxt.Encryption, "; ")
		policy := strings.Join(securityTxt.Policy, "; ")
		acknowledgments := strings.Join(securityTxt.Acknowledgments, "; ")

		record := []string{domain, contacts, expires, encryption, policy, acknowledgments}
		if err := f.writer.Write(record); err != nil {
			return "", err
		}
	}

	f.writer.Flush()
	return f.buffer.String(), f.writer.Error()
}

// formatPlatformsCSV formats platforms as CSV
func (f *CSVFormatter) formatPlatformsCSV(platforms []core.Platform) (string, error) {
	// Header
	if err := f.writer.Write([]string{"Platform", "Type", "Program", "Confidence", "URL"}); err != nil {
		return "", err
	}

	// Data
	for _, platform := range platforms {
		confidence := fmt.Sprintf("%.3f", platform.Confidence)
		record := []string{platform.Name, platform.Type, platform.Program, confidence, platform.URL}
		if err := f.writer.Write(record); err != nil {
			return "", err
		}
	}

	f.writer.Flush()
	return f.buffer.String(), f.writer.Error()
}

// XMLFormatter formats output as XML
type XMLFormatter struct {
	Pretty bool
}

// NewXMLFormatter creates a new XML formatter
func NewXMLFormatter(pretty bool) *XMLFormatter {
	return &XMLFormatter{Pretty: pretty}
}

// Format formats data as XML
func (f *XMLFormatter) Format(data interface{}) (string, error) {
	var result []byte
	var err error

	if f.Pretty {
		result, err = xml.MarshalIndent(data, "", "  ")
	} else {
		result, err = xml.Marshal(data)
	}

	if err != nil {
		return "", fmt.Errorf("failed to marshal XML: %w", err)
	}

	return string(result), nil
}

// SARIFFormatter formats output as SARIF (Static Analysis Results Interchange Format)
type SARIFFormatter struct{}

// NewSARIFFormatter creates a new SARIF formatter
func NewSARIFFormatter() *SARIFFormatter {
	return &SARIFFormatter{}
}

// Format formats data as SARIF
func (f *SARIFFormatter) Format(data interface{}) (string, error) {
	switch v := data.(type) {
	case *core.LintReport:
		return f.formatLintReportSARIF(v)
	case []core.LintReport:
		return f.formatLintReportsSARIF(v)
	default:
		return "", fmt.Errorf("unsupported data type for SARIF format")
	}
}

// formatLintReportSARIF formats a lint report as SARIF
func (f *SARIFFormatter) formatLintReportSARIF(report *core.LintReport) (string, error) {
	sarif := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":    "bountytxt",
						"version": "1.0.0",
						"informationUri": "https://github.com/example/bountytxt",
					},
				},
				"results": f.convertIssuesToSARIF(report.Issues),
			},
		},
	}

	result, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal SARIF: %w", err)
	}

	return string(result), nil
}

// formatLintReportsSARIF formats multiple lint reports as SARIF
func (f *SARIFFormatter) formatLintReportsSARIF(reports []core.LintReport) (string, error) {
	allIssues := make([]core.Issue, 0)
	for _, report := range reports {
		allIssues = append(allIssues, report.Issues...)
	}

	sarif := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":    "bountytxt",
						"version": "1.0.0",
						"informationUri": "https://github.com/example/bountytxt",
					},
				},
				"results": f.convertIssuesToSARIF(allIssues),
			},
		},
	}

	result, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal SARIF: %w", err)
	}

	return string(result), nil
}

// convertIssuesToSARIF converts issues to SARIF format
func (f *SARIFFormatter) convertIssuesToSARIF(issues []core.Issue) []map[string]interface{} {
	results := make([]map[string]interface{}, 0, len(issues))

	for _, issue := range issues {
		level := "note"
		switch issue.Severity {
		case "error":
			level = "error"
		case "warning":
			level = "warning"
		case "info":
			level = "note"
		}

		result := map[string]interface{}{
			"ruleId":  issue.Type,
			"level":   level,
			"message": map[string]interface{}{"text": issue.Message},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]interface{}{
							"uri": "security.txt",
						},
						"region": map[string]interface{}{
							"startLine": issue.Line,
						},
					},
				},
			},
		}

		if issue.Suggestion != "" {
			result["fixes"] = []map[string]interface{}{
				{
					"description": map[string]interface{}{"text": issue.Suggestion},
				},
			}
		}

		results = append(results, result)
	}

	return results
}

// formatBulkResult formats a single bulk result as a table
func (f *TableFormatter) formatBulkResult(result *core.BulkResult) string {
	var output strings.Builder

	if f.ShowHeaders {
		output.WriteString("DOMAIN" + f.Separator + "FOUND" + f.Separator + "SOURCE URL" + f.Separator + "SCORE" + f.Separator + "GRADE" + f.Separator + "STATUS" + f.Separator + "PROCESSED AT\n")
		output.WriteString(strings.Repeat("-", 120) + "\n")
	}

	found := "No"
	if result.Found {
		found = "Yes"
	}

	sourceURL := result.SourceURL
	if sourceURL == "" {
		sourceURL = "N/A"
	}

	status := "Success"
	if result.Error != "" {
		status = "Error"
	} else if !result.ValidationPassed {
		status = "Failed Validation"
	}

	score := "-"
	grade := "-"
	if result.Score > 0 {
		score = fmt.Sprintf("%d", result.Score)
		grade = result.Grade
	}

	output.WriteString(fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
		result.Domain,
		f.Separator,
		found,
		f.Separator,
		sourceURL,
		f.Separator,
		score,
		f.Separator,
		grade,
		f.Separator,
		status,
		f.Separator,
		result.ProcessedAt.Format("2006-01-02 15:04:05"),
	))

	return output.String()
}

// formatBulkResults formats multiple bulk results as a table
func (f *TableFormatter) formatBulkResults(results []core.BulkResult) string {
	var output strings.Builder

	if f.ShowHeaders {
		output.WriteString("DOMAIN" + f.Separator + "FOUND" + f.Separator + "SOURCE URL" + f.Separator + "SCORE" + f.Separator + "GRADE" + f.Separator + "STATUS" + f.Separator + "PROCESSED AT\n")
		output.WriteString(strings.Repeat("-", 120) + "\n")
	}

	for _, result := range results {
		found := "No"
		if result.Found {
			found = "Yes"
		}

		sourceURL := result.SourceURL
		if sourceURL == "" {
			sourceURL = "N/A"
		}

		status := "Success"
		if result.Error != "" {
			status = "Error"
		} else if !result.ValidationPassed {
			status = "Failed Validation"
		}

		score := "-"
		grade := "-"
		if result.Score > 0 {
			score = fmt.Sprintf("%d", result.Score)
			grade = result.Grade
		}

		output.WriteString(fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
			result.Domain,
			f.Separator,
			found,
			f.Separator,
			sourceURL,
			f.Separator,
			score,
			f.Separator,
			grade,
			f.Separator,
			status,
			f.Separator,
			result.ProcessedAt.Format("2006-01-02 15:04:05"),
		))
	}

	return output.String()
}

// formatContactsOutput formats contacts output as a table
func (f *TableFormatter) formatContactsOutput(data map[string]interface{}) string {
	var output strings.Builder

	// Extract data from the map
	domain, _ := data["domain"].(string)
	sourceURL, _ := data["source_url"].(string)
	contactCount, _ := data["contact_count"].(int)
	contacts, _ := data["contacts"].([]interface{})
	showConfidence, _ := data["show_confidence"].(bool)

	// Header information
	output.WriteString(fmt.Sprintf("Domain: %s\n", domain))
	if sourceURL != "" {
		output.WriteString(fmt.Sprintf("Source URL: %s\n", sourceURL))
	}
	output.WriteString(fmt.Sprintf("Contact Count: %d\n\n", contactCount))

	if len(contacts) == 0 {
		output.WriteString("No contacts found.\n")
		return output.String()
	}

	// Table headers
	if f.ShowHeaders {
		if showConfidence {
			output.WriteString("TYPE" + f.Separator + "VALUE" + f.Separator + "VALID" + f.Separator + "CONFIDENCE\n")
			output.WriteString(strings.Repeat("-", 80) + "\n")
		} else {
			output.WriteString("TYPE" + f.Separator + "VALUE" + f.Separator + "VALID\n")
			output.WriteString(strings.Repeat("-", 60) + "\n")
		}
	}

	// Contact rows
	for _, contact := range contacts {
		if contactMap, ok := contact.(map[string]interface{}); ok {
			contactType, _ := contactMap["type"].(string)
			value, _ := contactMap["value"].(string)
			valid, _ := contactMap["valid"].(bool)
			confidence, _ := contactMap["confidence"].(float64)

			validStr := "No"
			if valid {
				validStr = "Yes"
			}

			if showConfidence {
				output.WriteString(fmt.Sprintf("%s%s%s%s%s%s%.2f\n",
					contactType,
					f.Separator,
					value,
					f.Separator,
					validStr,
					f.Separator,
					confidence,
				))
			} else {
				output.WriteString(fmt.Sprintf("%s%s%s%s%s\n",
					contactType,
					f.Separator,
					value,
					f.Separator,
					validStr,
				))
			}
		}
	}

	return output.String()
}

// formatHuntOutput formats hunt output as a table
func (f *TableFormatter) formatHuntOutput(data map[string]interface{}) string {
	var output strings.Builder

	// Extract data from the map
	baseDomain, _ := data["base_domain"].(string)
	targetsChecked, _ := data["targets_checked"].(int)
	foundCount, _ := data["found_count"].(int)
	results, _ := data["results"].([]interface{})

	// Header information
	output.WriteString(fmt.Sprintf("Hunt Results for: %s\n", baseDomain))
	output.WriteString(fmt.Sprintf("Targets Checked: %d\n", targetsChecked))
	output.WriteString(fmt.Sprintf("Security.txt Found: %d\n\n", foundCount))

	if len(results) == 0 {
		output.WriteString("No results to display.\n")
		return output.String()
	}

	// Table headers
	if f.ShowHeaders {
		output.WriteString("DOMAIN" + f.Separator + "FOUND" + f.Separator + "TYPE" + f.Separator + "SOURCE URL" + f.Separator + "DEPTH\n")
		output.WriteString(strings.Repeat("-", 100) + "\n")
	}

	// Result rows
	for _, result := range results {
		if resultMap, ok := result.(map[string]interface{}); ok {
			domain, _ := resultMap["domain"].(string)
			found, _ := resultMap["found"].(bool)
			resultType, _ := resultMap["type"].(string)
			sourceURL, _ := resultMap["source_url"].(string)
			depth, _ := resultMap["depth"].(int)

			foundStr := "No"
			if found {
				foundStr = "Yes"
			}

			if sourceURL == "" {
				sourceURL = "N/A"
			}

			output.WriteString(fmt.Sprintf("%s%s%s%s%s%s%s%s%d\n",
				domain,
				f.Separator,
				foundStr,
				f.Separator,
				resultType,
				f.Separator,
				sourceURL,
				f.Separator,
				depth,
			))
		}
	}

	return output.String()
}

// formatCIOutput formats CI output as a table
func (f *TableFormatter) formatCIOutput(data map[string]interface{}) string {
	var output strings.Builder

	// Extract data from the map
	domain, _ := data["domain"].(string)
	sourceURL, _ := data["source_url"].(string)
	found, _ := data["found"].(bool)
	score, _ := data["score"].(int)
	grade, _ := data["grade"].(string)
	passed, _ := data["passed"].(bool)
	exitCode, _ := data["exit_code"].(int)
	ciSummary, _ := data["ci_summary"].(string)
	issues, _ := data["issues"].([]interface{})

	// Header information
	output.WriteString(fmt.Sprintf("CI Validation Results for: %s\n", domain))
	if sourceURL != "" {
		output.WriteString(fmt.Sprintf("Source URL: %s\n", sourceURL))
	}
	output.WriteString(fmt.Sprintf("Found: %t\n", found))
	output.WriteString(fmt.Sprintf("Score: %d\n", score))
	output.WriteString(fmt.Sprintf("Grade: %s\n", grade))
	
	// CI Results
	passedStr := "❌ FAILED"
	if passed {
		passedStr = "✅ PASSED"
	}
	output.WriteString(fmt.Sprintf("Status: %s\n", passedStr))
	output.WriteString(fmt.Sprintf("Exit Code: %d\n", exitCode))
	output.WriteString(fmt.Sprintf("Summary: %s\n\n", ciSummary))

	// Issues table
	if len(issues) > 0 {
		output.WriteString("Issues:\n")
		if f.ShowHeaders {
			output.WriteString("SEVERITY" + f.Separator + "TYPE" + f.Separator + "FIELD" + f.Separator + "MESSAGE\n")
			output.WriteString(strings.Repeat("-", 80) + "\n")
		}

		for _, issue := range issues {
			if issueMap, ok := issue.(map[string]interface{}); ok {
				severity, _ := issueMap["severity"].(string)
				issueType, _ := issueMap["type"].(string)
				field, _ := issueMap["field"].(string)
				message, _ := issueMap["message"].(string)

				if field == "" {
					field = "N/A"
				}

				output.WriteString(fmt.Sprintf("%s%s%s%s%s%s%s\n",
					severity,
					f.Separator,
					issueType,
					f.Separator,
					field,
					f.Separator,
					message,
				))
			}
		}
	} else {
		output.WriteString("No issues found.\n")
	}

	return output.String()
}

// GetFormatter returns a formatter based on the format string
func GetFormatter(format string) (Formatter, error) {
	switch strings.ToLower(format) {
	case "table":
		return NewTableFormatter(), nil
	case "json":
		return NewJSONFormatter(true), nil
	case "json-compact":
		return NewJSONFormatter(false), nil
	case "jsonl":
		return NewJSONLFormatter(), nil
	case "yaml":
		return NewYAMLFormatter(), nil
	case "csv":
		return NewCSVFormatter(), nil
	case "xml":
		return NewXMLFormatter(true), nil
	case "xml-compact":
		return NewXMLFormatter(false), nil
	case "sarif":
		return NewSARIFFormatter(), nil
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// extractDomainFromURL extracts domain from URL
func extractDomainFromURL(urlStr string) string {
	if strings.HasPrefix(urlStr, "http") {
		parts := strings.Split(urlStr, "/")
		if len(parts) >= 3 {
			return parts[2]
		}
	}
	return urlStr
}

// WriteOutput writes formatted output to a writer
func WriteOutput(writer io.Writer, formatter Formatter, data interface{}) error {
	output, err := formatter.Format(data)
	if err != nil {
		return err
	}

	_, err = writer.Write([]byte(output))
	return err
}