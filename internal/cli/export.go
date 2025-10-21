package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/victorstaflin/bountytxt-cli/internal/discovery"
	"github.com/victorstaflin/bountytxt-cli/internal/output"
	"github.com/victorstaflin/bountytxt-cli/internal/validation"
)

// exportCmd represents the export command
var exportCmd = &cobra.Command{
	Use:   "export [domain]",
	Short: "Export security.txt data in various formats",
	Long: `Export security.txt data and validation results in various formats for integration with other tools.

This command discovers and validates security.txt files, then exports the data in formats
suitable for:
- Security scanning tools
- Vulnerability management platforms
- Compliance reporting
- Data analysis and visualization

Supported export formats:
- JSON: Structured data for APIs and tools
- YAML: Human-readable configuration format
- CSV: Spreadsheet and database import
- XML: Enterprise system integration
- SARIF: Static analysis results format

Examples:
  securitytxt-cli export example.com --format json --output security.json
  securitytxt-cli export example.com --format csv --include-validation
  securitytxt-cli export example.com --format sarif --output results.sarif
  securitytxt-cli export example.com --template custom.tmpl --output report.txt`,
	Args: cobra.ExactArgs(1),
	RunE: runExport,
}

func init() {
	// Export-specific flags
	exportCmd.Flags().String("format", "json", "export format (json, yaml, csv, xml, sarif)")
	exportCmd.Flags().String("output", "", "output file (default: stdout)")
	exportCmd.Flags().Bool("include-validation", true, "include validation results")
	exportCmd.Flags().Bool("include-raw", false, "include raw security.txt content")
	exportCmd.Flags().Bool("include-metadata", true, "include discovery metadata")
	exportCmd.Flags().String("template", "", "custom template file for formatting")
	exportCmd.Flags().Bool("pretty", true, "pretty-print output (where applicable)")
	exportCmd.Flags().StringSlice("fields", []string{}, "specific fields to export (default: all)")
	exportCmd.Flags().Bool("compress", false, "compress output (gzip)")
}

func runExport(cmd *cobra.Command, args []string) error {
	domain := args[0]
	
	// Get flag values
	format, _ := cmd.Flags().GetString("format")
	outputFile, _ := cmd.Flags().GetString("output")
	includeValidation, _ := cmd.Flags().GetBool("include-validation")
	includeRaw, _ := cmd.Flags().GetBool("include-raw")
	includeMetadata, _ := cmd.Flags().GetBool("include-metadata")
	templateFile, _ := cmd.Flags().GetString("template")
	pretty, _ := cmd.Flags().GetBool("pretty")
	fields, _ := cmd.Flags().GetStringSlice("fields")
	compress, _ := cmd.Flags().GetBool("compress")

	// Validate format
	if !isValidExportFormat(format) {
		return fmt.Errorf("unsupported export format: %s", format)
	}

	// Create services
	discoveryService := discovery.NewService(config)
	defer discoveryService.Close()

	var validationService *validation.Service
	if includeValidation {
		validationService = validation.NewService(config)
		defer validationService.Close()
	}

	// Discover and validate
	ctx := context.Background()
	exportData, err := gatherExportData(ctx, domain, discoveryService, validationService, ExportOptions{
		IncludeValidation: includeValidation,
		IncludeRaw:        includeRaw,
		IncludeMetadata:   includeMetadata,
		Fields:            fields,
	})
	if err != nil {
		return fmt.Errorf("failed to gather export data: %w", err)
	}

	// Create exporter
	exporter, err := createExporter(format, ExporterOptions{
		Pretty:       pretty,
		TemplateFile: templateFile,
		Compress:     compress,
	})
	if err != nil {
		return fmt.Errorf("failed to create exporter: %w", err)
	}

	// Export data
	exportedData, err := exporter.Export(exportData)
	if err != nil {
		return fmt.Errorf("failed to export data: %w", err)
	}

	// Write output
	if outputFile != "" {
		err = writeToFile(outputFile, exportedData)
		if err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		
		if !config.Output.Quiet {
			fmt.Fprintf(os.Stderr, "Exported to: %s\n", outputFile)
		}
	} else {
		fmt.Print(string(exportedData))
	}

	return nil
}

// ExportOptions holds export configuration
type ExportOptions struct {
	IncludeValidation bool
	IncludeRaw        bool
	IncludeMetadata   bool
	Fields            []string
}

// ExporterOptions holds exporter configuration
type ExporterOptions struct {
	Pretty       bool
	TemplateFile string
	Compress     bool
}

// ExportData holds all data for export
type ExportData struct {
	Domain           string                 `json:"domain"`
	Timestamp        time.Time              `json:"timestamp"`
	Found            bool                   `json:"found"`
	SourceURL        string                 `json:"source_url,omitempty"`
	SecurityTxt      map[string][]string    `json:"security_txt,omitempty"`
	RawContent       string                 `json:"raw_content,omitempty"`
	ValidationReport *ValidationExport      `json:"validation,omitempty"`
	Metadata         *MetadataExport        `json:"metadata,omitempty"`
}

// ValidationExport holds validation data for export
type ValidationExport struct {
	Score   int                     `json:"score"`
	Grade   string                  `json:"grade"`
	Issues  []ValidationIssueExport `json:"issues"`
	Summary string                  `json:"summary"`
}

// ValidationIssueExport holds validation issue data for export
type ValidationIssueExport struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	Field       string `json:"field,omitempty"`
	Line        int    `json:"line,omitempty"`
	Suggestion  string `json:"suggestion,omitempty"`
}

// MetadataExport holds metadata for export
type MetadataExport struct {
	DiscoveryAttempts []string  `json:"discovery_attempts"`
	ResponseTime      string    `json:"response_time"`
	ContentLength     int       `json:"content_length"`
	LastModified      string    `json:"last_modified,omitempty"`
	ETag              string    `json:"etag,omitempty"`
	ServerHeader      string    `json:"server,omitempty"`
}

// Exporter interface for different export formats
type Exporter interface {
	Export(data *ExportData) ([]byte, error)
}

// gatherExportData collects all data for export
func gatherExportData(ctx context.Context, domain string, discoveryService *discovery.Service,
	validationService *validation.Service, options ExportOptions) (*ExportData, error) {
	
	exportData := &ExportData{
		Domain:    domain,
		Timestamp: time.Now(),
	}

	// Discover security.txt
	result, err := discoveryService.Discover(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("discovery failed: %w", err)
	}

	exportData.Found = result.Found
	if result.Found {
		exportData.SourceURL = result.SecurityTxt.SourceURL
		exportData.SecurityTxt = filterFields(result.SecurityTxt.Fields, options.Fields)
		
		if options.IncludeRaw {
			exportData.RawContent = result.SecurityTxt.RawContent
		}
	}

	// Add validation data
	if options.IncludeValidation && validationService != nil && result.Found {
		report, err := validationService.ValidateDomain(ctx, domain)
		if err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}

		exportData.ValidationReport = &ValidationExport{
			Score:   report.Score,
			Grade:   report.Grade,
			Summary: fmt.Sprintf("Score: %d/100, Grade: %s", report.Score, report.Grade),
			Issues:  make([]ValidationIssueExport, len(report.Issues)),
		}

		for i, issue := range report.Issues {
			exportData.ValidationReport.Issues[i] = ValidationIssueExport{
				Type:       issue.Type,
				Severity:   issue.Severity,
				Message:    issue.Message,
				Field:      issue.Field,
				Line:       issue.Line,
				Suggestion: issue.Suggestion,
			}
		}
	}

	// Add metadata
	if options.IncludeMetadata {
		exportData.Metadata = &MetadataExport{
			DiscoveryAttempts: []string{
				"https://" + domain + "/.well-known/security.txt",
				"https://" + domain + "/security.txt",
			},
			ResponseTime:  "0ms", // Placeholder
			ContentLength: len(exportData.RawContent),
		}
	}

	return exportData, nil
}

// filterFields filters fields based on the specified field list
func filterFields(fields map[string][]string, filterList []string) map[string][]string {
	if len(filterList) == 0 {
		return fields
	}

	filtered := make(map[string][]string)
	for _, field := range filterList {
		if values, exists := fields[field]; exists {
			filtered[field] = values
		}
	}
	return filtered
}

// createExporter creates an exporter for the specified format
func createExporter(format string, options ExporterOptions) (Exporter, error) {
	switch strings.ToLower(format) {
	case "json":
		return &JSONExporter{Pretty: options.Pretty}, nil
	case "yaml":
		return &YAMLExporter{}, nil
	case "csv":
		return &CSVExporter{}, nil
	case "xml":
		return &XMLExporter{Pretty: options.Pretty}, nil
	case "sarif":
		return &SARIFExporter{}, nil
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// isValidExportFormat checks if the format is supported
func isValidExportFormat(format string) bool {
	validFormats := []string{"json", "yaml", "csv", "xml", "sarif"}
	for _, valid := range validFormats {
		if strings.ToLower(format) == valid {
			return true
		}
	}
	return false
}

// writeToFile writes data to a file
func writeToFile(filename string, data []byte) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	if dir != "." {
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	// Write file
	err := os.WriteFile(filename, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// JSONExporter exports data as JSON
type JSONExporter struct {
	Pretty bool
}

func (e *JSONExporter) Export(data *ExportData) ([]byte, error) {
	formatter, err := output.GetFormatter("json")
	if err != nil {
		return nil, err
	}
	
	result, err := formatter.Format(data)
	if err != nil {
		return nil, err
	}
	
	return []byte(result), nil
}

// YAMLExporter exports data as YAML
type YAMLExporter struct{}

func (e *YAMLExporter) Export(data *ExportData) ([]byte, error) {
	formatter, err := output.GetFormatter("yaml")
	if err != nil {
		return nil, err
	}
	
	result, err := formatter.Format(data)
	if err != nil {
		return nil, err
	}
	
	return []byte(result), nil
}

// CSVExporter exports data as CSV
type CSVExporter struct{}

func (e *CSVExporter) Export(data *ExportData) ([]byte, error) {
	// Simple CSV implementation
	csv := "Domain,Found,Score,Grade,Issues\n"
	issueCount := 0
	if data.ValidationReport != nil {
		issueCount = len(data.ValidationReport.Issues)
	}
	
	score := "N/A"
	grade := "N/A"
	if data.ValidationReport != nil {
		score = fmt.Sprintf("%d", data.ValidationReport.Score)
		grade = data.ValidationReport.Grade
	}
	
	csv += fmt.Sprintf("%s,%t,%s,%s,%d\n", data.Domain, data.Found, score, grade, issueCount)
	return []byte(csv), nil
}

// XMLExporter exports data as XML
type XMLExporter struct {
	Pretty bool
}

func (e *XMLExporter) Export(data *ExportData) ([]byte, error) {
	// Simple XML implementation
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<security-txt-export>
  <domain>` + data.Domain + `</domain>
  <found>` + fmt.Sprintf("%t", data.Found) + `</found>
  <timestamp>` + data.Timestamp.Format(time.RFC3339) + `</timestamp>
</security-txt-export>`
	
	return []byte(xml), nil
}

// SARIFExporter exports data as SARIF (Static Analysis Results Interchange Format)
type SARIFExporter struct{}

func (e *SARIFExporter) Export(data *ExportData) ([]byte, error) {
	// Basic SARIF structure
	sarif := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":    "securitytxt-cli",
						"version": "1.0.0",
					},
				},
				"results": []map[string]interface{}{},
			},
		},
	}
	
	formatter, err := output.GetFormatter("json")
	if err != nil {
		return nil, err
	}
	
	result, err := formatter.Format(sarif)
	if err != nil {
		return nil, err
	}
	
	return []byte(result), nil
}