package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/victorstaflin/bountytxt-cli/internal/core"
	"github.com/victorstaflin/bountytxt-cli/internal/output"
	"github.com/victorstaflin/bountytxt-cli/internal/validation"
)

// bulkCmd represents the bulk command
var bulkCmd = &cobra.Command{
	Use:   "bulk [file]",
	Short: "Process multiple domains from file or stdin",
	Long: `Process multiple domains from a file or stdin for bulk security.txt discovery and validation.

This command reads domain names from a file (one per line) or from stdin and processes
them concurrently with configurable worker pools and rate limiting.

Input formats:
- Plain text file with one domain per line
- Stdin input (use "-" as filename)
- Comments (lines starting with #) are ignored
- Empty lines are ignored

Examples:
  securitytxt-cli bulk domains.txt
  securitytxt-cli bulk domains.txt --workers 10 --output jsonl
  cat domains.txt | securitytxt-cli bulk -
  securitytxt-cli bulk domains.txt --validate --min-score 80
  securitytxt-cli bulk domains.txt --continue-on-error --timeout 30s`,
	Args: cobra.ExactArgs(1),
	RunE: runBulk,
}

func init() {
	// Bulk processing flags
	bulkCmd.Flags().Int("workers", 5, "number of concurrent workers")
	bulkCmd.Flags().Duration("delay", 100*time.Millisecond, "delay between requests per domain")
	bulkCmd.Flags().Bool("validate", false, "validate discovered security.txt files")
	bulkCmd.Flags().Int("min-score", 0, "minimum validation score (0-100)")
	bulkCmd.Flags().String("min-grade", "", "minimum validation grade (A, B, C, D, F)")
	bulkCmd.Flags().Bool("continue-on-error", false, "continue processing on individual domain errors")
	bulkCmd.Flags().Bool("show-progress", false, "show progress information")
	bulkCmd.Flags().Bool("found-only", false, "only output domains with security.txt found")
	bulkCmd.Flags().Int("max-domains", 0, "maximum number of domains to process (0 = unlimited)")
}

func runBulk(cmd *cobra.Command, args []string) error {
	filename := args[0]

	// Get flag values
	workers, _ := cmd.Flags().GetInt("workers")
	delay, _ := cmd.Flags().GetDuration("delay")
	validate, _ := cmd.Flags().GetBool("validate")
	minScore, _ := cmd.Flags().GetInt("min-score")
	minGrade, _ := cmd.Flags().GetString("min-grade")
	continueOnError, _ := cmd.Flags().GetBool("continue-on-error")
	showProgress, _ := cmd.Flags().GetBool("show-progress")
	foundOnly, _ := cmd.Flags().GetBool("found-only")
	maxDomains, _ := cmd.Flags().GetInt("max-domains")

	// Read domains from file or stdin
	domains, err := readDomains(filename, maxDomains)
	if err != nil {
		return fmt.Errorf("failed to read domains: %w", err)
	}

	if len(domains) == 0 {
		return fmt.Errorf("no domains to process")
	}

	// Create output formatter
	formatter, err := output.GetFormatter(config.Output.Format)
	if err != nil {
		return fmt.Errorf("failed to create output formatter: %w", err)
	}

	// Create validation service if needed
	var validationService *validation.Service
	if validate {
		validationService = validation.NewService(config)
		defer validationService.Close()
	}

	// Configure bulk options
	bulkOptions := &core.BulkOptions{
		Workers:         workers,
		Delay:           delay,
		ContinueOnError: continueOnError,
		Validate:        validate,
		MinScore:        minScore,
		MinGrade:        minGrade,
		FoundOnly:       foundOnly,
	}

	// Process domains
	ctx := context.Background()
	results := make(chan *core.BulkResult, workers)

	go func() {
		defer close(results)
		processBulkDomains(ctx, domains, bulkOptions, validationService, results, showProgress)
	}()

	// Collect results
	var allResults []core.BulkResult
	totalProcessed := 0
	totalFound := 0
	totalPassed := 0

	for result := range results {
		totalProcessed++

		if result.Found {
			totalFound++
		}

		if result.ValidationPassed {
			totalPassed++
		}

		// Apply filters
		if foundOnly && !result.Found {
			continue
		}

		allResults = append(allResults, *result)
	}

	// Format and output all results together
	if len(allResults) > 0 {
		output, err := formatter.Format(allResults)
		if err != nil {
			return fmt.Errorf("failed to format output: %w", err)
		}
		fmt.Print(output)
	}

	// Show summary if verbose or progress was requested
	if config.Output.Verbose || showProgress {
		fmt.Fprintf(os.Stderr, "\nBulk processing complete:\n")
		fmt.Fprintf(os.Stderr, "  Processed: %d domains\n", totalProcessed)
		fmt.Fprintf(os.Stderr, "  Found: %d security.txt files\n", totalFound)
		if validate {
			fmt.Fprintf(os.Stderr, "  Passed validation: %d domains\n", totalPassed)
		}
	}

	return nil
}

// readDomains reads domain names from a file or stdin
func readDomains(filename string, maxDomains int) ([]string, error) {
	var file *os.File
	var err error

	if filename == "-" {
		file = os.Stdin
	} else {
		file, err = os.Open(filename)
		if err != nil {
			return nil, fmt.Errorf("failed to open file: %w", err)
		}
		defer file.Close()
	}

	domains := make([]string, 0)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Clean up domain name
		domain := cleanDomain(line)
		if domain != "" {
			domains = append(domains, domain)

			// Check max domains limit
			if maxDomains > 0 && len(domains) >= maxDomains {
				break
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return domains, nil
}

// cleanDomain cleans and normalizes domain names
func cleanDomain(domain string) string {
	// Remove protocol if present
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")

	// Remove path if present
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}

	// Remove port if present
	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}

	// Trim whitespace
	domain = strings.TrimSpace(domain)

	// Basic validation
	if domain == "" || !strings.Contains(domain, ".") {
		return ""
	}

	return domain
}

// processBulkDomains processes domains concurrently with worker pools
func processBulkDomains(ctx context.Context, domains []string, options *core.BulkOptions,
	validationService *validation.Service, results chan<- *core.BulkResult, showProgress bool) {

	// Create worker pool
	domainChan := make(chan string, len(domains))
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < options.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bulkWorker(ctx, domainChan, options, validationService, results, showProgress)
		}()
	}

	// Send domains to workers
	for _, domain := range domains {
		domainChan <- domain
	}
	close(domainChan)

	// Wait for all workers to complete
	wg.Wait()
}

// bulkWorker processes individual domains
func bulkWorker(ctx context.Context, domains <-chan string, options *core.BulkOptions,
	validationService *validation.Service, results chan<- *core.BulkResult, showProgress bool) {

	for domain := range domains {
		result := processSingleDomain(ctx, domain, options, validationService)

		if showProgress && !config.Output.Quiet {
			status := "NOT FOUND"
			if result.Found {
				status = "FOUND"
				if options.Validate && result.ValidationPassed {
					status = fmt.Sprintf("FOUND (Score: %d)", result.Score)
				}
			}
			if result.Error != "" {
				status = "ERROR"
			}
			fmt.Fprintf(os.Stderr, "Processed %s: %s\n", domain, status)
		}

		results <- result

		// Rate limiting delay
		if options.Delay > 0 {
			time.Sleep(options.Delay)
		}
	}
}

// processSingleDomain processes a single domain
func processSingleDomain(ctx context.Context, domain string, options *core.BulkOptions,
	validationService *validation.Service) *core.BulkResult {

	result := &core.BulkResult{
		Domain:      domain,
		ProcessedAt: time.Now(),
	}

	if options.Validate && validationService != nil {
		// Use validation service for discovery + validation
		report, err := validationService.ValidateDomain(ctx, domain)
		if err != nil {
			result.Error = err.Error()
			return result
		}

		result.Found = report.Found
		if report.Found {
			result.SourceURL = report.SourceURL
			result.Score = report.Score
			result.Grade = report.Grade
			result.Issues = report.Issues

			// Check if validation passed based on minimum requirements
			result.ValidationPassed = checkValidationPassed(report, options.MinScore, options.MinGrade)
		}
	} else {
		// Discovery only
		discoveryService := validation.NewService(config)
		defer discoveryService.Close()

		discoveryResult, err := discoveryService.ValidateDomain(ctx, domain)
		if err != nil {
			result.Error = err.Error()
			return result
		}

		result.Found = discoveryResult.Found
		if discoveryResult.Found {
			result.SourceURL = discoveryResult.SourceURL
		}
	}

	return result
}

// checkValidationPassed checks if validation meets minimum requirements
func checkValidationPassed(report *core.LintReport, minScore int, minGrade string) bool {
	// Check minimum score
	if minScore > 0 && report.Score < minScore {
		return false
	}

	// Check minimum grade
	if minGrade != "" {
		gradeValues := map[string]int{
			"A": 90, "B": 80, "C": 70, "D": 60, "F": 0,
		}

		requiredScore, exists := gradeValues[strings.ToUpper(minGrade)]
		if exists && report.Score < requiredScore {
			return false
		}
	}

	return true
}
