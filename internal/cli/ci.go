package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/victorstaflin/bountytxt-cli/internal/core"
	"github.com/victorstaflin/bountytxt-cli/internal/output"
	"github.com/victorstaflin/bountytxt-cli/internal/validation"
)

// ciCmd represents the ci command
var ciCmd = &cobra.Command{
	Use:   "ci [domain]",
	Short: "CI/CD integration with proper exit codes and structured logging",
	Long: `CI/CD integration command designed for automated pipelines and continuous monitoring.

This command provides:
- Structured logging compatible with GitHub Actions and other CI systems
- Proper exit codes for pipeline integration
- Configurable validation thresholds
- Machine-readable output formats
- Error categorization for different failure types

Exit codes:
  0 - Success (security.txt found and valid)
  1 - Not found (no security.txt file)
  2 - Invalid (security.txt found but validation failed)
  3 - Error (network, parsing, or other errors)
  4 - Threshold not met (score/grade below minimum)

Examples:
  securitytxt-cli ci example.com
  securitytxt-cli ci example.com --min-score 80 --fail-on warnings
  securitytxt-cli ci example.com --output json --github-actions
  securitytxt-cli ci example.com --enforce-https --require-expires`,
	Args: cobra.ExactArgs(1),
	RunE: runCI,
}

func init() {
	// CI-specific flags
	ciCmd.Flags().Int("min-score", 70, "minimum validation score (0-100)")
	ciCmd.Flags().String("min-grade", "C", "minimum validation grade (A, B, C, D, F)")
	ciCmd.Flags().StringSlice("fail-on", []string{"error"}, "fail on issue types (error, warning, hint)")
	ciCmd.Flags().Bool("enforce-https", true, "require HTTPS for security.txt")
	ciCmd.Flags().Bool("require-expires", true, "require valid Expires field")
	ciCmd.Flags().Bool("require-contact", true, "require at least one Contact field")
	ciCmd.Flags().Bool("github-actions", false, "enable GitHub Actions compatible output")
	ciCmd.Flags().Bool("strict", false, "enable strict validation mode")
	ciCmd.Flags().StringSlice("ignore-issues", []string{}, "ignore specific issue types")
	ciCmd.Flags().Bool("allow-http", false, "allow HTTP security.txt (overrides enforce-https)")
}

func runCI(cmd *cobra.Command, args []string) error {
	domain := args[0]

	// Get flag values
	minScore, _ := cmd.Flags().GetInt("min-score")
	minGrade, _ := cmd.Flags().GetString("min-grade")
	failOn, _ := cmd.Flags().GetStringSlice("fail-on")
	enforceHTTPS, _ := cmd.Flags().GetBool("enforce-https")
	requireExpires, _ := cmd.Flags().GetBool("require-expires")
	requireContact, _ := cmd.Flags().GetBool("require-contact")
	githubActions, _ := cmd.Flags().GetBool("github-actions")
	strict, _ := cmd.Flags().GetBool("strict")
	ignoreIssues, _ := cmd.Flags().GetStringSlice("ignore-issues")
	allowHTTP, _ := cmd.Flags().GetBool("allow-http")

	// Override enforce-https if allow-http is set
	if allowHTTP {
		enforceHTTPS = false
	}

	// Create validation service
	validationService := validation.NewService(config)
	defer validationService.Close()

	// Create output formatter
	formatter, err := output.GetFormatter(config.Output.Format)
	if err != nil {
		return exitWithCode(core.ExitCodeError, fmt.Sprintf("Failed to create output formatter: %v", err), githubActions)
	}

	// Validate domain
	ctx := context.Background()
	report, err := validationService.ValidateDomain(ctx, domain)
	if err != nil {
		return exitWithCode(core.ExitCodeError, fmt.Sprintf("Validation failed: %v", err), githubActions)
	}

	// Check if security.txt was found
	if !report.Found {
		return exitWithCode(core.ExitCodeNotFound, fmt.Sprintf("No security.txt found for domain: %s", domain), githubActions)
	}

	// Apply CI-specific validation rules
	ciResult := applyCIValidation(report, CIValidationOptions{
		MinScore:       minScore,
		MinGrade:       minGrade,
		FailOn:         failOn,
		EnforceHTTPS:   enforceHTTPS,
		RequireExpires: requireExpires,
		RequireContact: requireContact,
		Strict:         strict,
		IgnoreIssues:   ignoreIssues,
	})

	// Prepare output data
	outputData := map[string]interface{}{
		"domain":     report.Domain,
		"source_url": report.SourceURL,
		"found":      report.Found,
		"score":      report.Score,
		"grade":      report.Grade,
		"passed":     ciResult.Passed,
		"exit_code":  ciResult.ExitCode,
		"issues":     filterIssues(report.Issues, ignoreIssues),
		"ci_summary": ciResult.Summary,
	}

	// Add GitHub Actions specific output
	if githubActions {
		outputData["github_actions"] = generateGitHubActionsOutput(ciResult, report)
	}

	// Format and output
	output, err := formatter.Format(outputData)
	if err != nil {
		return exitWithCode(core.ExitCodeError, fmt.Sprintf("Failed to format output: %v", err), githubActions)
	}

	fmt.Print(output)

	// Output GitHub Actions annotations
	if githubActions {
		outputGitHubActionsAnnotations(report, ciResult)
	}

	// Exit with appropriate code
	if !ciResult.Passed {
		os.Exit(ciResult.ExitCode)
	}

	return nil
}

// CIValidationOptions holds CI-specific validation options
type CIValidationOptions struct {
	MinScore       int
	MinGrade       string
	FailOn         []string
	EnforceHTTPS   bool
	RequireExpires bool
	RequireContact bool
	Strict         bool
	IgnoreIssues   []string
}

// CIResult holds the result of CI validation
type CIResult struct {
	Passed   bool     `json:"passed"`
	ExitCode int      `json:"exit_code"`
	Summary  string   `json:"summary"`
	Reasons  []string `json:"reasons,omitempty"`
}

// applyCIValidation applies CI-specific validation rules
func applyCIValidation(report *core.LintReport, options CIValidationOptions) CIResult {
	result := CIResult{
		Passed:   true,
		ExitCode: core.ExitCodeSuccess,
		Reasons:  make([]string, 0),
	}

	// Check minimum score
	if report.Score < options.MinScore {
		result.Passed = false
		result.ExitCode = core.ExitCodeThresholdNotMet
		result.Reasons = append(result.Reasons, fmt.Sprintf("Score %d below minimum %d", report.Score, options.MinScore))
	}

	// Check minimum grade
	if options.MinGrade != "" {
		gradeValues := map[string]int{
			"A": 90, "B": 80, "C": 70, "D": 60, "F": 0,
		}

		if requiredScore, exists := gradeValues[strings.ToUpper(options.MinGrade)]; exists {
			if report.Score < requiredScore {
				result.Passed = false
				result.ExitCode = core.ExitCodeThresholdNotMet
				result.Reasons = append(result.Reasons, fmt.Sprintf("Grade %s below minimum %s", report.Grade, options.MinGrade))
			}
		}
	}

	// Check fail-on conditions
	for _, issue := range report.Issues {
		if contains(options.FailOn, strings.ToLower(issue.Severity)) && !contains(options.IgnoreIssues, issue.Type) {
			result.Passed = false
			if result.ExitCode == core.ExitCodeSuccess {
				result.ExitCode = core.ExitCodeInvalid
			}
			result.Reasons = append(result.Reasons, fmt.Sprintf("Failed on %s: %s", issue.Severity, issue.Message))
		}
	}

	// CI-specific requirements
	// Check HTTPS requirement - use the actual source URL from discovery result
	sourceURL := report.SourceURL
	if sourceURL == "" && report.DiscoveryResult != nil {
		sourceURL = report.DiscoveryResult.SourceURL
	}
	if options.EnforceHTTPS && !strings.HasPrefix(sourceURL, "https://") {
		result.Passed = false
		result.ExitCode = core.ExitCodeInvalid
		result.Reasons = append(result.Reasons, "HTTPS required but security.txt served over HTTP")
	}

	if options.RequireExpires {
		hasValidExpires := false
		// Check if there's a valid Expires field in the security.txt
		if report.DiscoveryResult != nil && report.DiscoveryResult.SecurityTxt != nil && report.DiscoveryResult.SecurityTxt.Expires != nil {
			hasValidExpires = true
		}
		// If not found in parsed data, check if Expires field exists in raw content
		if !hasValidExpires && report.DiscoveryResult != nil && report.DiscoveryResult.SecurityTxt != nil {
			rawContent := report.DiscoveryResult.SecurityTxt.RawContent
			if strings.Contains(strings.ToLower(rawContent), "expires:") {
				hasValidExpires = true
			}
		}
		// Check if there are error-level issues with Expires field that would invalidate it
		for _, issue := range report.Issues {
			if issue.Field == "Expires" && issue.Severity == "error" {
				hasValidExpires = false
				break
			}
		}
		if !hasValidExpires {
			result.Passed = false
			result.ExitCode = core.ExitCodeInvalid
			result.Reasons = append(result.Reasons, "Expires field required but missing or invalid")
		}
	}

	if options.RequireContact {
		hasValidContact := false
		// Check if there are valid contacts in the security.txt
		if report.DiscoveryResult != nil && report.DiscoveryResult.SecurityTxt != nil && len(report.DiscoveryResult.SecurityTxt.Contact) > 0 {
			hasValidContact = true
		}
		// Also check if there are no error-level issues with Contact field
		for _, issue := range report.Issues {
			if issue.Field == "Contact" && issue.Severity == "error" {
				hasValidContact = false
				break
			}
		}
		if !hasValidContact {
			result.Passed = false
			result.ExitCode = core.ExitCodeInvalid
			result.Reasons = append(result.Reasons, "Contact field required but missing or invalid")
		}
	}

	// Generate summary
	if result.Passed {
		result.Summary = fmt.Sprintf("✅ Validation passed (Score: %d, Grade: %s)", report.Score, report.Grade)
	} else {
		result.Summary = fmt.Sprintf("❌ Validation failed: %s", strings.Join(result.Reasons, "; "))
	}

	return result
}

// filterIssues filters out ignored issues
func filterIssues(issues []core.ValidationIssue, ignoreIssues []string) []core.ValidationIssue {
	if len(ignoreIssues) == 0 {
		return issues
	}

	filtered := make([]core.ValidationIssue, 0)
	for _, issue := range issues {
		if !contains(ignoreIssues, issue.Type) {
			filtered = append(filtered, issue)
		}
	}
	return filtered
}

// generateGitHubActionsOutput generates GitHub Actions specific output
func generateGitHubActionsOutput(ciResult CIResult, report *core.LintReport) map[string]interface{} {
	conclusion := "failure"
	if ciResult.Passed {
		conclusion = "success"
	}

	return map[string]interface{}{
		"workflow_status": map[string]interface{}{
			"conclusion": conclusion,
			"output": map[string]string{
				"title":   fmt.Sprintf("Security.txt Validation - %s", report.Domain),
				"summary": ciResult.Summary,
			},
		},
		"step_outputs": map[string]interface{}{
			"found":      report.Found,
			"score":      report.Score,
			"grade":      report.Grade,
			"passed":     ciResult.Passed,
			"source_url": report.SourceURL,
		},
	}
}

// outputGitHubActionsAnnotations outputs GitHub Actions annotations
func outputGitHubActionsAnnotations(report *core.LintReport, ciResult CIResult) {
	// Output step summary
	fmt.Fprintf(os.Stderr, "::notice title=Security.txt Validation::%s\n", ciResult.Summary)

	// Output issues as annotations
	for _, issue := range report.Issues {
		level := "notice"
		switch strings.ToLower(issue.Severity) {
		case "error":
			level = "error"
		case "warning":
			level = "warning"
		}

		fmt.Fprintf(os.Stderr, "::%s title=%s::%s\n", level, issue.Type, issue.Message)
	}

	// Set step outputs
	fmt.Fprintf(os.Stderr, "::set-output name=found::%t\n", report.Found)
	fmt.Fprintf(os.Stderr, "::set-output name=score::%d\n", report.Score)
	fmt.Fprintf(os.Stderr, "::set-output name=grade::%s\n", report.Grade)
	fmt.Fprintf(os.Stderr, "::set-output name=passed::%t\n", ciResult.Passed)
	fmt.Fprintf(os.Stderr, "::set-output name=source_url::%s\n", report.SourceURL)
}

// exitWithCode exits with the specified code and message
func exitWithCode(code int, message string, githubActions bool) error {
	if githubActions {
		level := "error"
		if code == core.ExitCodeNotFound {
			level = "warning"
		}
		fmt.Fprintf(os.Stderr, "::%s::%s\n", level, message)
	} else if !config.Output.Quiet {
		fmt.Fprintf(os.Stderr, "Error: %s\n", message)
	}

	os.Exit(code)
	return nil // Never reached
}
