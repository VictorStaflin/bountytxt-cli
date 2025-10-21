package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/victorstaflin/bountytxt-cli/internal/core"
	"github.com/victorstaflin/bountytxt-cli/internal/output"
	"github.com/victorstaflin/bountytxt-cli/internal/validation"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify [domain]",
	Short: "Verify and validate security.txt files",
	Long: `Verify and validate security.txt files for RFC 9116 compliance.

This command discovers security.txt files and performs comprehensive validation
including format checking, field validation, expiration checking, and best
practice recommendations.

The validation engine provides a score from 0-100 and assigns a grade (A-F)
based on compliance and best practices.

Examples:
  securitytxt-cli verify example.com
  securitytxt-cli verify example.com --output json
  securitytxt-cli verify example.com --show-issues
  securitytxt-cli verify example.com --min-score 80`,
	Args: cobra.ExactArgs(1),
	RunE: runVerify,
}

func init() {
	// Command-specific flags
	verifyCmd.Flags().Bool("show-issues", true, "show validation issues")
	verifyCmd.Flags().Bool("show-discovery", false, "show discovery details")
	verifyCmd.Flags().Int("min-score", 0, "minimum score required (exit 1 if below)")
	verifyCmd.Flags().String("min-grade", "", "minimum grade required (A, B, C, D, F)")
	verifyCmd.Flags().StringSlice("ignore-issues", []string{}, "issue categories to ignore (format, expiration, security, etc.)")
}

func runVerify(cmd *cobra.Command, args []string) error {
	domain := args[0]
	
	// Get flag values
	minScore, _ := cmd.Flags().GetInt("min-score")
	minGrade, _ := cmd.Flags().GetString("min-grade")
	ignoreIssues, _ := cmd.Flags().GetStringSlice("ignore-issues")

	// Create validation service
	validationService := validation.NewService(config)
	defer validationService.Close()

	// Create output formatter
	formatter, err := output.GetFormatter(config.Output.Format)
	if err != nil {
		return fmt.Errorf("failed to create output formatter: %w", err)
	}

	// Validate domain
	ctx := context.Background()
	report, err := validationService.ValidateDomain(ctx, domain)
	if err != nil {
		if config.Output.Quiet {
			os.Exit(1)
		}
		return fmt.Errorf("validation failed: %w", err)
	}

	// Filter ignored issues
	if len(ignoreIssues) > 0 {
		filteredIssues := make([]core.Issue, 0)
		for _, issue := range report.Issues {
			ignored := false
			for _, ignoreCategory := range ignoreIssues {
				if issue.Category == ignoreCategory {
					ignored = true
					break
				}
			}
			if !ignored {
				filteredIssues = append(filteredIssues, issue)
			}
		}
		report.Issues = filteredIssues
	}

	// Format and output - pass the lint report directly
	output, err := formatter.Format(report)
	if err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	fmt.Print(output)

	// Check exit conditions
	exitCode := 0

	// Check minimum score
	if minScore > 0 && report.Score < minScore {
		if !config.Output.Quiet {
			fmt.Fprintf(os.Stderr, "Score %d is below minimum required score %d\n", report.Score, minScore)
		}
		exitCode = 1
	}

	// Check minimum grade
	if minGrade != "" {
		gradeValues := map[string]int{"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}
		if gradeValues[report.Grade] < gradeValues[minGrade] {
			if !config.Output.Quiet {
				fmt.Fprintf(os.Stderr, "Grade %s is below minimum required grade %s\n", report.Grade, minGrade)
			}
			exitCode = 1
		}
	}

	// Exit with error if no security.txt found
	if report.SourceURL == "" {
		exitCode = 1
	}

	if exitCode != 0 {
		os.Exit(exitCode)
	}

	return nil
}