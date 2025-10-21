package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/victorstaflin/bountytxt-cli/internal/bounty"
	"github.com/victorstaflin/bountytxt-cli/internal/core"
)

var bountyCmd = &cobra.Command{
	Use:   "bounty [domain]",
	Short: "Analyze bug bounty programs from security.txt and external sources",
	Long: `Analyze bug bounty programs for a given domain. This command will:

- Parse security.txt for bug bounty program information
- Detect program platform (HackerOne, Bugcrowd, etc.)
- Analyze scope and asset information
- Estimate reward ranges based on program type
- Analyze response time expectations

Examples:
  securitytxt-cli bounty github.com
  securitytxt-cli bounty example.com --scope --rewards
  securitytxt-cli bounty hackerone.com --timeline --output json`,
	Args: cobra.ExactArgs(1),
	RunE: runBountyAnalysis,
}

var (
	showScope    bool
	showRewards  bool
	showTimeline bool
	showContacts bool
	outputFormat string
)

func init() {
	bountyCmd.Flags().BoolVar(&showScope, "scope", false, "Show detailed scope analysis")
	bountyCmd.Flags().BoolVar(&showRewards, "rewards", false, "Show reward range analysis")
	bountyCmd.Flags().BoolVar(&showTimeline, "timeline", false, "Show response time analysis")
	bountyCmd.Flags().BoolVar(&showContacts, "contacts", false, "Show contact information")
	bountyCmd.Flags().StringVar(&outputFormat, "output", "table", "Output format (table, json, yaml)")
}

func runBountyAnalysis(cmd *cobra.Command, args []string) error {
	domain := args[0]

	// Initialize config using the global config
	bountyConfig := &core.Config{
		Timeout:      30 * time.Second,
		MaxRedirects: 5,
		VerifyTLS:    true,
		UserAgent:    "securitytxt-cli/1.0.0",
		MaxRPS:       5,
		Concurrency:  10,
	}

	// Create bounty service
	service := bounty.NewService(bountyConfig)
	defer service.Close()

	// Analyze the program
	program, err := service.AnalyzeProgram(domain)
	if err != nil {
		return fmt.Errorf("failed to analyze bug bounty program: %w", err)
	}

	// Output the results
	return outputBountyResults(program, outputFormat)
}

func outputBountyResults(program *bounty.Program, format string) error {
	switch strings.ToLower(format) {
	case "json":
		return outputJSON(program)
	case "yaml":
		return outputYAML(program)
	default:
		return outputTable(program)
	}
}

func outputJSON(program *bounty.Program) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(program)
}

func outputYAML(program *bounty.Program) error {
	// For now, use JSON format as YAML implementation would require additional dependency
	fmt.Println("# Bug Bounty Program Analysis (YAML format)")
	return outputJSON(program)
}

func outputTable(program *bounty.Program) error {
	fmt.Printf("Bug Bounty Program Analysis for: %s\n", program.Domain)
	fmt.Println(strings.Repeat("=", 60))

	// Basic Information
	fmt.Printf("Program Name: %s\n", program.Name)
	fmt.Printf("Platform: %s\n", program.Platform)
	fmt.Printf("Status: %s\n", program.Status)
	fmt.Printf("Type: %s\n", program.Type)
	fmt.Printf("Industry: %s\n", program.Industry)

	if program.URL != "" {
		fmt.Printf("Program URL: %s\n", program.URL)
	}

	fmt.Println()

	// Security.txt Information
	if program.SecurityTxtInfo.HasSecurityTxt {
		fmt.Println("Security.txt Information:")
		fmt.Println(strings.Repeat("-", 30))
		if program.SecurityTxtInfo.PolicyURL != "" {
			fmt.Printf("Policy URL: %s\n", program.SecurityTxtInfo.PolicyURL)
		}
		if len(program.SecurityTxtInfo.ContactEmails) > 0 {
			fmt.Printf("Contact Emails: %s\n", strings.Join(program.SecurityTxtInfo.ContactEmails, ", "))
		}
		if len(program.SecurityTxtInfo.PreferredLangs) > 0 {
			fmt.Printf("Preferred Languages: %s\n", strings.Join(program.SecurityTxtInfo.PreferredLangs, ", "))
		}
		if program.SecurityTxtInfo.Acknowledgment != "" {
			fmt.Printf("Acknowledgments: %s\n", program.SecurityTxtInfo.Acknowledgment)
		}
		fmt.Println()
	}

	// Reward Information
	if showRewards || program.RewardRange.HasBounties {
		fmt.Println("Reward Information:")
		fmt.Println(strings.Repeat("-", 30))
		if program.RewardRange.HasBounties {
			fmt.Printf("Has Bounties: Yes\n")
			if program.RewardRange.Minimum > 0 || program.RewardRange.Maximum > 0 {
				fmt.Printf("Reward Range: %s%d - %s%d\n",
					program.RewardRange.Currency, program.RewardRange.Minimum,
					program.RewardRange.Currency, program.RewardRange.Maximum)
			}
		} else {
			fmt.Printf("Has Bounties: No\n")
		}
		fmt.Printf("Program Type: %s\n", program.RewardRange.Type)
		fmt.Println()
	}

	// Scope Information
	if showScope || len(program.Scope.InScope) > 0 {
		fmt.Println("Scope Information:")
		fmt.Println(strings.Repeat("-", 30))
		fmt.Printf("Total Assets: %d\n", program.Scope.AssetCount)
		fmt.Printf("Includes Subdomains: %t\n", program.Scope.Subdomains)
		fmt.Printf("Includes Wildcards: %t\n", program.Scope.Wildcards)

		if len(program.Scope.InScope) > 0 {
			fmt.Println("\nIn-Scope Assets:")
			for _, asset := range program.Scope.InScope {
				fmt.Printf("  - %s (%s): %s\n", asset.Target, asset.Type, asset.Description)
				if len(asset.VulnTypes) > 0 {
					fmt.Printf("    Allowed: %s\n", strings.Join(asset.VulnTypes, ", "))
				}
				if len(asset.Exclusions) > 0 {
					fmt.Printf("    Excluded: %s\n", strings.Join(asset.Exclusions, ", "))
				}
			}
		}

		if len(program.Scope.OutOfScope) > 0 {
			fmt.Println("\nOut-of-Scope Assets:")
			for _, asset := range program.Scope.OutOfScope {
				fmt.Printf("  - %s (%s): %s\n", asset.Target, asset.Type, asset.Description)
			}
		}
		fmt.Println()
	}

	// Response Time Information
	if showTimeline || program.ResponseTime.FirstResponse != "" {
		fmt.Println("Response Time Information:")
		fmt.Println(strings.Repeat("-", 30))
		if program.ResponseTime.FirstResponse != "" {
			fmt.Printf("First Response: %s\n", program.ResponseTime.FirstResponse)
		}
		if program.ResponseTime.Triage != "" {
			fmt.Printf("Triage Time: %s\n", program.ResponseTime.Triage)
		}
		if program.ResponseTime.Resolution != "" {
			fmt.Printf("Resolution Time: %s\n", program.ResponseTime.Resolution)
		}
		if program.ResponseTime.SLA != "" {
			fmt.Printf("SLA: %s\n", program.ResponseTime.SLA)
		}
		fmt.Println()
	}

	// Contact Information
	if showContacts && len(program.SecurityTxtInfo.ContactEmails) > 0 {
		fmt.Println("Contact Information:")
		fmt.Println(strings.Repeat("-", 30))
		for _, email := range program.SecurityTxtInfo.ContactEmails {
			fmt.Printf("Email: %s\n", email)
		}
		fmt.Println()
	}

	// Metadata
	if len(program.Metadata) > 0 {
		fmt.Println("Additional Information:")
		fmt.Println(strings.Repeat("-", 30))
		for key, value := range program.Metadata {
			fmt.Printf("%s: %s\n", key, value)
		}
		fmt.Println()
	}

	fmt.Printf("Last Updated: %s\n", program.LastUpdated.Format("2006-01-02 15:04:05"))

	return nil
}
