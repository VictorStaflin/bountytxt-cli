package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/victorstaflin/bountytxt-cli/internal/bounty"
	"github.com/victorstaflin/bountytxt-cli/internal/core"
)

var programsCmd = &cobra.Command{
	Use:   "programs",
	Short: "Search and list bug bounty programs",
	Long: `Search and list bug bounty programs from various platforms. This command allows you to:

- Search for programs by name, industry, or keywords
- Filter by platform (HackerOne, Bugcrowd, etc.)
- Filter by status (active, paused, private)
- Filter by industry type
- Export results in various formats

Examples:
  securitytxt-cli programs --search "fintech"
  securitytxt-cli programs --platform hackerone --active
  securitytxt-cli programs --industry "Financial Services" --output json
  securitytxt-cli programs --search "github" --rewards`,
	RunE: runProgramsSearch,
}

var (
	searchQuery     string
	platformFilter  string
	industryFilter  string
	statusFilter    string
	activeOnly      bool
	showRewardsInfo bool
	limitResults    int
)

func init() {
	programsCmd.Flags().StringVar(&searchQuery, "search", "", "Search query for program names or keywords")
	programsCmd.Flags().StringVar(&platformFilter, "platform", "", "Filter by platform (hackerone, bugcrowd, intigriti)")
	programsCmd.Flags().StringVar(&industryFilter, "industry", "", "Filter by industry type")
	programsCmd.Flags().StringVar(&statusFilter, "status", "", "Filter by status (active, paused, private)")
	programsCmd.Flags().BoolVar(&activeOnly, "active", false, "Show only active programs")
	programsCmd.Flags().BoolVar(&showRewardsInfo, "rewards", false, "Include reward information")
	programsCmd.Flags().IntVar(&limitResults, "limit", 50, "Limit number of results")
	programsCmd.Flags().StringVar(&outputFormat, "output", "table", "Output format (table, json, yaml)")
}

func runProgramsSearch(cmd *cobra.Command, args []string) error {
	// Initialize config using the global config
	programConfig := &core.Config{
		Timeout:      30 * time.Second,
		MaxRedirects: 5,
		VerifyTLS:    true,
		UserAgent:    "securitytxt-cli/1.0.0",
		MaxRPS:       5,
		Concurrency:  10,
	}

	// Create bounty service
	service := bounty.NewService(programConfig)
	defer service.Close()

	// Build filters
	filters := make(map[string]string)
	if platformFilter != "" {
		filters["platform"] = platformFilter
	}
	if industryFilter != "" {
		filters["industry"] = industryFilter
	}
	if statusFilter != "" {
		filters["status"] = statusFilter
	}
	if activeOnly {
		filters["status"] = "active"
	}

	// Search for programs
	programs, err := service.SearchPrograms(searchQuery, filters)
	if err != nil {
		return fmt.Errorf("failed to search programs: %w", err)
	}

	// Limit results
	if limitResults > 0 && len(programs) > limitResults {
		programs = programs[:limitResults]
	}

	// Output results
	return outputProgramsResults(programs, outputFormat)
}

func outputProgramsResults(programs []*bounty.Program, format string) error {
	if len(programs) == 0 {
		fmt.Println("No bug bounty programs found matching your criteria.")
		return nil
	}

	switch strings.ToLower(format) {
	case "json":
		return outputProgramsJSON(programs)
	case "yaml":
		return outputProgramsYAML(programs)
	default:
		return outputProgramsTable(programs)
	}
}

func outputProgramsJSON(programs []*bounty.Program) error {
	// Use the same JSON output as bounty command
	for i, program := range programs {
		if i > 0 {
			fmt.Println(",")
		}
		if err := outputJSON(program); err != nil {
			return err
		}
	}
	return nil
}

func outputProgramsYAML(programs []*bounty.Program) error {
	fmt.Println("# Bug Bounty Programs Search Results")
	for i, program := range programs {
		fmt.Printf("# Program %d\n", i+1)
		if err := outputYAML(program); err != nil {
			return err
		}
		fmt.Println("---")
	}
	return nil
}

func outputProgramsTable(programs []*bounty.Program) error {
	fmt.Printf("Found %d bug bounty programs:\n", len(programs))
	fmt.Println(strings.Repeat("=", 80))
	
	for i, program := range programs {
		fmt.Printf("\n%d. %s (%s)\n", i+1, program.Name, program.Domain)
		fmt.Println(strings.Repeat("-", 40))
		
		// Basic information
		fmt.Printf("Platform: %s\n", program.Platform)
		fmt.Printf("Status: %s\n", program.Status)
		fmt.Printf("Type: %s\n", program.Type)
		fmt.Printf("Industry: %s\n", program.Industry)
		
		if program.URL != "" {
			fmt.Printf("URL: %s\n", program.URL)
		}

		// Reward information if requested
		if showRewardsInfo {
			if program.RewardRange.HasBounties {
				fmt.Printf("Rewards: %s%d - %s%d (%s)\n", 
					program.RewardRange.Currency, program.RewardRange.Minimum,
					program.RewardRange.Currency, program.RewardRange.Maximum,
					program.RewardRange.Type)
			} else {
				fmt.Printf("Rewards: %s\n", program.RewardRange.Type)
			}
		}

		// Contact information
		if len(program.SecurityTxtInfo.ContactEmails) > 0 {
			fmt.Printf("Contacts: %s\n", strings.Join(program.SecurityTxtInfo.ContactEmails, ", "))
		}

		// Languages
		if len(program.Languages) > 0 {
			fmt.Printf("Languages: %s\n", strings.Join(program.Languages, ", "))
		}

		// Scope summary
		if program.Scope.AssetCount > 0 {
			fmt.Printf("Assets in Scope: %d", program.Scope.AssetCount)
			if program.Scope.Subdomains {
				fmt.Printf(" (includes subdomains)")
			}
			if program.Scope.Wildcards {
				fmt.Printf(" (includes wildcards)")
			}
			fmt.Println()
		}

		// Response times
		if program.ResponseTime.FirstResponse != "" {
			fmt.Printf("Response Time: %s (first response)\n", program.ResponseTime.FirstResponse)
		}

		fmt.Printf("Last Updated: %s\n", program.LastUpdated.Format("2006-01-02"))
	}

	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("\nTotal: %d programs found\n", len(programs))
	
	if len(programs) == limitResults {
		fmt.Printf("Note: Results limited to %d programs. Use --limit to see more.\n", limitResults)
	}

	return nil
}