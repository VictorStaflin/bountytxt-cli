package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/victorstaflin/bountytxt-cli/internal/discovery"
	"github.com/victorstaflin/bountytxt-cli/internal/output"
)

// findCmd represents the find command
var findCmd = &cobra.Command{
	Use:   "find [domain]",
	Short: "Find security.txt files for a domain",
	Long: `Find and discover security.txt files for a given domain.

This command searches for security.txt files at the standard RFC 9116 locations:
- /.well-known/security.txt (preferred)
- /security.txt (fallback)

The command will also try common variations like www subdomain if the
initial discovery fails.

Examples:
  securitytxt-cli find example.com
  securitytxt-cli find example.com --output json
  securitytxt-cli find example.com --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runFind,
}

func init() {
	// Command-specific flags
	findCmd.Flags().Bool("show-attempts", false, "show all discovery attempts")
	findCmd.Flags().Bool("include-raw", false, "include raw security.txt content in output")
}

func runFind(cmd *cobra.Command, args []string) error {
	domain := args[0]

	// Create discovery service
	discoveryService := discovery.NewService(config)
	defer discoveryService.Close()

	// Create output formatter
	formatter, err := output.GetFormatter(config.Output.Format)
	if err != nil {
		return fmt.Errorf("failed to create output formatter: %w", err)
	}

	// Discover security.txt
	ctx := context.Background()
	result, err := discoveryService.Discover(ctx, domain)
	if err != nil {
		if config.Output.Quiet {
			os.Exit(1)
		}
		return fmt.Errorf("discovery failed: %w", err)
	}

	// Format and output - pass the discovery result directly
	output, err := formatter.Format(result)
	if err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	fmt.Print(output)

	// Exit with appropriate code
	if !result.Found {
		os.Exit(1)
	}

	return nil
}