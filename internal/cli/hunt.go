package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/victorstaflin/bountytxt-cli/internal/discovery"
	"github.com/victorstaflin/bountytxt-cli/internal/output"
)

// huntCmd represents the hunt command
var huntCmd = &cobra.Command{
	Use:   "hunt [domain]",
	Short: "Hunt for security.txt files with subdomain enumeration",
	Long: `Hunt for security.txt files across subdomains and related domains.

This command performs comprehensive discovery by:
- Checking the main domain
- Enumerating common subdomains (www, api, app, etc.)
- Checking wildcard subdomains
- Looking for related domains and services

Discovery includes:
- Standard RFC 9116 paths (/.well-known/security.txt, /security.txt)
- Common subdomain patterns
- Platform-specific discovery (GitHub, GitLab, etc.)

Examples:
  securitytxt-cli hunt example.com
  securitytxt-cli hunt example.com --subdomains www,api,app,dev
  securitytxt-cli hunt example.com --output json --found-only
  securitytxt-cli hunt example.com --include-wildcards --max-depth 2`,
	Args: cobra.ExactArgs(1),
	RunE: runHunt,
}

func init() {
	// Hunt-specific flags
	huntCmd.Flags().StringSlice("subdomains", []string{}, "custom subdomain list (default: common subdomains)")
	huntCmd.Flags().Bool("include-wildcards", false, "include wildcard subdomain discovery")
	huntCmd.Flags().Int("max-depth", 1, "maximum subdomain depth to check")
	huntCmd.Flags().Bool("found-only", false, "only show domains where security.txt was found")
	huntCmd.Flags().Bool("show-attempts", false, "show all discovery attempts")
	huntCmd.Flags().StringSlice("exclude", []string{}, "exclude specific subdomains")
	huntCmd.Flags().Int("max-subdomains", 50, "maximum number of subdomains to check")
}

func runHunt(cmd *cobra.Command, args []string) error {
	domain := args[0]
	
	// Get flag values
	customSubdomains, _ := cmd.Flags().GetStringSlice("subdomains")
	includeWildcards, _ := cmd.Flags().GetBool("include-wildcards")
	maxDepth, _ := cmd.Flags().GetInt("max-depth")
	foundOnly, _ := cmd.Flags().GetBool("found-only")
	showAttempts, _ := cmd.Flags().GetBool("show-attempts")
	exclude, _ := cmd.Flags().GetStringSlice("exclude")
	maxSubdomains, _ := cmd.Flags().GetInt("max-subdomains")

	// Create discovery service
	discoveryService := discovery.NewService(config)
	defer discoveryService.Close()

	// Create output formatter
	formatter, err := output.GetFormatter(config.Output.Format)
	if err != nil {
		return fmt.Errorf("failed to create output formatter: %w", err)
	}

	// Generate target domains
	targets := generateHuntTargets(domain, customSubdomains, includeWildcards, maxDepth, exclude, maxSubdomains)

	if config.Output.Verbose {
		fmt.Fprintf(os.Stderr, "Hunting across %d targets for domain: %s\n", len(targets), domain)
	}

	// Hunt for security.txt files
	ctx := context.Background()
	results := make([]HuntResult, 0)
	foundCount := 0

	for _, target := range targets {
		result := huntSingleTarget(ctx, discoveryService, target, showAttempts)
		
		if result.Found {
			foundCount++
		}

		// Apply filters
		if foundOnly && !result.Found {
			continue
		}

		results = append(results, result)
	}

	// Convert results to interface{} slice for formatter
	resultsInterface := make([]interface{}, len(results))
	for i, result := range results {
		resultsInterface[i] = map[string]interface{}{
			"domain":     result.Domain,
			"found":      result.Found,
			"source_url": result.SourceURL,
			"attempts":   result.Attempts,
			"error":      result.Error,
			"type":       result.Type,
			"depth":      result.Depth,
		}
	}

	// Prepare output data
	outputData := map[string]interface{}{
		"base_domain":     domain,
		"targets_checked": len(targets),
		"found_count":     foundCount,
		"results":         resultsInterface,
	}

	// Format and output
	output, err := formatter.Format(outputData)
	if err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	fmt.Print(output)

	// Show summary if verbose
	if config.Output.Verbose {
		fmt.Fprintf(os.Stderr, "\nHunt complete: %d security.txt files found across %d targets\n", foundCount, len(targets))
	}

	return nil
}

// HuntResult represents the result of hunting a single target
type HuntResult struct {
	Domain      string   `json:"domain"`
	Found       bool     `json:"found"`
	SourceURL   string   `json:"source_url,omitempty"`
	Attempts    []string `json:"attempts,omitempty"`
	Error       string   `json:"error,omitempty"`
	Type        string   `json:"type"` // main, subdomain, wildcard
	Depth       int      `json:"depth"`
}

// generateHuntTargets generates a list of domains to hunt
func generateHuntTargets(baseDomain string, customSubdomains []string, includeWildcards bool, 
	maxDepth int, exclude []string, maxSubdomains int) []string {
	
	targets := make([]string, 0)
	seen := make(map[string]bool)
	
	// Add base domain
	targets = append(targets, baseDomain)
	seen[baseDomain] = true

	// Use custom subdomains if provided, otherwise use common ones
	subdomains := customSubdomains
	if len(subdomains) == 0 {
		subdomains = getCommonSubdomains()
	}

	// Add subdomains
	for _, subdomain := range subdomains {
		if len(targets) >= maxSubdomains {
			break
		}
		
		// Skip excluded subdomains
		if contains(exclude, subdomain) {
			continue
		}
		
		target := subdomain + "." + baseDomain
		if !seen[target] {
			targets = append(targets, target)
			seen[target] = true
		}
	}

	// Add wildcard patterns if requested
	if includeWildcards {
		wildcardTargets := generateWildcardTargets(baseDomain, maxDepth)
		for _, target := range wildcardTargets {
			if len(targets) >= maxSubdomains {
				break
			}
			if !seen[target] && !contains(exclude, strings.Split(target, ".")[0]) {
				targets = append(targets, target)
				seen[target] = true
			}
		}
	}

	return targets
}

// getCommonSubdomains returns a list of common subdomains to check
func getCommonSubdomains() []string {
	return []string{
		"www", "api", "app", "dev", "test", "staging", "prod", "production",
		"admin", "portal", "dashboard", "console", "panel", "manage", "management",
		"secure", "security", "auth", "login", "sso", "oauth", "accounts",
		"mail", "email", "smtp", "imap", "webmail", "mx",
		"ftp", "sftp", "files", "upload", "download", "cdn", "static", "assets",
		"blog", "news", "docs", "help", "support", "status", "health",
		"mobile", "m", "wap", "touch", "amp",
		"shop", "store", "cart", "checkout", "payment", "pay",
		"git", "gitlab", "github", "bitbucket", "code", "repo", "scm",
		"jenkins", "ci", "build", "deploy", "release",
		"monitoring", "metrics", "logs", "analytics", "stats",
		"vpn", "proxy", "gateway", "lb", "loadbalancer",
	}
}

// generateWildcardTargets generates wildcard subdomain patterns
func generateWildcardTargets(baseDomain string, maxDepth int) []string {
	targets := make([]string, 0)
	
	// Common wildcard patterns
	patterns := []string{
		"*", "test-*", "dev-*", "staging-*", "prod-*",
		"*-api", "*-app", "*-web", "*-service",
		"user-*", "client-*", "tenant-*", "org-*",
	}

	for _, pattern := range patterns {
		if maxDepth >= 1 {
			// Replace * with common values
			commonValues := []string{"1", "2", "3", "a", "b", "c", "test", "demo", "temp"}
			for _, value := range commonValues {
				target := strings.ReplaceAll(pattern, "*", value) + "." + baseDomain
				targets = append(targets, target)
			}
		}
	}

	return targets
}

// huntSingleTarget hunts for security.txt on a single target
func huntSingleTarget(ctx context.Context, discoveryService *discovery.Service, 
	target string, showAttempts bool) HuntResult {
	
	result := HuntResult{
		Domain: target,
		Type:   determineTargetType(target),
		Depth:  calculateDepth(target),
	}

	// Discover security.txt
	discoveryResult, err := discoveryService.Discover(ctx, target)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Found = discoveryResult.Found
	if discoveryResult.Found {
		result.SourceURL = discoveryResult.SecurityTxt.SourceURL
	}

	// Add attempts if requested
	if showAttempts {
		result.Attempts = []string{
			"https://" + target + "/.well-known/security.txt",
			"https://" + target + "/security.txt",
			"http://" + target + "/.well-known/security.txt",
			"http://" + target + "/security.txt",
		}
	}

	return result
}

// determineTargetType determines the type of target (main, subdomain, wildcard)
func determineTargetType(target string) string {
	parts := strings.Split(target, ".")
	if len(parts) <= 2 {
		return "main"
	}
	
	subdomain := parts[0]
	if strings.Contains(subdomain, "-") && (strings.Contains(subdomain, "1") || 
		strings.Contains(subdomain, "2") || strings.Contains(subdomain, "test")) {
		return "wildcard"
	}
	
	return "subdomain"
}

// calculateDepth calculates the subdomain depth
func calculateDepth(target string) int {
	parts := strings.Split(target, ".")
	return len(parts) - 2 // Subtract domain and TLD
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}