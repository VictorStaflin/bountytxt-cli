package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/victorstaflin/bountytxt-cli/internal/banner"
	"github.com/victorstaflin/bountytxt-cli/internal/core"
)

var (
	cfgFile string
	config  *core.Config
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "bountytxt",
	Short: "A CLI tool for discovering and validating RFC 9116 security.txt files",
	Long: `BountyTxt CLI is a comprehensive tool for discovering, validating, and analyzing
RFC 9116 security.txt files to find vulnerability disclosure contacts for domains.

The tool prioritizes legal and safe defaults, including HTTPS-only requests,
honoring robots.txt, and avoiding unsolicited messages.

Examples:
  bountytxt find example.com
  bountytxt verify example.com
  bountytxt contacts example.com
  bountytxt bulk domains.txt
  bountytxt hunt --platform hackerone
  bountytxt ci example.com`,
	Version: "1.0.0",
	Run: func(cmd *cobra.Command, args []string) {
		// Show banner when no subcommands are provided
		banner.PrintBanner()
	},
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.bountytxt.yaml)")
	rootCmd.PersistentFlags().String("output", "table", "output format (table, json, jsonl, yaml)")
	rootCmd.PersistentFlags().Bool("verbose", false, "verbose output")
	rootCmd.PersistentFlags().Bool("quiet", false, "quiet output (errors only)")
	rootCmd.PersistentFlags().Duration("timeout", 30*time.Second, "request timeout")
	rootCmd.PersistentFlags().Int("max-redirects", 5, "maximum number of redirects to follow")
	rootCmd.PersistentFlags().Bool("verify-tls", true, "verify TLS certificates")
	rootCmd.PersistentFlags().Bool("honor-robots", true, "honor robots.txt")
	rootCmd.PersistentFlags().Bool("public-mode", true, "enforce HTTPS-only and other public safety measures")
	rootCmd.PersistentFlags().String("user-agent", "bountytxt/1.0.0", "user agent string")
	rootCmd.PersistentFlags().Int("workers", 10, "number of concurrent workers for bulk operations")
	rootCmd.PersistentFlags().Float64("rate-limit", 5.0, "requests per second rate limit")
	rootCmd.PersistentFlags().Int("rate-burst", 10, "rate limit burst size")

	// Bind flags to viper
	viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("quiet", rootCmd.PersistentFlags().Lookup("quiet"))
	viper.BindPFlag("timeout", rootCmd.PersistentFlags().Lookup("timeout"))
	viper.BindPFlag("max-redirects", rootCmd.PersistentFlags().Lookup("max-redirects"))
	viper.BindPFlag("verify-tls", rootCmd.PersistentFlags().Lookup("verify-tls"))
	viper.BindPFlag("honor-robots", rootCmd.PersistentFlags().Lookup("honor-robots"))
	viper.BindPFlag("public-mode", rootCmd.PersistentFlags().Lookup("public-mode"))
	viper.BindPFlag("user-agent", rootCmd.PersistentFlags().Lookup("user-agent"))
	viper.BindPFlag("workers", rootCmd.PersistentFlags().Lookup("workers"))
	viper.BindPFlag("rate-limit", rootCmd.PersistentFlags().Lookup("rate-limit"))
	viper.BindPFlag("rate-burst", rootCmd.PersistentFlags().Lookup("rate-burst"))

	// Add subcommands
	rootCmd.AddCommand(findCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(contactsCmd)
	rootCmd.AddCommand(bulkCmd)
	rootCmd.AddCommand(huntCmd)
	rootCmd.AddCommand(ciCmd)
	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(bountyCmd)
	rootCmd.AddCommand(programsCmd)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".securitytxt-cli" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".bountytxt")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		if viper.GetBool("verbose") {
			fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		}
	}

	// Initialize global config
	config = &core.Config{
		Timeout:      viper.GetDuration("timeout"),
		MaxRedirects: viper.GetInt("max-redirects"),
		VerifyTLS:    viper.GetBool("verify-tls"),
		HonorRobots:  viper.GetBool("honor-robots"),
		PublicMode:   viper.GetBool("public-mode"),
		UserAgent:    viper.GetString("user-agent"),
		MaxRPS:       int(viper.GetFloat64("rate-limit")),
		Concurrency:  viper.GetInt("rate-burst"),
		Workers:      viper.GetInt("workers"),
		CacheEnabled: false, // Disabled by default for CLI
		OutputFormat: viper.GetString("output"),
		Verbose:      viper.GetBool("verbose"),
		Output: core.OutputConfig{
			Format:  viper.GetString("output"),
			Verbose: viper.GetBool("verbose"),
			Quiet:   viper.GetBool("quiet"),
		},
	}
}
