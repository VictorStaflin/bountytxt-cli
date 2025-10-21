package core

import "time"

// Default configuration constants
const (
	// HTTP Client defaults
	DefaultTimeout      = 30 * time.Second
	DefaultMaxRedirects = 5
	DefaultUserAgent    = "bountytxt/1.0 (+https://github.com/bountytxt/bountytxt)"

	// Rate limiting defaults
	DefaultMaxRPS      = 10
	DefaultConcurrency = 5

	// Security.txt paths according to RFC 9116
	WellKnownPath = "/.well-known/security.txt"
	RootPath      = "/security.txt"

	// Validation scoring weights
	ContactWeight    = 30
	ExpiresWeight    = 25
	CanonicalWeight  = 15
	EncryptionWeight = 10
	PolicyWeight     = 10
	FormatWeight     = 10

	// Platform detection patterns
	HackerOnePattern = "hackerone.com"
	BugcrowdPattern  = "bugcrowd.com"
	IntigritiPattern = "intigriti.com"
	YesWeHackPattern = "yeswehack.com"
	SynackPattern    = "synack.com"

	// Common security email patterns
	SecurityEmailPattern = "security@"
	VulnEmailPattern     = "vuln@"
	AbuseEmailPattern    = "abuse@"
	AdminEmailPattern    = "admin@"
	ContactEmailPattern  = "contact@"

	// Output formats
	FormatTable = "table"
	FormatJSON  = "json"
	FormatJSONL = "jsonl"
	FormatYAML  = "yaml"

	// Exit codes for CI integration
	ExitSuccess             = 0
	ExitValidationFailed    = 1
	ExitNotFound            = 2
	ExitNetworkError        = 3
	ExitInvalidInput        = 4
	ExitCodeError           = 3
	ExitCodeNotFound        = 2
	ExitCodeSuccess         = 0
	ExitCodeThresholdNotMet = 1
	ExitCodeInvalid         = 4
)

// OutputConfig holds output-specific configuration
type OutputConfig struct {
	Format  string `mapstructure:"format"`
	Verbose bool   `mapstructure:"verbose"`
	Quiet   bool   `mapstructure:"quiet"`
}

// Config holds application configuration
type Config struct {
	// HTTP settings
	Timeout      time.Duration `mapstructure:"timeout"`
	MaxRedirects int           `mapstructure:"max_redirects"`
	UserAgent    string        `mapstructure:"user_agent"`
	VerifyTLS    bool          `mapstructure:"verify_tls"`

	// Rate limiting
	MaxRPS      int `mapstructure:"max_rps"`
	Concurrency int `mapstructure:"concurrency"`
	Workers     int `mapstructure:"workers"`

	// Validation settings
	RequireContact   bool `mapstructure:"require_contact"`
	RequireExpires   bool `mapstructure:"require_expires"`
	RequireCanonical bool `mapstructure:"require_canonical"`
	MaxExpiryDays    int  `mapstructure:"max_expiry_days"`
	AllowHTTP        bool `mapstructure:"allow_http"`

	// Output settings
	OutputFormat string `mapstructure:"output_format"`
	NoColor      bool   `mapstructure:"no_color"`
	Verbose      bool   `mapstructure:"verbose"`
	Output       OutputConfig

	// Cache settings
	CacheEnabled bool          `mapstructure:"cache_enabled"`
	CacheDir     string        `mapstructure:"cache_dir"`
	CacheTTL     time.Duration `mapstructure:"cache_ttl"`

	// Legal compliance
	HonorRobots bool `mapstructure:"honor_robots"`
	PublicMode  bool `mapstructure:"public_mode"`

	// CI/CD settings
	FailOnExpiring int  `mapstructure:"fail_on_expiring"`
	Compliance     bool `mapstructure:"compliance"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Timeout:          DefaultTimeout,
		MaxRedirects:     DefaultMaxRedirects,
		UserAgent:        DefaultUserAgent,
		VerifyTLS:        true,
		MaxRPS:           DefaultMaxRPS,
		Concurrency:      DefaultConcurrency,
		Workers:          DefaultConcurrency,
		RequireContact:   true,
		RequireExpires:   true,
		RequireCanonical: false,
		MaxExpiryDays:    365,
		AllowHTTP:        false,
		OutputFormat:     FormatTable,
		NoColor:          false,
		Verbose:          false,
		Output: OutputConfig{
			Format:  FormatTable,
			Verbose: false,
			Quiet:   false,
		},
		CacheEnabled:   false,
		CacheTTL:       24 * time.Hour,
		HonorRobots:    true,
		PublicMode:     true,
		FailOnExpiring: 30,
		Compliance:     false,
	}
}

// PlatformPatterns maps platform names to their URL patterns
var PlatformPatterns = map[string]string{
	"HackerOne": HackerOnePattern,
	"Bugcrowd":  BugcrowdPattern,
	"Intigriti": IntigritiPattern,
	"YesWeHack": YesWeHackPattern,
	"Synack":    SynackPattern,
}

// EmailPatterns maps email types to their patterns with confidence scores
var EmailPatterns = map[string]int{
	SecurityEmailPattern: 90,
	VulnEmailPattern:     85,
	AbuseEmailPattern:    70,
	AdminEmailPattern:    60,
	ContactEmailPattern:  50,
}

// RFC 9116 field names (case-insensitive but stored in title case)
// RFC 9116 field mappings for normalization
var RFC9116Fields = map[string]string{
	"contact":             "Contact",
	"expires":             "Expires",
	"encryption":          "Encryption",
	"acknowledgments":     "Acknowledgments",
	"acknowledgements":    "Acknowledgments", // Alternative spelling
	"preferred-languages": "Preferred-Languages",
	"canonical":           "Canonical",
	"policy":              "Policy",
	"hiring":              "Hiring",
}
