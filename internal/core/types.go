package core

import (
	"context"
	"time"
)

// SecurityTxt represents a parsed security.txt file according to RFC 9116
type SecurityTxt struct {
	SourceURL  string              `json:"source_url"`
	Status     int                 `json:"status"`
	FetchedAt  time.Time           `json:"fetched_at"`
	Fields     map[string][]string `json:"fields"` // Title-cased keys
	Raw        string              `json:"raw,omitempty"`
	RawContent string              `json:"raw_content,omitempty"`

	// Parsed fields for easier access
	Contact         []string          `json:"contact,omitempty"`
	Expires         *time.Time        `json:"expires,omitempty"`
	Encryption      []string          `json:"encryption,omitempty"`
	Acknowledgments []string          `json:"acknowledgments,omitempty"`
	Canonical       []string          `json:"canonical,omitempty"`
	Policy          []string          `json:"policy,omitempty"`
	Hiring          []string          `json:"hiring,omitempty"`
	Languages       []string          `json:"languages,omitempty"`
	CSAF            []string          `json:"csaf,omitempty"`
	PreferredLangs  []string          `json:"preferred_langs,omitempty"`
	Extensions      map[string]string `json:"extensions,omitempty"`
}

// Issue represents a validation issue
type Issue struct {
	Type        string `json:"type"`         // error, warning, hint
	Category    string `json:"category"`     // required_fields, format, security, etc.
	Field       string `json:"field"`        // Field name that caused the issue
	Message     string `json:"message"`      // Human-readable description
	Severity    string `json:"severity"`     // high, medium, low
	ScoreImpact int    `json:"score_impact"` // Impact on score (negative)
	Line        int    `json:"line,omitempty"`
	Suggestion  string `json:"suggestion,omitempty"`
}

// ValidationIssue is an alias for Issue for backward compatibility
type ValidationIssue = Issue

// LintReport contains validation results with scoring
type LintReport struct {
	Domain          string           `json:"domain"`
	SourceURL       string           `json:"source_url"`
	Found           bool             `json:"found"`
	ValidatedAt     time.Time        `json:"validated_at"`
	Issues          []Issue          `json:"issues"`
	Score           int              `json:"score"` // 0-100
	Grade           string           `json:"grade"` // A, B, C, D, F
	DiscoveryResult *DiscoveryResult `json:"discovery_result,omitempty"`
	Errors          []string         `json:"errors,omitempty"`   // Deprecated: use Issues
	Warnings        []string         `json:"warnings,omitempty"` // Deprecated: use Issues
	Hints           []string         `json:"hints,omitempty"`    // Deprecated: use Issues
}

// DiscoveryResult aggregates all discovery information for a domain
type DiscoveryResult struct {
	Domain        string       `json:"domain"`
	Found         bool         `json:"found"`
	DiscoveredAt  time.Time    `json:"discovered_at"`
	SecurityTxt   *SecurityTxt `json:"security_txt,omitempty"`
	SourceURL     string       `json:"source_url,omitempty"`
	LintReport    *LintReport  `json:"lint_report,omitempty"`
	Contacts      []Contact    `json:"contacts,omitempty"`
	PlatformHints []Platform   `json:"platform_hints,omitempty"`
	Attempts      []Fallback   `json:"attempts,omitempty"`
	FallbackInfo  *Fallback    `json:"fallback_info,omitempty"`
}

// Contact represents a contact method with confidence scoring
type Contact struct {
	Type       string `json:"type"` // email, url, phone
	Value      string `json:"value"`
	Source     string `json:"source"`     // security.txt, guessed, dns
	Confidence int    `json:"confidence"` // 0-100
	Validated  bool   `json:"validated"`
}

// ContactIntelligence represents analyzed contact information with metadata
type ContactIntelligence struct {
	Contact    string                 `json:"contact"`
	Type       string                 `json:"type"`       // email, url, phone
	Confidence float64                `json:"confidence"` // 0.0-1.0
	Metadata   map[string]interface{} `json:"metadata"`
}

// Platform represents a detected vulnerability disclosure platform
type Platform struct {
	Name       string  `json:"name"`       // HackerOne, Bugcrowd, etc.
	Type       string  `json:"type"`       // bug_bounty, vdp, etc.
	Program    string  `json:"program"`    // Program name
	URL        string  `json:"url"`        // Platform URL
	Confidence float64 `json:"confidence"` // 0.0-1.0
	Evidence   string  `json:"evidence"`   // URL pattern, header, etc.
}

// Fallback contains fallback discovery information
type Fallback struct {
	URL             string      `json:"url,omitempty"`
	Method          string      `json:"method,omitempty"`
	AttemptedAt     time.Time   `json:"attempted_at,omitempty"`
	StatusCode      int         `json:"status_code,omitempty"`
	Success         bool        `json:"success"`
	Error           string      `json:"error,omitempty"`
	GuessedContacts []Contact   `json:"guessed_contacts,omitempty"`
	DNSRecords      []DNSRecord `json:"dns_records,omitempty"`
	RDAPInfo        *RDAPInfo   `json:"rdap_info,omitempty"`
	SecurityPages   []string    `json:"security_pages,omitempty"`
}

// DNSRecord represents DNS information for fallback discovery
type DNSRecord struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

// RDAPInfo contains RDAP/WHOIS information
type RDAPInfo struct {
	AdminContact string `json:"admin_contact,omitempty"`
	TechContact  string `json:"tech_contact,omitempty"`
	AbuseContact string `json:"abuse_contact,omitempty"`
}

// FetchOptions configures security.txt fetching behavior
type FetchOptions struct {
	Timeout       time.Duration
	MaxRedirects  int
	UserAgent     string
	FollowRobots  bool
	VerifyTLS     bool
	CacheEnabled  bool
	RetryAttempts int
	Headers       map[string]string
}

// ValidationRules configures validation behavior
type ValidationRules struct {
	RequiredFields    []string
	RecommendedFields []string
	OptionalFields    []string
	MaxAge            time.Duration
	HTTPSRequired     bool
	RequireContact    bool
	RequireExpires    bool
	RequireCanonical  bool
	MaxExpiryDays     int
	AllowHTTP         bool
	StrictParsing     bool
}

// BulkOptions configures bulk processing
type BulkOptions struct {
	Workers         int
	Concurrency     int
	MaxRPS          int
	RetryAttempts   int
	Timeout         time.Duration
	OutputFormat    string
	FailFast        bool
	SkipErrors      bool
	Delay           time.Duration
	ContinueOnError bool
	Validate        bool
	MinScore        int
	MinGrade        string
	FoundOnly       bool
}

// BulkResult represents the result of processing a single domain in bulk
type BulkResult struct {
	Domain           string            `json:"domain"`
	Found            bool              `json:"found"`
	SourceURL        string            `json:"source_url,omitempty"`
	Error            string            `json:"error,omitempty"`
	ValidationPassed bool              `json:"validation_passed,omitempty"`
	Score            int               `json:"score,omitempty"`
	Grade            string            `json:"grade,omitempty"`
	Issues           []ValidationIssue `json:"issues,omitempty"`
	ProcessedAt      time.Time         `json:"processed_at"`
}

// Core interfaces for the application

// Fetcher handles security.txt file retrieval
type Fetcher interface {
	Fetch(ctx context.Context, domain string) (*SecurityTxt, error)
	FetchWithOptions(ctx context.Context, domain string, opts FetchOptions) (*SecurityTxt, error)
}

// Validator handles security.txt validation and scoring
type Validator interface {
	Validate(securityTxt *SecurityTxt) *LintReport
	ValidateWithRules(securityTxt *SecurityTxt, rules ValidationRules) *LintReport
}

// Discoverer handles comprehensive domain discovery
type Discoverer interface {
	Discover(ctx context.Context, domain string) (*DiscoveryResult, error)
	DiscoverBulk(ctx context.Context, domains []string, opts BulkOptions) <-chan *DiscoveryResult
}

// PlatformDetector identifies vulnerability disclosure platforms
type PlatformDetector interface {
	DetectPlatforms(securityTxt *SecurityTxt, domain string) []Platform
	GetSubmissionURL(platform Platform, domain string) string
}

// ContactGuesser generates intelligent contact guesses
type ContactGuesser interface {
	GuessContacts(domain string) []Contact
	ValidateContact(contact Contact) (bool, int) // validated, confidence
}

// RateLimiter controls request rate limiting
type RateLimiter interface {
	Allow() bool
	Wait(ctx context.Context) error
	SetRate(rps int)
}

// OutputFormatter handles different output formats
type OutputFormatter interface {
	FormatTable(data interface{}) (string, error)
	FormatJSON(data interface{}) (string, error)
	FormatJSONL(data interface{}) (string, error)
	FormatYAML(data interface{}) (string, error)
}
