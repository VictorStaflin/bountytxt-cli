package validation

import (
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/victorstaflin/bountytxt-cli/internal/core"
)

// Engine handles security.txt validation and scoring
type Engine struct {
	rules *core.ValidationRules
}

// NewEngine creates a new validation engine with the given rules
func NewEngine(rules *core.ValidationRules) *Engine {
	if rules == nil {
		rules = &core.ValidationRules{
			RequiredFields:    []string{"Contact"},
			RecommendedFields: []string{"Expires", "Canonical"},
			OptionalFields:    []string{"Encryption", "Acknowledgments", "Languages", "Policy", "Hiring", "CSAF"},
			MaxAge:            365 * 24 * time.Hour, // 1 year
			HTTPSRequired:     true,
		}
	}

	return &Engine{
		rules: rules,
	}
}

// Validate validates a security.txt file and returns a lint report
func (e *Engine) Validate(securityTxt *core.SecurityTxt) *core.LintReport {
	report := &core.LintReport{
		Domain:      extractDomainFromURL(securityTxt.RawContent),
		SourceURL:   "", // Will be set by caller
		ValidatedAt: time.Now(),
		Issues:      make([]core.Issue, 0),
		Score:       100, // Start with perfect score
		Grade:       "A",
	}

	// Validate required fields
	e.validateRequiredFields(securityTxt, report)

	// Validate field formats
	e.validateFieldFormats(securityTxt, report)

	// Validate expiration
	e.validateExpiration(securityTxt, report)

	// Validate HTTPS requirements
	e.validateHTTPS(securityTxt, report)

	// Validate canonical URLs
	e.validateCanonical(securityTxt, report)

	// Check for recommended fields
	e.checkRecommendedFields(securityTxt, report)

	// Calculate final score and grade
	e.calculateScoreAndGrade(report)

	return report
}

// validateRequiredFields checks that all required fields are present
func (e *Engine) validateRequiredFields(securityTxt *core.SecurityTxt, report *core.LintReport) {
	for _, field := range e.rules.RequiredFields {
		switch strings.ToLower(field) {
		case "contact":
			if len(securityTxt.Contact) == 0 {
				e.addIssue(report, core.Issue{
					Type:        "missing_required_field",
					Category:    "format",
					Field:       "Contact",
					Message:     "Contact field is required but missing",
					Severity:    "error",
					ScoreImpact: -30,
				})
			}
		case "expires":
			if securityTxt.Expires == nil {
				e.addIssue(report, core.Issue{
					Type:        "missing_required_field",
					Category:    "format",
					Field:       "Expires",
					Message:     "Expires field is required but missing",
					Severity:    "error",
					ScoreImpact: -20,
				})
			}
		}
	}
}

// validateFieldFormats validates the format of each field
func (e *Engine) validateFieldFormats(securityTxt *core.SecurityTxt, report *core.LintReport) {
	// Validate contact fields
	for i, contact := range securityTxt.Contact {
		if err := e.validateContact(contact); err != nil {
			e.addIssue(report, core.Issue{
				Type:        "invalid_format",
				Category:    "format",
				Field:       "Contact",
				Message:     fmt.Sprintf("Invalid contact format at index %d: %s", i, err.Error()),
				Severity:    "error",
				ScoreImpact: -10,
				Line:        i + 1,
				Suggestion:  "Use a valid email address or HTTPS URL",
			})
		}
	}

	// Validate encryption URLs
	for i, encryption := range securityTxt.Encryption {
		if err := e.validateURL(encryption); err != nil {
			e.addIssue(report, core.Issue{
				Type:        "invalid_format",
				Category:    "format",
				Field:       "Encryption",
				Message:     fmt.Sprintf("Invalid encryption URL at index %d: %s", i, err.Error()),
				Severity:    "warning",
				ScoreImpact: -5,
				Line:        i + 1,
				Suggestion:  "Use a valid HTTPS URL",
			})
		}
	}

	// Validate acknowledgments URLs
	for i, ack := range securityTxt.Acknowledgments {
		if err := e.validateURL(ack); err != nil {
			e.addIssue(report, core.Issue{
				Type:        "invalid_format",
				Category:    "format",
				Field:       "Acknowledgments",
				Message:     fmt.Sprintf("Invalid acknowledgments URL at index %d: %s", i, err.Error()),
				Severity:    "warning",
				ScoreImpact: -3,
				Line:        i + 1,
				Suggestion:  "Use a valid HTTPS URL",
			})
		}
	}

	// Validate canonical URLs
	for i, canonical := range securityTxt.Canonical {
		if err := e.validateURL(canonical); err != nil {
			e.addIssue(report, core.Issue{
				Type:        "invalid_format",
				Category:    "format",
				Field:       "Canonical",
				Message:     fmt.Sprintf("Invalid canonical URL at index %d: %s", i, err.Error()),
				Severity:    "error",
				ScoreImpact: -10,
				Line:        i + 1,
				Suggestion:  "Use a valid HTTPS URL",
			})
		}
	}

	// Validate policy URLs
	for i, policy := range securityTxt.Policy {
		if err := e.validateURL(policy); err != nil {
			e.addIssue(report, core.Issue{
				Type:        "invalid_format",
				Category:    "format",
				Field:       "Policy",
				Message:     fmt.Sprintf("Invalid policy URL at index %d: %s", i, err.Error()),
				Severity:    "warning",
				ScoreImpact: -3,
				Line:        i + 1,
				Suggestion:  "Use a valid HTTPS URL",
			})
		}
	}
}

// validateExpiration checks if the expires field is valid and not expired
func (e *Engine) validateExpiration(securityTxt *core.SecurityTxt, report *core.LintReport) {
	if securityTxt.Expires == nil {
		return // Already handled in required fields
	}

	now := time.Now()
	expires := *securityTxt.Expires

	// Check if expired
	if expires.Before(now) {
		e.addIssue(report, core.Issue{
			Type:        "expired",
			Category:    "expiration",
			Field:       "Expires",
			Message:     fmt.Sprintf("Security.txt expired on %s", expires.Format(time.RFC3339)),
			Severity:    "error",
			ScoreImpact: -25,
			Suggestion:  "Update the expires field to a future date",
		})
		return
	}

	// Check if expires too far in the future
	maxAge := e.rules.MaxAge
	if maxAge > 0 && expires.After(now.Add(maxAge)) {
		e.addIssue(report, core.Issue{
			Type:        "expires_too_far",
			Category:    "expiration",
			Field:       "Expires",
			Message:     fmt.Sprintf("Expires date is too far in the future (max: %s)", maxAge),
			Severity:    "warning",
			ScoreImpact: -5,
			Suggestion:  fmt.Sprintf("Set expires date within %s", maxAge),
		})
	}

	// Check if expires soon (within 30 days)
	if expires.Before(now.Add(30 * 24 * time.Hour)) {
		e.addIssue(report, core.Issue{
			Type:        "expires_soon",
			Category:    "expiration",
			Field:       "Expires",
			Message:     "Security.txt expires within 30 days",
			Severity:    "warning",
			ScoreImpact: -5,
			Suggestion:  "Consider updating the expires date",
		})
	}
}

// validateHTTPS checks HTTPS requirements
func (e *Engine) validateHTTPS(securityTxt *core.SecurityTxt, report *core.LintReport) {
	if !e.rules.HTTPSRequired {
		return
	}

	// Check all URLs for HTTPS
	allURLs := make([]string, 0)
	allURLs = append(allURLs, securityTxt.Encryption...)
	allURLs = append(allURLs, securityTxt.Acknowledgments...)
	allURLs = append(allURLs, securityTxt.Canonical...)
	allURLs = append(allURLs, securityTxt.Policy...)
	allURLs = append(allURLs, securityTxt.Hiring...)
	allURLs = append(allURLs, securityTxt.CSAF...)

	for _, urlStr := range allURLs {
		if !strings.HasPrefix(strings.ToLower(urlStr), "https://") {
			e.addIssue(report, core.Issue{
				Type:        "non_https_url",
				Category:    "security",
				Field:       "URL",
				Message:     fmt.Sprintf("Non-HTTPS URL found: %s", urlStr),
				Severity:    "warning",
				ScoreImpact: -5,
				Suggestion:  "Use HTTPS URLs for better security",
			})
		}
	}
}

// validateCanonical validates canonical URL requirements
func (e *Engine) validateCanonical(securityTxt *core.SecurityTxt, report *core.LintReport) {
	if len(securityTxt.Canonical) == 0 {
		e.addIssue(report, core.Issue{
			Type:        "missing_canonical",
			Category:    "format",
			Field:       "Canonical",
			Message:     "Canonical field is recommended for security.txt files",
			Severity:    "info",
			ScoreImpact: -5,
			Suggestion:  "Add a canonical URL pointing to this security.txt file",
		})
	}
}

// checkRecommendedFields checks for presence of recommended fields
func (e *Engine) checkRecommendedFields(securityTxt *core.SecurityTxt, report *core.LintReport) {
	for _, field := range e.rules.RecommendedFields {
		switch strings.ToLower(field) {
		case "expires":
			if securityTxt.Expires == nil {
				e.addIssue(report, core.Issue{
					Type:        "missing_recommended_field",
					Category:    "format",
					Field:       "Expires",
					Message:     "Expires field is recommended",
					Severity:    "info",
					ScoreImpact: -5,
					Suggestion:  "Add an expires field with a future date",
				})
			}
		case "canonical":
			if len(securityTxt.Canonical) == 0 {
				e.addIssue(report, core.Issue{
					Type:        "missing_recommended_field",
					Category:    "format",
					Field:       "Canonical",
					Message:     "Canonical field is recommended",
					Severity:    "info",
					ScoreImpact: -3,
					Suggestion:  "Add a canonical URL",
				})
			}
		case "encryption":
			if len(securityTxt.Encryption) == 0 {
				e.addIssue(report, core.Issue{
					Type:        "missing_recommended_field",
					Category:    "format",
					Field:       "Encryption",
					Message:     "Encryption field is recommended for secure communication",
					Severity:    "info",
					ScoreImpact: -3,
					Suggestion:  "Add a PGP key URL for encrypted communication",
				})
			}
		}
	}
}

// validateContact validates a contact field (email or URL)
func (e *Engine) validateContact(contact string) error {
	// Check if it's an email
	if _, err := mail.ParseAddress(contact); err == nil {
		return nil
	}

	// Check if it's a URL
	if err := e.validateURL(contact); err == nil {
		return nil
	}

	return fmt.Errorf("must be a valid email address or URL")
}

// validateURL validates a URL
func (e *Engine) validateURL(urlStr string) error {
	u, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	if u.Scheme == "" {
		return fmt.Errorf("URL must include scheme (http/https)")
	}

	if u.Host == "" {
		return fmt.Errorf("URL must include host")
	}

	return nil
}

// addIssue adds an issue to the report
func (e *Engine) addIssue(report *core.LintReport, issue core.Issue) {
	report.Issues = append(report.Issues, issue)
}

// calculateScoreAndGrade calculates the final score and grade
func (e *Engine) calculateScoreAndGrade(report *core.LintReport) {
	// Apply score impacts
	for _, issue := range report.Issues {
		report.Score += issue.ScoreImpact // ScoreImpact is negative
	}

	// Ensure score is within bounds
	if report.Score < 0 {
		report.Score = 0
	}
	if report.Score > 100 {
		report.Score = 100
	}

	// Calculate grade
	switch {
	case report.Score >= 90:
		report.Grade = "A"
	case report.Score >= 80:
		report.Grade = "B"
	case report.Score >= 70:
		report.Grade = "C"
	case report.Score >= 60:
		report.Grade = "D"
	default:
		report.Grade = "F"
	}
}

// extractDomainFromURL extracts domain from a URL or returns empty string
func extractDomainFromURL(content string) string {
	// Simple regex to find domain in canonical URLs
	re := regexp.MustCompile(`(?i)canonical:\s*https?://([^/\s]+)`)
	matches := re.FindStringSubmatch(content)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}