package discovery

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/victorstaflin/bountytxt-cli/internal/core"
)

// Parser handles RFC 9116 security.txt parsing and validation
type Parser struct {
	config *core.Config
}

// NewParser creates a new security.txt parser
func NewParser(config *core.Config) *Parser {
	return &Parser{
		config: config,
	}
}

// Parse parses security.txt content according to RFC 9116
func (p *Parser) Parse(content, sourceURL string) (*core.SecurityTxt, error) {
	fields := make(map[string][]string)
	lines := strings.Split(content, "\n")
	lineNumber := 0

	for _, line := range lines {
		lineNumber++
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse field: value format
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			// Invalid line format - this could be a validation issue
			continue
		}

		fieldName := strings.TrimSpace(parts[0])
		fieldValue := strings.TrimSpace(parts[1])

		// Normalize field name according to RFC 9116
		normalizedName := p.normalizeFieldName(fieldName)

		// Validate and normalize field value
		normalizedValue, err := p.normalizeFieldValue(normalizedName, fieldValue)
		if err != nil {
			// Log validation error but continue parsing
			continue
		}

		// Append to existing values (fields can have multiple values)
		fields[normalizedName] = append(fields[normalizedName], normalizedValue)
	}

	return &core.SecurityTxt{
		SourceURL: sourceURL,
		FetchedAt: time.Now(),
		Fields:    fields,
		Raw:       content,
	}, nil
}

// normalizeFieldName normalizes field names according to RFC 9116
func (p *Parser) normalizeFieldName(fieldName string) string {
	lowerName := strings.ToLower(fieldName)

	// Check if it's a known RFC 9116 field
	if normalizedName, exists := core.RFC9116Fields[lowerName]; exists {
		return normalizedName
	}

	// For unknown fields, use title case
	return strings.Title(lowerName)
}

// normalizeFieldValue normalizes and validates field values
func (p *Parser) normalizeFieldValue(fieldName, fieldValue string) (string, error) {
	switch fieldName {
	case "Contact":
		return p.normalizeContact(fieldValue)
	case "Expires":
		return p.normalizeExpires(fieldValue)
	case "Encryption":
		return p.normalizeEncryption(fieldValue)
	case "Canonical":
		return p.normalizeCanonical(fieldValue)
	case "Policy":
		return p.normalizePolicy(fieldValue)
	case "Acknowledgments":
		return p.normalizeAcknowledgments(fieldValue)
	case "Hiring":
		return p.normalizeHiring(fieldValue)
	case "Preferred-Languages":
		return p.normalizePreferredLanguages(fieldValue)
	default:
		// For unknown fields, return as-is
		return fieldValue, nil
	}
}

// normalizeContact validates and normalizes contact information
func (p *Parser) normalizeContact(value string) (string, error) {
	value = strings.TrimSpace(value)

	// Check if it's an email
	if strings.Contains(value, "@") {
		if !p.isValidEmail(value) {
			return "", fmt.Errorf("invalid email format: %s", value)
		}
		return value, nil
	}

	// Check if it's a URL
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		if _, err := url.Parse(value); err != nil {
			return "", fmt.Errorf("invalid URL format: %s", value)
		}
		return value, nil
	}

	// Check if it's a phone number (basic validation)
	if strings.HasPrefix(value, "tel:") {
		return value, nil
	}

	return "", fmt.Errorf("invalid contact format: %s", value)
}

// normalizeExpires validates and normalizes expiration dates
func (p *Parser) normalizeExpires(value string) (string, error) {
	value = strings.TrimSpace(value)

	// Try to parse as RFC 3339 format
	if _, err := time.Parse(time.RFC3339, value); err == nil {
		return value, nil
	}

	// Try other common formats
	formats := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, value); err == nil {
			return t.Format(time.RFC3339), nil
		}
	}

	return "", fmt.Errorf("invalid date format: %s", value)
}

// normalizeEncryption validates and normalizes encryption key URLs
func (p *Parser) normalizeEncryption(value string) (string, error) {
	value = strings.TrimSpace(value)

	// Must be a valid URL
	if _, err := url.Parse(value); err != nil {
		return "", fmt.Errorf("invalid encryption URL: %s", value)
	}

	// Should be HTTPS for security
	if !strings.HasPrefix(value, "https://") && p.config.PublicMode {
		return "", fmt.Errorf("encryption URL must use HTTPS: %s", value)
	}

	return value, nil
}

// normalizeCanonical validates and normalizes canonical URLs
func (p *Parser) normalizeCanonical(value string) (string, error) {
	value = strings.TrimSpace(value)

	// Must be a valid URL
	parsedURL, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("invalid canonical URL: %s", value)
	}

	// Should be HTTPS for security
	if parsedURL.Scheme != "https" && p.config.PublicMode {
		return "", fmt.Errorf("canonical URL must use HTTPS: %s", value)
	}

	// Should point to a security.txt file
	if !strings.HasSuffix(parsedURL.Path, "/security.txt") {
		return "", fmt.Errorf("canonical URL must point to security.txt: %s", value)
	}

	return value, nil
}

// normalizePolicy validates and normalizes policy URLs
func (p *Parser) normalizePolicy(value string) (string, error) {
	value = strings.TrimSpace(value)

	// Must be a valid URL
	if _, err := url.Parse(value); err != nil {
		return "", fmt.Errorf("invalid policy URL: %s", value)
	}

	return value, nil
}

// normalizeAcknowledgments validates and normalizes acknowledgment URLs
func (p *Parser) normalizeAcknowledgments(value string) (string, error) {
	value = strings.TrimSpace(value)

	// Must be a valid URL
	if _, err := url.Parse(value); err != nil {
		return "", fmt.Errorf("invalid acknowledgments URL: %s", value)
	}

	return value, nil
}

// normalizeHiring validates and normalizes hiring URLs
func (p *Parser) normalizeHiring(value string) (string, error) {
	value = strings.TrimSpace(value)

	// Must be a valid URL
	if _, err := url.Parse(value); err != nil {
		return "", fmt.Errorf("invalid hiring URL: %s", value)
	}

	return value, nil
}

// normalizePreferredLanguages validates and normalizes language codes
func (p *Parser) normalizePreferredLanguages(value string) (string, error) {
	value = strings.TrimSpace(value)

	// Split by comma for multiple languages
	languages := strings.Split(value, ",")
	normalizedLanguages := make([]string, 0, len(languages))

	for _, lang := range languages {
		lang = strings.TrimSpace(lang)

		// Basic validation for language codes (ISO 639-1 or RFC 5646)
		if p.isValidLanguageCode(lang) {
			normalizedLanguages = append(normalizedLanguages, lang)
		}
	}

	if len(normalizedLanguages) == 0 {
		return "", fmt.Errorf("no valid language codes found: %s", value)
	}

	return strings.Join(normalizedLanguages, ", "), nil
}

// isValidEmail performs basic email validation
func (p *Parser) isValidEmail(email string) bool {
	// Basic email regex - not comprehensive but good enough for security.txt
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// isValidLanguageCode performs basic language code validation
func (p *Parser) isValidLanguageCode(code string) bool {
	// Basic validation for common language codes
	// This is a simplified check - a full implementation would use a proper language code library
	codeRegex := regexp.MustCompile(`^[a-z]{2}(-[A-Z]{2})?$`)
	return codeRegex.MatchString(code) || code == "en" || code == "es" || code == "fr" || code == "de" || code == "it" || code == "pt" || code == "ru" || code == "ja" || code == "ko" || code == "zh"
}
