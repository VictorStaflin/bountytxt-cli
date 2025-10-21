package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/victorstaflin/bountytxt-cli/internal/core"
	"github.com/victorstaflin/bountytxt-cli/internal/discovery"
	"github.com/victorstaflin/bountytxt-cli/internal/output"
)

// contactsCmd represents the contacts command
var contactsCmd = &cobra.Command{
	Use:   "contacts [domain]",
	Short: "Extract and analyze contact information",
	Long: `Extract and analyze contact information from security.txt files.

This command discovers security.txt files and extracts all contact information,
providing analysis of contact types, validation status, and recommendations.

Contact types include:
- Email addresses
- URLs (web forms, issue trackers)
- Phone numbers

Examples:
  securitytxt-cli contacts example.com
  securitytxt-cli contacts example.com --output json
  securitytxt-cli contacts example.com --validate-contacts
  securitytxt-cli contacts example.com --prefer-email`,
	Args: cobra.ExactArgs(1),
	RunE: runContacts,
}

func init() {
	// Command-specific flags
	contactsCmd.Flags().Bool("validate-contacts", false, "validate contact information (check email/URL accessibility)")
	contactsCmd.Flags().Bool("prefer-email", false, "prioritize email contacts in output")
	contactsCmd.Flags().Bool("show-confidence", false, "show confidence scores for contact validation")
	contactsCmd.Flags().StringSlice("contact-types", []string{}, "filter by contact types (email, url, phone)")
}

func runContacts(cmd *cobra.Command, args []string) error {
	domain := args[0]

	// Get flag values
	validateContacts, _ := cmd.Flags().GetBool("validate-contacts")
	preferEmail, _ := cmd.Flags().GetBool("prefer-email")
	showConfidence, _ := cmd.Flags().GetBool("show-confidence")
	contactTypes, _ := cmd.Flags().GetStringSlice("contact-types")

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

	if !result.Found || result.SecurityTxt == nil {
		if !config.Output.Quiet {
			fmt.Fprintf(os.Stderr, "No security.txt found for domain: %s\n", domain)
		}
		os.Exit(1)
	}

	// Extract contacts from the structured SecurityTxt data
	contacts := extractContactsFromSecurityTxt(result.SecurityTxt, contactTypes, preferEmail)

	// Validate contacts if requested
	if validateContacts {
		contacts = validateContactList(contacts)
	}

	// Convert contacts to interface{} slice for formatter
	contactsInterface := make([]interface{}, len(contacts))
	for i, contact := range contacts {
		contactsInterface[i] = map[string]interface{}{
			"type":       contact.Type,
			"value":      contact.Value,
			"valid":      contact.Valid,
			"confidence": contact.Confidence,
			"error":      contact.Error,
		}
	}

	// Prepare output data
	outputData := map[string]interface{}{
		"domain":        result.Domain,
		"source_url":    result.SecurityTxt.SourceURL,
		"contact_count": len(contacts),
		"contacts":      contactsInterface,
	}

	if showConfidence || config.Output.Verbose {
		outputData["show_confidence"] = true
	}

	// Format and output
	output, err := formatter.Format(outputData)
	if err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	fmt.Print(output)

	// Exit with error if no contacts found
	if len(contacts) == 0 {
		os.Exit(1)
	}

	return nil
}

// ContactInfo represents extracted contact information
type ContactInfo struct {
	Value      string  `json:"value"`
	Type       string  `json:"type"`
	Valid      bool    `json:"valid"`
	Confidence float64 `json:"confidence,omitempty"`
	Error      string  `json:"error,omitempty"`
}

// extractContactsFromSecurityTxt extracts and categorizes contact information from SecurityTxt struct
func extractContactsFromSecurityTxt(securityTxt *core.SecurityTxt, filterTypes []string, preferEmail bool) []ContactInfo {
	contacts := make([]ContactInfo, 0)

	// Use the structured Contact field from SecurityTxt
	for _, contact := range securityTxt.Contact {
		contactInfo := categorizeContact(contact)

		// Apply type filter if specified
		if len(filterTypes) > 0 {
			found := false
			for _, filterType := range filterTypes {
				if contactInfo.Type == filterType {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		contacts = append(contacts, contactInfo)
	}

	// Sort contacts if preferEmail is set
	if preferEmail {
		emailContacts := make([]ContactInfo, 0)
		otherContacts := make([]ContactInfo, 0)

		for _, contact := range contacts {
			if contact.Type == "email" {
				emailContacts = append(emailContacts, contact)
			} else {
				otherContacts = append(otherContacts, contact)
			}
		}

		contacts = append(emailContacts, otherContacts...)
	}

	return contacts
}

// categorizeContact determines the type of contact information
func categorizeContact(contact string) ContactInfo {
	contact = strings.TrimSpace(contact)

	if strings.Contains(contact, "@") && !strings.HasPrefix(contact, "http") {
		return ContactInfo{
			Value:      contact,
			Type:       "email",
			Valid:      isValidEmail(contact),
			Confidence: calculateEmailConfidence(contact),
		}
	}

	if strings.HasPrefix(contact, "http://") || strings.HasPrefix(contact, "https://") {
		return ContactInfo{
			Value:      contact,
			Type:       "url",
			Valid:      isValidURL(contact),
			Confidence: calculateURLConfidence(contact),
		}
	}

	if strings.HasPrefix(contact, "tel:") {
		return ContactInfo{
			Value:      contact,
			Type:       "phone",
			Valid:      isValidPhone(contact),
			Confidence: calculatePhoneConfidence(contact),
		}
	}

	return ContactInfo{
		Value:      contact,
		Type:       "unknown",
		Valid:      false,
		Confidence: 0.0,
	}
}

// isValidEmail performs basic email validation
func isValidEmail(email string) bool {
	return strings.Contains(email, "@") && strings.Contains(email, ".")
}

// isValidURL performs basic URL validation
func isValidURL(url string) bool {
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}

// isValidPhone performs basic phone validation
func isValidPhone(phone string) bool {
	return strings.HasPrefix(phone, "tel:") && len(phone) > 4
}

// calculateEmailConfidence calculates confidence score for email addresses
func calculateEmailConfidence(email string) float64 {
	confidence := 0.5 // Base confidence

	// Security-specific email patterns
	if strings.Contains(email, "security@") {
		confidence += 0.3
	} else if strings.Contains(email, "vuln") || strings.Contains(email, "bug") {
		confidence += 0.2
	}

	// Domain validation
	if strings.Contains(email, ".") {
		confidence += 0.1
	}

	// Common security email patterns
	securityPatterns := []string{"security", "vuln", "bug", "disclosure", "responsible"}
	for _, pattern := range securityPatterns {
		if strings.Contains(strings.ToLower(email), pattern) {
			confidence += 0.1
			break
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// calculateURLConfidence calculates confidence score for URLs
func calculateURLConfidence(url string) float64 {
	confidence := 0.5 // Base confidence

	// HTTPS bonus
	if strings.HasPrefix(url, "https://") {
		confidence += 0.2
	}

	// Known platforms
	platforms := []string{"hackerone.com", "bugcrowd.com", "github.com", "gitlab.com"}
	for _, platform := range platforms {
		if strings.Contains(url, platform) {
			confidence += 0.3
			break
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// calculatePhoneConfidence calculates confidence score for phone numbers
func calculatePhoneConfidence(phone string) float64 {
	if len(phone) > 10 {
		return 0.7
	}
	return 0.5
}

// validateContactList validates a list of contacts (placeholder for actual validation)
func validateContactList(contacts []ContactInfo) []ContactInfo {
	// This would implement actual validation logic
	// For now, just return the contacts as-is
	return contacts
}
