package platform

import (
	"net/url"
	"regexp"
	"strings"

	"securitytxt-cli/internal/core"
)

// Detector identifies bug bounty platforms and security programs
type Detector struct {
	patterns map[string]*PlatformPattern
}

// PlatformPattern defines patterns for detecting platforms
type PlatformPattern struct {
	Name        string
	URLPatterns []string
	Indicators  []string
	Confidence  float64
}

// NewDetector creates a new platform detector
func NewDetector() *Detector {
	return &Detector{
		patterns: map[string]*PlatformPattern{
			"hackerone": {
				Name: "HackerOne",
				URLPatterns: []string{
					`hackerone\.com/([^/]+)`,
					`h1\.com/([^/]+)`,
				},
				Indicators: []string{
					"hackerone.com",
					"h1.com",
					"hackerone",
				},
				Confidence: 0.95,
			},
			"bugcrowd": {
				Name: "Bugcrowd",
				URLPatterns: []string{
					`bugcrowd\.com/([^/]+)`,
					`bc\.com/([^/]+)`,
				},
				Indicators: []string{
					"bugcrowd.com",
					"bc.com",
					"bugcrowd",
				},
				Confidence: 0.95,
			},
			"intigriti": {
				Name: "Intigriti",
				URLPatterns: []string{
					`intigriti\.com/programs/([^/]+)`,
				},
				Indicators: []string{
					"intigriti.com",
					"intigriti",
				},
				Confidence: 0.90,
			},
			"yeswehack": {
				Name: "YesWeHack",
				URLPatterns: []string{
					`yeswehack\.com/programs/([^/]+)`,
				},
				Indicators: []string{
					"yeswehack.com",
					"yeswehack",
				},
				Confidence: 0.90,
			},
			"synack": {
				Name: "Synack",
				URLPatterns: []string{
					`synack\.com/red-team/([^/]+)`,
				},
				Indicators: []string{
					"synack.com",
					"synack",
				},
				Confidence: 0.85,
			},
			"cobalt": {
				Name: "Cobalt",
				URLPatterns: []string{
					`cobalt\.io/([^/]+)`,
				},
				Indicators: []string{
					"cobalt.io",
					"cobalt",
				},
				Confidence: 0.85,
			},
			"federacy": {
				Name: "Federacy",
				URLPatterns: []string{
					`federacy\.com/([^/]+)`,
				},
				Indicators: []string{
					"federacy.com",
					"federacy",
				},
				Confidence: 0.80,
			},
			"zerocopter": {
				Name: "Zerocopter",
				URLPatterns: []string{
					`zerocopter\.com/([^/]+)`,
				},
				Indicators: []string{
					"zerocopter.com",
					"zerocopter",
				},
				Confidence: 0.80,
			},
		},
	}
}

// DetectPlatforms analyzes security.txt content and detects platforms
func (d *Detector) DetectPlatforms(securityTxt *core.SecurityTxt) []core.Platform {
	platforms := make([]core.Platform, 0)
	detected := make(map[string]bool)

	// Check all URLs in the security.txt
	allURLs := make([]string, 0)
	allURLs = append(allURLs, securityTxt.Contact...)
	allURLs = append(allURLs, securityTxt.Policy...)
	allURLs = append(allURLs, securityTxt.Acknowledgments...)
	allURLs = append(allURLs, securityTxt.Hiring...)

	for _, urlStr := range allURLs {
		if platform := d.detectFromURL(urlStr); platform != nil && !detected[platform.Name] {
			platforms = append(platforms, *platform)
			detected[platform.Name] = true
		}
	}

	// Check raw content for additional indicators
	contentPlatforms := d.detectFromContent(securityTxt.RawContent)
	for _, platform := range contentPlatforms {
		if !detected[platform.Name] {
			platforms = append(platforms, platform)
			detected[platform.Name] = true
		}
	}

	return platforms
}

// detectFromURL detects platform from a single URL
func (d *Detector) detectFromURL(urlStr string) *core.Platform {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil
	}

	host := strings.ToLower(parsedURL.Host)
	fullURL := strings.ToLower(urlStr)

	for platformID, pattern := range d.patterns {
		// Check URL patterns
		for _, urlPattern := range pattern.URLPatterns {
			re := regexp.MustCompile(urlPattern)
			if matches := re.FindStringSubmatch(fullURL); len(matches) > 1 {
				return &core.Platform{
					Name:       pattern.Name,
					Type:       d.getPlatformType(platformID),
					URL:        urlStr,
					Confidence: pattern.Confidence,
					Program:    matches[1], // Extract program name from URL
				}
			}
		}

		// Check host indicators
		for _, indicator := range pattern.Indicators {
			if strings.Contains(host, indicator) {
				return &core.Platform{
					Name:       pattern.Name,
					Type:       d.getPlatformType(platformID),
					URL:        urlStr,
					Confidence: pattern.Confidence * 0.8, // Lower confidence for host-only match
					Program:    d.extractProgramFromURL(urlStr),
				}
			}
		}
	}

	return nil
}

// detectFromContent detects platforms from raw content
func (d *Detector) detectFromContent(content string) []core.Platform {
	platforms := make([]core.Platform, 0)
	contentLower := strings.ToLower(content)

	for platformID, pattern := range d.patterns {
		for _, indicator := range pattern.Indicators {
			if strings.Contains(contentLower, indicator) {
				platforms = append(platforms, core.Platform{
					Name:       pattern.Name,
					Type:       d.getPlatformType(platformID),
					URL:        "",
					Confidence: pattern.Confidence * 0.6, // Lower confidence for content-only match
					Program:    "",
				})
				break // Only add once per platform
			}
		}
	}

	return platforms
}

// getPlatformType returns the platform type based on platform ID
func (d *Detector) getPlatformType(platformID string) string {
	switch platformID {
	case "hackerone", "bugcrowd", "intigriti", "yeswehack", "synack", "cobalt", "federacy", "zerocopter":
		return "bug_bounty"
	default:
		return "unknown"
	}
}

// extractProgramFromURL attempts to extract program name from URL
func (d *Detector) extractProgramFromURL(urlStr string) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}

	path := strings.Trim(parsedURL.Path, "/")
	parts := strings.Split(path, "/")

	// Common patterns for program extraction
	for i, part := range parts {
		if part == "programs" || part == "program" {
			if i+1 < len(parts) {
				return parts[i+1]
			}
		}
		if part == "red-team" {
			if i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}

	// If no specific pattern, return the last path segment
	if len(parts) > 0 && parts[len(parts)-1] != "" {
		return parts[len(parts)-1]
	}

	return ""
}

// AnalyzeContacts analyzes contact information for intelligence
func (d *Detector) AnalyzeContacts(securityTxt *core.SecurityTxt) []core.ContactIntelligence {
	intelligence := make([]core.ContactIntelligence, 0)

	for _, contact := range securityTxt.Contact {
		intel := d.analyzeContact(contact)
		if intel != nil {
			intelligence = append(intelligence, *intel)
		}
	}

	return intelligence
}

// analyzeContact analyzes a single contact for intelligence
func (d *Detector) analyzeContact(contact string) *core.ContactIntelligence {
	intel := &core.ContactIntelligence{
		Contact:    contact,
		Type:       d.getContactType(contact),
		Confidence: 0.5,
		Metadata:   make(map[string]interface{}),
	}

	// Analyze email addresses
	if strings.Contains(contact, "@") {
		intel.Type = "email"
		intel.Confidence = 0.9

		// Extract domain
		parts := strings.Split(contact, "@")
		if len(parts) == 2 {
			domain := parts[1]
			intel.Metadata["domain"] = domain

			// Check for security-specific emails
			localPart := strings.ToLower(parts[0])
			if d.isSecurityEmail(localPart) {
				intel.Confidence = 0.95
				intel.Metadata["security_specific"] = "true"
			}

			// Check for role-based emails
			if d.isRoleBasedEmail(localPart) {
				intel.Metadata["role_based"] = "true"
			}
		}
	}

	// Analyze URLs
	if strings.HasPrefix(contact, "http") {
		intel.Type = "url"
		intel.Confidence = 0.8

		parsedURL, err := url.Parse(contact)
		if err == nil {
			intel.Metadata["host"] = parsedURL.Host
			intel.Metadata["scheme"] = parsedURL.Scheme

			// Check for HTTPS
			if parsedURL.Scheme == "https" {
				intel.Confidence += 0.1
			}

			// Check for platform URLs
			if platform := d.detectFromURL(contact); platform != nil {
				intel.Metadata["platform"] = platform.Name
				intel.Confidence = 0.95
			}
		}
	}

	// Analyze phone numbers
	if strings.HasPrefix(contact, "tel:") {
		intel.Type = "phone"
		intel.Confidence = 0.7
		intel.Metadata["number"] = strings.TrimPrefix(contact, "tel:")
	}

	return intel
}

// getContactType determines the type of contact
func (d *Detector) getContactType(contact string) string {
	if strings.Contains(contact, "@") {
		return "email"
	}
	if strings.HasPrefix(contact, "http") {
		return "url"
	}
	if strings.HasPrefix(contact, "tel:") {
		return "phone"
	}
	return "unknown"
}

// isSecurityEmail checks if an email is security-specific
func (d *Detector) isSecurityEmail(localPart string) bool {
	securityTerms := []string{
		"security", "vuln", "vulnerability", "bug", "bounty",
		"disclosure", "responsible", "coordinated", "psirt",
		"cert", "csirt", "incident", "response",
	}

	for _, term := range securityTerms {
		if strings.Contains(localPart, term) {
			return true
		}
	}

	return false
}

// isRoleBasedEmail checks if an email is role-based
func (d *Detector) isRoleBasedEmail(localPart string) bool {
	roleTerms := []string{
		"admin", "administrator", "support", "help", "info",
		"contact", "noreply", "no-reply", "postmaster", "webmaster",
		"abuse", "legal", "privacy", "compliance",
	}

	for _, term := range roleTerms {
		if localPart == term || strings.HasPrefix(localPart, term+"-") || strings.HasSuffix(localPart, "-"+term) {
			return true
		}
	}

	return false
}

// GetPlatformStats returns statistics about detected platforms
func (d *Detector) GetPlatformStats(platforms []core.Platform) map[string]interface{} {
	stats := make(map[string]interface{})

	if len(platforms) == 0 {
		stats["total"] = 0
		stats["types"] = make(map[string]int)
		return stats
	}

	stats["total"] = len(platforms)

	// Count by type
	typeCount := make(map[string]int)
	highConfidence := 0
	avgConfidence := 0.0

	for _, platform := range platforms {
		typeCount[platform.Type]++
		if platform.Confidence >= 0.8 {
			highConfidence++
		}
		avgConfidence += platform.Confidence
	}

	stats["types"] = typeCount
	stats["high_confidence"] = highConfidence
	stats["average_confidence"] = avgConfidence / float64(len(platforms))

	return stats
}