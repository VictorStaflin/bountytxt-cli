package bounty

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/victorstaflin/bountytxt-cli/internal/core"
	"github.com/victorstaflin/bountytxt-cli/internal/discovery"
)

// Service handles bug bounty program analysis
type Service struct {
	config     *core.Config
	httpClient *http.Client
	discovery  *discovery.Service
}

// Program represents a bug bounty program
type Program struct {
	Domain          string            `json:"domain"`
	Name            string            `json:"name"`
	Platform        string            `json:"platform"`
	URL             string            `json:"url"`
	Status          string            `json:"status"`
	Type            string            `json:"type"`
	Industry        string            `json:"industry"`
	RewardRange     RewardRange       `json:"reward_range"`
	Scope           Scope             `json:"scope"`
	ResponseTime    ResponseTime      `json:"response_time"`
	Languages       []string          `json:"languages"`
	LastUpdated     time.Time         `json:"last_updated"`
	SecurityTxtInfo SecurityTxtInfo   `json:"security_txt_info"`
	Metadata        map[string]string `json:"metadata"`
}

// RewardRange represents the reward information
type RewardRange struct {
	HasBounties bool   `json:"has_bounties"`
	Minimum     int    `json:"minimum"`
	Maximum     int    `json:"maximum"`
	Currency    string `json:"currency"`
	Type        string `json:"type"` // "monetary", "swag", "recognition"
}

// Scope represents the program scope
type Scope struct {
	InScope    []Asset `json:"in_scope"`
	OutOfScope []Asset `json:"out_of_scope"`
	AssetCount int     `json:"asset_count"`
	Subdomains bool    `json:"subdomains"`
	Wildcards  bool    `json:"wildcards"`
}

// Asset represents a target asset
type Asset struct {
	Target      string   `json:"target"`
	Type        string   `json:"type"` // "web", "mobile", "api", "hardware", "other"
	Description string   `json:"description"`
	VulnTypes   []string `json:"vuln_types"`
	Exclusions  []string `json:"exclusions"`
}

// ResponseTime represents expected response times
type ResponseTime struct {
	FirstResponse string `json:"first_response"`
	Triage        string `json:"triage"`
	Resolution    string `json:"resolution"`
	SLA           string `json:"sla"`
}

// SecurityTxtInfo represents information from security.txt
type SecurityTxtInfo struct {
	HasSecurityTxt bool     `json:"has_security_txt"`
	PolicyURL      string   `json:"policy_url"`
	ContactEmails  []string `json:"contact_emails"`
	PreferredLangs []string `json:"preferred_langs"`
	Acknowledgment string   `json:"acknowledgment"`
	Expires        string   `json:"expires"`
}

// ProgramDatabase represents external program data
type ProgramDatabase struct {
	HackerOne []PlatformProgram `json:"hackerone"`
	Bugcrowd  []PlatformProgram `json:"bugcrowd"`
}

// PlatformProgram represents a program from external platforms
type PlatformProgram struct {
	Name     string `json:"name"`
	Handle   string `json:"handle"`
	URL      string `json:"url"`
	Status   string `json:"status"`
	Industry string `json:"industry"`
}

// NewService creates a new bounty service
func NewService(config *core.Config) *Service {
	httpClient := &http.Client{
		Timeout: config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= config.MaxRedirects {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	return &Service{
		config:     config,
		httpClient: httpClient,
		discovery:  discovery.NewService(config),
	}
}

// AnalyzeProgram analyzes a bug bounty program for the given domain
func (s *Service) AnalyzeProgram(domain string) (*Program, error) {
	program := &Program{
		Domain:      domain,
		LastUpdated: time.Now(),
		Metadata:    make(map[string]string),
	}

	// Get security.txt information
	securityTxtInfo, err := s.getSecurityTxtInfo(domain)
	if err == nil {
		program.SecurityTxtInfo = *securityTxtInfo
	}

	// Extract program information from security.txt
	if program.SecurityTxtInfo.HasSecurityTxt {
		s.extractProgramFromSecurityTxt(program)
	}

	// Detect platform from URL
	if program.URL != "" {
		program.Platform = s.detectPlatformFromURL(program.URL)
	}

	// Extract program name
	program.Name = s.extractProgramName(domain, program.SecurityTxtInfo.PolicyURL)

	// Determine program type
	program.Type = s.determineProgramType(program.SecurityTxtInfo)

	// Try to detect external program information
	s.detectExternalProgram(program)

	// Analyze scope
	s.analyzeScope(program)

	// Estimate rewards
	s.estimateRewards(program)

	// Analyze response times
	s.analyzeResponseTimes(program)

	return program, nil
}

// SearchPrograms searches for bug bounty programs
func (s *Service) SearchPrograms(query string, filters map[string]string) ([]*Program, error) {
	var programs []*Program

	// Search HackerOne
	h1Programs, err := s.searchHackerOne()
	if err == nil {
		programs = append(programs, h1Programs...)
	}

	// Search Bugcrowd
	bcPrograms, err := s.searchBugcrowd()
	if err == nil {
		programs = append(programs, bcPrograms...)
	}

	// Apply filters
	return s.filterPrograms(programs, filters), nil
}

// getSecurityTxtInfo retrieves and parses security.txt
func (s *Service) getSecurityTxtInfo(domain string) (*SecurityTxtInfo, error) {
	ctx := context.Background()
	result, err := s.discovery.Discover(ctx, domain)
	if err != nil || !result.Found || result.SecurityTxt == nil {
		return &SecurityTxtInfo{HasSecurityTxt: false}, err
	}

	securityTxt := result.SecurityTxt

	info := &SecurityTxtInfo{
		HasSecurityTxt: true,
		ContactEmails:  make([]string, 0),
		PreferredLangs: make([]string, 0),
	}

	// Extract policy URL
	if len(securityTxt.Policy) > 0 {
		info.PolicyURL = securityTxt.Policy[0]
	}

	// Extract contact emails
	for _, contact := range securityTxt.Contact {
		if strings.HasPrefix(contact, "mailto:") {
			email := strings.TrimPrefix(contact, "mailto:")
			info.ContactEmails = append(info.ContactEmails, email)
		}
	}

	// Extract preferred languages
	if len(securityTxt.PreferredLangs) > 0 {
		info.PreferredLangs = securityTxt.PreferredLangs
	}

	// Extract acknowledgments
	if len(securityTxt.Acknowledgments) > 0 {
		info.Acknowledgment = securityTxt.Acknowledgments[0]
	}

	// Extract expires
	if securityTxt.Expires != nil {
		info.Expires = securityTxt.Expires.Format(time.RFC3339)
	}

	return info, nil
}

// extractProgramFromSecurityTxt extracts program info from security.txt
func (s *Service) extractProgramFromSecurityTxt(program *Program) {
	if program.SecurityTxtInfo.PolicyURL != "" {
		program.URL = program.SecurityTxtInfo.PolicyURL

		// Try to extract additional information from policy URL
		if strings.Contains(program.SecurityTxtInfo.PolicyURL, "hackerone.com") {
			program.Platform = "HackerOne"
			program.Status = "Active"
		} else if strings.Contains(program.SecurityTxtInfo.PolicyURL, "bugcrowd.com") {
			program.Platform = "Bugcrowd"
			program.Status = "Active"
		} else if strings.Contains(program.SecurityTxtInfo.PolicyURL, "intigriti.com") {
			program.Platform = "Intigriti"
			program.Status = "Active"
		}
	}

	// Set languages
	if len(program.SecurityTxtInfo.PreferredLangs) > 0 {
		program.Languages = program.SecurityTxtInfo.PreferredLangs
	} else {
		program.Languages = []string{"en"}
	}
}

// detectPlatformFromURL detects the platform from URL
func (s *Service) detectPlatformFromURL(programURL string) string {
	u, err := url.Parse(programURL)
	if err != nil {
		return "Unknown"
	}

	hostname := strings.ToLower(u.Hostname())

	switch {
	case strings.Contains(hostname, "hackerone.com"):
		return "HackerOne"
	case strings.Contains(hostname, "bugcrowd.com"):
		return "Bugcrowd"
	case strings.Contains(hostname, "intigriti.com"):
		return "Intigriti"
	case strings.Contains(hostname, "yeswehack.com"):
		return "YesWeHack"
	case strings.Contains(hostname, "synack.com"):
		return "Synack"
	default:
		return "Private"
	}
}

// extractProgramName extracts program name from domain and URL
func (s *Service) extractProgramName(domain, policyURL string) string {
	// Try to extract from policy URL first
	if policyURL != "" {
		u, err := url.Parse(policyURL)
		if err == nil {
			path := strings.Trim(u.Path, "/")
			parts := strings.Split(path, "/")
			if len(parts) > 0 && parts[len(parts)-1] != "" {
				return strings.Title(strings.ReplaceAll(parts[len(parts)-1], "-", " "))
			}
		}
	}

	// Fallback to domain
	parts := strings.Split(domain, ".")
	if len(parts) > 0 {
		return strings.Title(parts[0])
	}

	return domain
}

// determineProgramType determines the program type
func (s *Service) determineProgramType(info SecurityTxtInfo) string {
	if info.PolicyURL != "" {
		return "Bug Bounty"
	}
	if len(info.ContactEmails) > 0 {
		return "Vulnerability Disclosure"
	}
	return "Unknown"
}

// detectExternalProgram tries to detect program from external sources
func (s *Service) detectExternalProgram(program *Program) {
	// This would typically involve API calls to HackerOne, Bugcrowd, etc.
	// For now, we'll use heuristics based on the domain

	// Set industry based on domain patterns
	domain := strings.ToLower(program.Domain)
	switch {
	case strings.Contains(domain, "bank") || strings.Contains(domain, "financial"):
		program.Industry = "Financial Services"
	case strings.Contains(domain, "tech") || strings.Contains(domain, "software"):
		program.Industry = "Technology"
	case strings.Contains(domain, "gov") || strings.Contains(domain, "government"):
		program.Industry = "Government"
	case strings.Contains(domain, "health") || strings.Contains(domain, "medical"):
		program.Industry = "Healthcare"
	case strings.Contains(domain, "edu") || strings.Contains(domain, "university"):
		program.Industry = "Education"
	default:
		program.Industry = "Other"
	}

	// Set default status if not already set
	if program.Status == "" {
		if program.SecurityTxtInfo.HasSecurityTxt {
			program.Status = "Active"
		} else {
			program.Status = "Unknown"
		}
	}
}

// analyzeScope analyzes the program scope
func (s *Service) analyzeScope(program *Program) {
	scope := &Scope{
		InScope:    make([]Asset, 0),
		OutOfScope: make([]Asset, 0),
	}

	// Add the main domain as in-scope
	mainAsset := Asset{
		Target:      program.Domain,
		Type:        "web",
		Description: "Main domain",
		VulnTypes:   []string{"XSS", "SQLi", "CSRF", "RCE", "LFI", "IDOR"},
		Exclusions:  []string{"DoS", "DDoS", "Social Engineering"},
	}
	scope.InScope = append(scope.InScope, mainAsset)

	// Check for wildcard subdomains
	if strings.HasPrefix(program.Domain, "*.") {
		scope.Wildcards = true
		scope.Subdomains = true
	} else {
		// Assume subdomains are in scope for most programs
		scope.Subdomains = true
		subdomainAsset := Asset{
			Target:      "*." + program.Domain,
			Type:        "web",
			Description: "All subdomains",
			VulnTypes:   []string{"XSS", "SQLi", "CSRF", "IDOR"},
			Exclusions:  []string{"DoS", "DDoS", "Social Engineering", "Physical attacks"},
		}
		scope.InScope = append(scope.InScope, subdomainAsset)
	}

	// Add common out-of-scope items
	commonOutOfScope := []Asset{
		{
			Target:      "Third-party services",
			Type:        "other",
			Description: "External services not owned by the organization",
		},
		{
			Target:      "Social engineering",
			Type:        "other",
			Description: "Attacks targeting employees or users",
		},
		{
			Target:      "Physical attacks",
			Type:        "other",
			Description: "Physical access to facilities or devices",
		},
	}
	scope.OutOfScope = append(scope.OutOfScope, commonOutOfScope...)

	scope.AssetCount = len(scope.InScope)
	program.Scope = *scope
}

// estimateRewards estimates reward ranges
func (s *Service) estimateRewards(program *Program) {
	rewards := &RewardRange{
		Currency: "$",
		Type:     "monetary",
	}

	// Determine if bounties are offered
	if program.SecurityTxtInfo.PolicyURL != "" {
		rewards.HasBounties = true

		// Estimate based on platform and industry
		switch program.Platform {
		case "HackerOne":
			rewards.Minimum = 100
			rewards.Maximum = 10000
		case "Bugcrowd":
			rewards.Minimum = 50
			rewards.Maximum = 5000
		case "Intigriti":
			rewards.Minimum = 25
			rewards.Maximum = 2500
		default:
			if program.Type == "Bug Bounty" {
				rewards.Minimum = 50
				rewards.Maximum = 1000
			} else {
				rewards.HasBounties = false
				rewards.Type = "recognition"
			}
		}

		// Adjust based on industry
		switch program.Industry {
		case "Financial Services":
			rewards.Maximum *= 3
		case "Technology":
			rewards.Maximum *= 2
		case "Government":
			rewards.Maximum *= 2
		}
	} else {
		rewards.HasBounties = false
		rewards.Type = "recognition"
	}

	program.RewardRange = *rewards
}

// analyzeResponseTimes analyzes expected response times
func (s *Service) analyzeResponseTimes(program *Program) {
	responseTime := &ResponseTime{}

	// Set default response times based on platform
	switch program.Platform {
	case "HackerOne":
		responseTime.FirstResponse = "1-3 business days"
		responseTime.Triage = "2-5 business days"
		responseTime.Resolution = "30-90 days"
		responseTime.SLA = "Standard HackerOne SLA"
	case "Bugcrowd":
		responseTime.FirstResponse = "2-5 business days"
		responseTime.Triage = "5-10 business days"
		responseTime.Resolution = "30-120 days"
		responseTime.SLA = "Standard Bugcrowd SLA"
	default:
		responseTime.FirstResponse = "1-7 business days"
		responseTime.Triage = "7-14 business days"
		responseTime.Resolution = "30-180 days"
		responseTime.SLA = "Best effort"
	}

	program.ResponseTime = *responseTime
}

// searchHackerOne searches HackerOne programs (mock implementation)
func (s *Service) searchHackerOne() ([]*Program, error) {
	// This would typically make API calls to HackerOne
	// For now, return empty results
	return []*Program{}, nil
}

// searchBugcrowd searches Bugcrowd programs (mock implementation)
func (s *Service) searchBugcrowd() ([]*Program, error) {
	// This would typically make API calls to Bugcrowd
	// For now, return empty results
	return []*Program{}, nil
}

// filterPrograms filters programs based on criteria
func (s *Service) filterPrograms(programs []*Program, filters map[string]string) []*Program {
	if len(filters) == 0 {
		return programs
	}

	var filtered []*Program
	for _, program := range programs {
		match := true

		if status, ok := filters["status"]; ok {
			if !strings.EqualFold(program.Status, status) {
				match = false
			}
		}

		if platform, ok := filters["platform"]; ok {
			if !strings.EqualFold(program.Platform, platform) {
				match = false
			}
		}

		if industry, ok := filters["industry"]; ok {
			if !strings.EqualFold(program.Industry, industry) {
				match = false
			}
		}

		if match {
			filtered = append(filtered, program)
		}
	}

	return filtered
}

// Close closes the service and cleans up resources
func (s *Service) Close() error {
	// Close HTTP client if needed
	if s.httpClient != nil {
		s.httpClient.CloseIdleConnections()
	}
	// Close discovery service
	if s.discovery != nil {
		return s.discovery.Close()
	}
	return nil
}
