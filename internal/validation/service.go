package validation

import (
	"context"
	"time"

	"github.com/victorstaflin/bountytxt-cli/internal/core"
	"github.com/victorstaflin/bountytxt-cli/internal/discovery"
)

// Service provides validation services for security.txt files
type Service struct {
	engine    *Engine
	discovery *discovery.Service
	config    *core.Config
}

// NewService creates a new validation service
func NewService(config *core.Config) *Service {
	// Create validation rules from config
	rules := &core.ValidationRules{
		RequiredFields:    []string{"Contact"},
		RecommendedFields: []string{"Expires", "Canonical"},
		OptionalFields:    []string{"Encryption", "Acknowledgments", "Languages", "Policy", "Hiring", "CSAF"},
		MaxAge:            365 * 24 * time.Hour, // 1 year
		HTTPSRequired:     true,
	}

	return &Service{
		engine:    NewEngine(rules),
		discovery: discovery.NewService(config),
		config:    config,
	}
}

// ValidateDomain discovers and validates security.txt for a domain
func (s *Service) ValidateDomain(ctx context.Context, domain string) (*core.LintReport, error) {
	// Discover security.txt
	result, err := s.discovery.Discover(ctx, domain)
	if err != nil {
		return nil, err
	}

	if !result.Found || result.SecurityTxt == nil {
		// Return a report indicating no security.txt found
		return &core.LintReport{
			Domain:    domain,
			SourceURL: "",
			Found:     false,
			Issues: []core.Issue{{
				Type:        "error",
				Category:    "discovery",
				Field:       "",
				Message:     "No security.txt file found",
				Severity:    "high",
				ScoreImpact: -100,
			}},
			Score: 0,
			Grade: "F",
		}, nil
	}

	// Validate the discovered security.txt
	report := s.engine.Validate(result.SecurityTxt)

	// Add discovery information to the report
	report.Found = true
	report.DiscoveryResult = result

	return report, nil
}

// ValidateBulk validates security.txt files for multiple domains
func (s *Service) ValidateBulk(ctx context.Context, domains []string, options *core.BulkOptions) ([]*core.LintReport, error) {
	// Discover security.txt files for all domains
	bulkOpts := core.BulkOptions{}
	if options != nil {
		bulkOpts = *options
	}
	results, err := s.discovery.DiscoverBulk(ctx, domains, bulkOpts)
	if err != nil {
		return nil, err
	}

	// Validate each discovered security.txt
	reports := make([]*core.LintReport, 0, len(results))
	for _, result := range results {
		if result.Found && result.SecurityTxt != nil {
			report := s.engine.Validate(result.SecurityTxt)
			report.Found = true
			report.DiscoveryResult = result
			reports = append(reports, report)
		} else {
			// Create a report for domains without security.txt
			report := &core.LintReport{
				Domain:    result.Domain,
				SourceURL: "",
				Found:     false,
				Issues: []core.Issue{{
					Type:        "error",
					Category:    "discovery",
					Field:       "",
					Message:     "No security.txt file found",
					Severity:    "high",
					ScoreImpact: -100,
				}},
				Score:           0,
				Grade:           "F",
				DiscoveryResult: result,
			}
			reports = append(reports, report)
		}
	}

	return reports, nil
}

// ValidateContent validates security.txt content directly
func (s *Service) ValidateContent(content, sourceURL string) *core.LintReport {
	// Parse the content using the discovery parser
	parser := discovery.NewParser(s.config)
	securityTxt, err := parser.Parse(content, sourceURL)
	if err != nil {
		return &core.LintReport{
			Domain:    extractDomainFromURL(sourceURL),
			SourceURL: sourceURL,
			Issues: []core.Issue{{
				Type:        "error",
				Category:    "parsing",
				Field:       "",
				Message:     err.Error(),
				Severity:    "high",
				ScoreImpact: -50,
			}},
			Score: 0,
			Grade: "F",
		}
	}

	return s.engine.Validate(securityTxt)
}

// Close cleans up the validation service resources
func (s *Service) Close() error {
	return s.discovery.Close()
}
