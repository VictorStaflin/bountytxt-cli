package discovery

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/victorstaflin/bountytxt-cli/internal/core"
	httpClient "github.com/victorstaflin/bountytxt-cli/internal/http"
)

// Service handles security.txt discovery
type Service struct {
	client *httpClient.Client
	config *core.Config
}

// NewService creates a new discovery service
func NewService(config *core.Config) *Service {
	return &Service{
		client: httpClient.NewClient(config),
		config: config,
	}
}

// Discover attempts to find security.txt for a domain
func (s *Service) Discover(ctx context.Context, domain string) (*core.DiscoveryResult, error) {
	result := &core.DiscoveryResult{
		Domain:       domain,
		DiscoveredAt: time.Now(),
		Attempts:     make([]core.Fallback, 0),
		Found:        false,
	}

	// Standard discovery URLs according to RFC 9116
	urls := []string{
		fmt.Sprintf("https://%s/.well-known/security.txt", domain),
		fmt.Sprintf("https://%s/security.txt", domain),
	}

	// Try each URL in order
	for _, url := range urls {
		attempt := core.Fallback{
			URL:         url,
			Method:      "GET",
			AttemptedAt: time.Now(),
		}

		resp, err := s.client.Get(ctx, url)
		if err != nil {
			attempt.Error = err.Error()
			attempt.Success = false
			result.Attempts = append(result.Attempts, attempt)
			continue
		}

		attempt.StatusCode = resp.StatusCode

		if resp.StatusCode == http.StatusOK {
			// Read the response body
			body, err := s.client.ReadResponse(resp)
			if err != nil {
				attempt.Error = err.Error()
				attempt.Success = false
				result.Attempts = append(result.Attempts, attempt)
				continue
			}

			// Parse the security.txt content
			securityTxt, err := s.parseSecurityTxt(string(body))
			if err != nil {
				attempt.Error = err.Error()
				attempt.Success = false
				result.Attempts = append(result.Attempts, attempt)
				continue
			}

			// Success!
			attempt.Success = true
			result.Attempts = append(result.Attempts, attempt)
			result.Found = true
			result.SecurityTxt = securityTxt
			result.SourceURL = url
			return result, nil
		} else {
			attempt.Success = false
			attempt.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
			result.Attempts = append(result.Attempts, attempt)
		}
	}

	return result, nil
}

// DiscoverBulk discovers security.txt for multiple domains
func (s *Service) DiscoverBulk(ctx context.Context, domains []string, options core.BulkOptions) ([]*core.DiscoveryResult, error) {
	results := make([]*core.DiscoveryResult, 0, len(domains))
	
	// Create worker pool
	workers := options.Workers
	if workers <= 0 {
		workers = s.config.Workers
	}
	if workers <= 0 {
		workers = 5 // Default
	}

	// Create channels for work distribution
	domainChan := make(chan string, len(domains))
	resultChan := make(chan *core.DiscoveryResult, len(domains))
	errorChan := make(chan error, len(domains))

	// Start workers
	for i := 0; i < workers; i++ {
		go func() {
			for domain := range domainChan {
				result, err := s.Discover(ctx, domain)
				if err != nil {
					errorChan <- err
				} else {
					resultChan <- result
				}
			}
		}()
	}

	// Send domains to workers
	for _, domain := range domains {
		domainChan <- domain
	}
	close(domainChan)

	// Collect results
	for i := 0; i < len(domains); i++ {
		select {
		case result := <-resultChan:
			results = append(results, result)
		case err := <-errorChan:
			if !options.ContinueOnError {
				return results, err
			}
			// Create a failed result
			results = append(results, &core.DiscoveryResult{
				Domain:       "unknown",
				DiscoveredAt: time.Now(),
				Found:        false,
				Attempts: []core.Fallback{{
					URL:         "unknown",
					Method:      "GET",
					AttemptedAt: time.Now(),
					Success:     false,
					Error:       err.Error(),
				}},
			})
		case <-ctx.Done():
			return results, ctx.Err()
		}
	}

	return results, nil
}

// parseSecurityTxt parses security.txt content into a structured format
func (s *Service) parseSecurityTxt(content string) (*core.SecurityTxt, error) {
	securityTxt := &core.SecurityTxt{
		Contact:         make([]string, 0),
		Encryption:      make([]string, 0),
		Acknowledgments: make([]string, 0),
		Languages:       make([]string, 0),
		Canonical:       make([]string, 0),
		Policy:          make([]string, 0),
		Hiring:          make([]string, 0),
		CSAF:            make([]string, 0),
		PreferredLangs:  make([]string, 0),
		Extensions:      make(map[string]string),
		RawContent:      content,
	}

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse field: value format
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		field := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Handle standard fields
		switch strings.ToLower(field) {
		case "contact":
			securityTxt.Contact = append(securityTxt.Contact, value)
		case "expires":
			if expires, err := time.Parse(time.RFC3339, value); err == nil {
				securityTxt.Expires = &expires
			}
		case "encryption":
			securityTxt.Encryption = append(securityTxt.Encryption, value)
		case "acknowledgments", "acknowledgements":
			securityTxt.Acknowledgments = append(securityTxt.Acknowledgments, value)
		case "languages", "preferred-languages":
			securityTxt.Languages = append(securityTxt.Languages, value)
		case "canonical":
			securityTxt.Canonical = append(securityTxt.Canonical, value)
		case "policy":
			securityTxt.Policy = append(securityTxt.Policy, value)
		case "hiring":
			securityTxt.Hiring = append(securityTxt.Hiring, value)
		case "csaf":
			securityTxt.CSAF = append(securityTxt.CSAF, value)
		default:
			// Handle extension fields
			securityTxt.Extensions[field] = value
		}
	}

	return securityTxt, nil
}

// Close closes the discovery service and cleans up resources
func (s *Service) Close() error {
	return s.client.Close()
}