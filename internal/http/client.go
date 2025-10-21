package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/victorstaflin/bountytxt-cli/internal/core"
)

// Client represents an HTTP client with security.txt specific features
type Client struct {
	httpClient  *http.Client
	config      *core.Config
	rateLimiter *RateLimiter
	robotsCache map[string]bool
}

// NewClient creates a new HTTP client with the given configuration
func NewClient(config *core.Config) *Client {
	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !config.VerifyTLS,
		MinVersion:         tls.VersionTLS12,
	}

	// Configure transport
	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Configure HTTP client
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= config.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", config.MaxRedirects)
			}
			return nil
		},
	}

	// Create rate limiter
	rateLimiter := NewRateLimiter(config.MaxRPS, config.Concurrency)

	return &Client{
		httpClient:  httpClient,
		config:      config,
		rateLimiter: rateLimiter,
		robotsCache: make(map[string]bool),
	}
}

// Get performs an HTTP GET request with rate limiting and robots.txt compliance
func (c *Client) Get(ctx context.Context, url string) (*http.Response, error) {
	// Check robots.txt compliance if enabled
	if c.config.HonorRobots {
		allowed, err := c.checkRobotsTxt(url)
		if err != nil {
			return nil, fmt.Errorf("robots.txt check failed: %w", err)
		}
		if !allowed {
			return nil, fmt.Errorf("robots.txt disallows access to %s", url)
		}
	}

	// Apply rate limiting
	if rateLimitErr := c.rateLimiter.Wait(ctx); rateLimitErr != nil {
		return nil, fmt.Errorf("rate limiting failed: %w", rateLimitErr)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set user agent
	req.Header.Set("User-Agent", c.config.UserAgent)

	// Set security headers
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("Cache-Control", "no-cache")

	// Perform request
	var resp *http.Response
	resp, err = c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}

	return resp, nil
}

// GetWithOptions performs an HTTP GET request with additional options
func (c *Client) GetWithOptions(ctx context.Context, url string, options core.FetchOptions) (*http.Response, error) {
	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers from options
	for key, value := range options.Headers {
		req.Header.Set(key, value)
	}

	// Set default headers if not provided
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.config.UserAgent)
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/plain")
	}

	// Apply timeout from options
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	// Apply rate limiting
	if rateLimitErr := c.rateLimiter.Wait(ctx); rateLimitErr != nil {
		return nil, fmt.Errorf("rate limiting failed: %w", rateLimitErr)
	}

	// Perform request
	var resp *http.Response
	resp, err = c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}

	return resp, nil
}

// ReadResponse reads the response body and closes it
func (c *Client) ReadResponse(response *http.Response) ([]byte, error) {
	defer response.Body.Close()

	// Limit response size to prevent abuse
	const maxResponseSize = 10 * 1024 * 1024 // 10MB
	limitedReader := io.LimitReader(response.Body, maxResponseSize)

	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, nil
}

// checkRobotsTxt checks if the URL is allowed by robots.txt
func (c *Client) checkRobotsTxt(targetURL string) (bool, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return false, fmt.Errorf("invalid URL: %w", err)
	}

	robotsURL := fmt.Sprintf("%s://%s/robots.txt", parsedURL.Scheme, parsedURL.Host)

	// Check cache first
	if allowed, exists := c.robotsCache[robotsURL]; exists {
		return allowed, nil
	}

	// Fetch robots.txt
	var resp *http.Response
	resp, err = c.httpClient.Get(robotsURL)
	if err != nil {
		// If robots.txt is not accessible, allow by default
		c.robotsCache[robotsURL] = true
		return true, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// If robots.txt returns non-200, allow by default
		c.robotsCache[robotsURL] = true
		return true, nil
	}

	var body []byte
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		// If we can't read robots.txt, allow by default
		c.robotsCache[robotsURL] = true
		return true, nil
	}

	// Parse robots.txt (simplified implementation)
	allowed := c.parseRobotsTxt(string(body), parsedURL.Path, c.config.UserAgent)
	c.robotsCache[robotsURL] = allowed

	return allowed, nil
}

// parseRobotsTxt parses robots.txt content and checks if the path is allowed
func (c *Client) parseRobotsTxt(content, path, userAgent string) bool {
	lines := strings.Split(content, "\n")
	var currentUserAgent string
	var disallowed []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		directive := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch directive {
		case "user-agent":
			currentUserAgent = value
		case "disallow":
			if currentUserAgent == "*" || strings.Contains(userAgent, currentUserAgent) {
				disallowed = append(disallowed, value)
			}
		}
	}

	// Check if path is disallowed
	for _, pattern := range disallowed {
		if pattern == "/" || strings.HasPrefix(path, pattern) {
			return false
		}
	}

	return true
}

// Close closes the HTTP client and cleans up resources
func (c *Client) Close() error {
	c.httpClient.CloseIdleConnections()
	return nil
}
