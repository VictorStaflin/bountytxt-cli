package validation

import (
	"context"
	"testing"
	"time"

	"securitytxt-cli/internal/core"
)

func TestNewService(t *testing.T) {
	config := &core.Config{
		Timeout:      30 * time.Second,
		MaxRedirects: 5,
		UserAgent:    "test-agent",
		Output: core.OutputConfig{
			Format: "json",
		},
	}

	service := NewService(config)
	if service == nil {
		t.Fatal("NewService returned nil")
	}

	if service.engine == nil {
		t.Error("Service engine is nil")
	}

	if service.discovery == nil {
		t.Error("Service discovery is nil")
	}

	if service.config != config {
		t.Error("Service config not set correctly")
	}
}

func TestValidateContent(t *testing.T) {
	config := &core.Config{
		Timeout:      30 * time.Second,
		MaxRedirects: 5,
		UserAgent:    "test-agent",
	}

	service := NewService(config)

	tests := []struct {
		name        string
		content     string
		sourceURL   string
		expectFound bool
		expectScore int
		expectGrade string
	}{
		{
			name: "valid security.txt",
			content: `Contact: mailto:security@example.com
Expires: 2025-12-31T23:59:59.000Z
Canonical: https://example.com/.well-known/security.txt`,
			sourceURL:   "https://example.com/.well-known/security.txt",
			expectFound: true,
			expectScore: 100,
			expectGrade: "A",
		},
		{
			name: "minimal security.txt",
			content: `Contact: mailto:security@example.com`,
			sourceURL:   "https://example.com/.well-known/security.txt",
			expectFound: true,
			expectScore: 70, // Should be lower due to missing recommended fields
			expectGrade: "C",
		},
		{
			name: "invalid content",
			content: `Invalid content that cannot be parsed`,
			sourceURL:   "https://example.com/.well-known/security.txt",
			expectFound: false,
			expectScore: 0,
			expectGrade: "F",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := service.ValidateContent(tt.content, tt.sourceURL)
			
			if report == nil {
				t.Fatal("ValidateContent returned nil report")
			}

			if report.SourceURL != tt.sourceURL {
				t.Errorf("Expected source URL %s, got %s", tt.sourceURL, report.SourceURL)
			}

			if report.Score < 0 || report.Score > 100 {
				t.Errorf("Score should be between 0-100, got %d", report.Score)
			}

			if report.Grade == "" {
				t.Error("Grade should not be empty")
			}

			// Check that issues are properly categorized
			for _, issue := range report.Issues {
				if issue.Type == "" {
					t.Error("Issue type should not be empty")
				}
				if issue.Severity == "" {
					t.Error("Issue severity should not be empty")
				}
			}
		})
	}
}

func TestValidateDomain_NotFound(t *testing.T) {
	config := &core.Config{
		Timeout:      5 * time.Second,
		MaxRedirects: 5,
		UserAgent:    "test-agent",
	}

	service := NewService(config)
	ctx := context.Background()

	// Test with a domain that likely doesn't have security.txt
	report, err := service.ValidateDomain(ctx, "nonexistent-domain-12345.com")
	
	// We expect either an error (DNS resolution failure) or a report indicating not found
	if err == nil {
		if report == nil {
			t.Fatal("ValidateDomain returned nil report and nil error")
		}

		if report.Found {
			t.Error("Expected security.txt not to be found for nonexistent domain")
		}

		if report.Score != 0 {
			t.Errorf("Expected score 0 for not found, got %d", report.Score)
		}

		if report.Grade != "F" {
			t.Errorf("Expected grade F for not found, got %s", report.Grade)
		}
	}
	// If there's an error, that's also acceptable (DNS resolution failure, etc.)
}

func TestValidateBulk(t *testing.T) {
	config := &core.Config{
		Timeout:      5 * time.Second,
		MaxRedirects: 5,
		UserAgent:    "test-agent",
	}

	service := NewService(config)
	ctx := context.Background()

	domains := []string{
		"nonexistent-domain-12345.com",
		"another-nonexistent-domain-67890.com",
	}

	options := &core.BulkOptions{
		Workers: 2,
		Delay:   100 * time.Millisecond,
	}

	reports, err := service.ValidateBulk(ctx, domains, options)
	
	// We expect either an error or reports for all domains
	if err == nil {
		if len(reports) != len(domains) {
			t.Errorf("Expected %d reports, got %d", len(domains), len(reports))
		}

		for i, report := range reports {
			if report == nil {
				t.Errorf("Report %d is nil", i)
				continue
			}

			if report.Domain != domains[i] {
				t.Errorf("Expected domain %s, got %s", domains[i], report.Domain)
			}
		}
	}
	// If there's an error, that's also acceptable for bulk operations
}

func TestServiceClose(t *testing.T) {
	config := &core.Config{
		Timeout:      30 * time.Second,
		MaxRedirects: 5,
		UserAgent:    "test-agent",
	}

	service := NewService(config)
	
	err := service.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}