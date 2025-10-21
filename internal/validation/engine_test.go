package validation

import (
	"testing"
	"time"

	"securitytxt-cli/internal/core"
)

func TestNewEngine(t *testing.T) {
	// Test with nil rules
	engine := NewEngine(nil)
	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}
	if engine.rules == nil {
		t.Error("Engine rules should not be nil when created with nil rules")
	}

	// Test with custom rules
	customRules := &core.ValidationRules{
		RequiredFields:    []string{"Contact", "Expires"},
		RecommendedFields: []string{"Canonical"},
		OptionalFields:    []string{"Policy"},
		MaxAge:            180 * 24 * time.Hour,
		HTTPSRequired:     true,
	}

	engine = NewEngine(customRules)
	if engine == nil {
		t.Fatal("NewEngine returned nil")
	}
	if engine.rules != customRules {
		t.Error("Engine rules not set correctly")
	}
}

func TestValidate_ValidSecurityTxt(t *testing.T) {
	engine := NewEngine(nil)
	
	futureTime := time.Now().Add(30 * 24 * time.Hour)
	securityTxt := &core.SecurityTxt{
		Contact:     []string{"mailto:security@example.com"},
		Expires:     &futureTime,
		Canonical:   []string{"https://example.com/.well-known/security.txt"},
		RawContent:  "Contact: mailto:security@example.com\nExpires: " + futureTime.Format(time.RFC3339),
	}

	report := engine.Validate(securityTxt)
	
	if report == nil {
		t.Fatal("Validate returned nil report")
	}

	if report.Score < 80 {
		t.Errorf("Expected high score for valid security.txt, got %d", report.Score)
	}

	if report.Grade == "F" {
		t.Errorf("Expected good grade for valid security.txt, got %s", report.Grade)
	}
}

func TestValidate_MissingRequiredFields(t *testing.T) {
	engine := NewEngine(nil)
	
	securityTxt := &core.SecurityTxt{
		RawContent: "Policy: https://example.com/policy",
	}

	report := engine.Validate(securityTxt)
	
	if report == nil {
		t.Fatal("Validate returned nil report")
	}

	// Should have issues for missing Contact field
	hasContactIssue := false
	for _, issue := range report.Issues {
		if issue.Field == "Contact" && issue.Type == "missing_required_field" {
			hasContactIssue = true
			break
		}
	}

	if !hasContactIssue {
		t.Error("Expected issue for missing Contact field")
	}

	if report.Score >= 80 {
		t.Errorf("Expected low score for missing required fields, got %d", report.Score)
	}
}

func TestValidate_ExpiredSecurityTxt(t *testing.T) {
	engine := NewEngine(nil)
	
	pastTime := time.Now().Add(-30 * 24 * time.Hour)
	securityTxt := &core.SecurityTxt{
		Contact:    []string{"mailto:security@example.com"},
		Expires:    &pastTime,
		RawContent: "Contact: mailto:security@example.com\nExpires: " + pastTime.Format(time.RFC3339),
	}

	report := engine.Validate(securityTxt)
	
	if report == nil {
		t.Fatal("Validate returned nil report")
	}

	// Should have issue for expired security.txt
	hasExpiredIssue := false
	for _, issue := range report.Issues {
		if issue.Type == "expired" {
			hasExpiredIssue = true
			break
		}
	}

	if !hasExpiredIssue {
		t.Error("Expected issue for expired security.txt")
	}
}

func TestValidate_InvalidContactFormat(t *testing.T) {
	engine := NewEngine(nil)
	
	futureTime := time.Now().Add(30 * 24 * time.Hour)
	securityTxt := &core.SecurityTxt{
		Contact:    []string{"invalid-contact-format"},
		Expires:    &futureTime,
		RawContent: "Contact: invalid-contact-format",
	}

	report := engine.Validate(securityTxt)
	
	if report == nil {
		t.Fatal("Validate returned nil report")
	}

	// Should have issue for invalid contact format
	hasFormatIssue := false
	for _, issue := range report.Issues {
		if issue.Field == "Contact" && issue.Type == "invalid_format" {
			hasFormatIssue = true
			break
		}
	}

	if !hasFormatIssue {
		t.Error("Expected issue for invalid contact format")
	}
}

func TestValidate_ScoreCalculation(t *testing.T) {
	engine := NewEngine(nil)
	
	tests := []struct {
		name           string
		securityTxt    *core.SecurityTxt
		expectedMinScore int
		expectedMaxScore int
	}{
		{
			name: "perfect security.txt",
			securityTxt: &core.SecurityTxt{
				Contact:   []string{"mailto:security@example.com"},
				Expires:   timePtr(time.Now().Add(30 * 24 * time.Hour)),
				Canonical: []string{"https://example.com/.well-known/security.txt"},
				RawContent: "Contact: mailto:security@example.com",
			},
			expectedMinScore: 90,
			expectedMaxScore: 100,
		},
		{
			name: "minimal security.txt",
			securityTxt: &core.SecurityTxt{
				Contact:    []string{"mailto:security@example.com"},
				RawContent: "Contact: mailto:security@example.com",
			},
			expectedMinScore: 50,
			expectedMaxScore: 80,
		},
		{
			name: "empty security.txt",
			securityTxt: &core.SecurityTxt{
				RawContent: "",
			},
			expectedMinScore: 0,
			expectedMaxScore: 30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := engine.Validate(tt.securityTxt)
			
			if report.Score < tt.expectedMinScore || report.Score > tt.expectedMaxScore {
				t.Errorf("Score %d not in expected range [%d, %d]", 
					report.Score, tt.expectedMinScore, tt.expectedMaxScore)
			}

			// Verify score is within valid range
			if report.Score < 0 || report.Score > 100 {
				t.Errorf("Score %d is outside valid range [0, 100]", report.Score)
			}

			// Verify grade is set
			if report.Grade == "" {
				t.Error("Grade should not be empty")
			}

			// Verify grade matches score
			expectedGrade := calculateExpectedGrade(report.Score)
			if report.Grade != expectedGrade {
				t.Errorf("Grade %s doesn't match score %d (expected %s)", 
					report.Grade, report.Score, expectedGrade)
			}
		})
	}
}

func TestValidate_IssueStructure(t *testing.T) {
	engine := NewEngine(nil)
	
	securityTxt := &core.SecurityTxt{
		Contact:    []string{"invalid-contact"},
		RawContent: "Contact: invalid-contact",
	}

	report := engine.Validate(securityTxt)
	
	if report == nil {
		t.Fatal("Validate returned nil report")
	}

	for i, issue := range report.Issues {
		if issue.Type == "" {
			t.Errorf("Issue %d has empty type", i)
		}
		if issue.Category == "" {
			t.Errorf("Issue %d has empty category", i)
		}
		if issue.Message == "" {
			t.Errorf("Issue %d has empty message", i)
		}
		if issue.Severity == "" {
			t.Errorf("Issue %d has empty severity", i)
		}
		
		// Verify severity is valid
		validSeverities := map[string]bool{
			"error":   true,
			"warning": true,
			"info":    true,
			"hint":    true,
		}
		if !validSeverities[issue.Severity] {
			t.Errorf("Issue %d has invalid severity: %s", i, issue.Severity)
		}
	}
}

// Helper functions
func timePtr(t time.Time) *time.Time {
	return &t
}

func calculateExpectedGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}