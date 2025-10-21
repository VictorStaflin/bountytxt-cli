package core

import (
	"errors"
	"fmt"
)

// Common error types for the application
var (
	ErrDomainNotFound     = errors.New("domain not found")
	ErrSecurityTxtNotFound = errors.New("security.txt not found")
	ErrInvalidDomain      = errors.New("invalid domain format")
	ErrNetworkTimeout     = errors.New("network timeout")
	ErrTLSVerification    = errors.New("TLS verification failed")
	ErrTooManyRedirects   = errors.New("too many redirects")
	ErrRateLimited        = errors.New("rate limited")
	ErrRobotsBlocked      = errors.New("blocked by robots.txt")
	ErrInvalidFormat      = errors.New("invalid security.txt format")
	ErrExpiredFile        = errors.New("security.txt file has expired")
	ErrMissingContact     = errors.New("missing required Contact field")
	ErrInvalidExpires     = errors.New("invalid Expires field")
	ErrInvalidCanonical   = errors.New("invalid Canonical field")
	ErrInvalidContact     = errors.New("invalid Contact field")
)

// SecurityTxtError represents a structured error with context
type SecurityTxtError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Domain  string `json:"domain,omitempty"`
	URL     string `json:"url,omitempty"`
	Field   string `json:"field,omitempty"`
	Code    int    `json:"code,omitempty"`
}

func (e *SecurityTxtError) Error() string {
	if e.Domain != "" {
		return fmt.Sprintf("%s: %s (domain: %s)", e.Type, e.Message, e.Domain)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// NewSecurityTxtError creates a new structured error
func NewSecurityTxtError(errorType, message string) *SecurityTxtError {
	return &SecurityTxtError{
		Type:    errorType,
		Message: message,
	}
}

// WithDomain adds domain context to the error
func (e *SecurityTxtError) WithDomain(domain string) *SecurityTxtError {
	e.Domain = domain
	return e
}

// WithURL adds URL context to the error
func (e *SecurityTxtError) WithURL(url string) *SecurityTxtError {
	e.URL = url
	return e
}

// WithField adds field context to the error
func (e *SecurityTxtError) WithField(field string) *SecurityTxtError {
	e.Field = field
	return e
}

// WithCode adds HTTP status code context to the error
func (e *SecurityTxtError) WithCode(code int) *SecurityTxtError {
	e.Code = code
	return e
}

// Error type constants
const (
	ErrorTypeNetwork     = "network"
	ErrorTypeValidation  = "validation"
	ErrorTypeParsing     = "parsing"
	ErrorTypeCompliance  = "compliance"
	ErrorTypeRateLimit   = "rate_limit"
	ErrorTypePermission  = "permission"
	ErrorTypeNotFound    = "not_found"
	ErrorTypeTimeout     = "timeout"
	ErrorTypeTLS         = "tls"
	ErrorTypeRedirect    = "redirect"
	ErrorTypeFormat      = "format"
)

// IsRetryableError determines if an error should trigger a retry
func IsRetryableError(err error) bool {
	if secErr, ok := err.(*SecurityTxtError); ok {
		switch secErr.Type {
		case ErrorTypeNetwork, ErrorTypeTimeout, ErrorTypeRateLimit:
			return true
		case ErrorTypeTLS, ErrorTypePermission, ErrorTypeNotFound:
			return false
		default:
			return false
		}
	}
	return false
}

// GetExitCode returns appropriate exit code for CI integration
func GetExitCode(err error) int {
	if err == nil {
		return ExitSuccess
	}

	if secErr, ok := err.(*SecurityTxtError); ok {
		switch secErr.Type {
		case ErrorTypeValidation, ErrorTypeCompliance:
			return ExitValidationFailed
		case ErrorTypeNotFound:
			return ExitNotFound
		case ErrorTypeNetwork, ErrorTypeTimeout, ErrorTypeTLS:
			return ExitNetworkError
		default:
			return ExitInvalidInput
		}
	}

	return ExitInvalidInput
}