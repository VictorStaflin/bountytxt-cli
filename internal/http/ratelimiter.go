package http

import (
	"context"
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	tokens    chan struct{}
	ticker    *time.Ticker
	maxTokens int
	rps       int
	mu        sync.Mutex
	closed    bool
}

// NewRateLimiter creates a new rate limiter with the specified RPS and burst capacity
func NewRateLimiter(rps, burst int) *RateLimiter {
	if rps <= 0 {
		rps = 10 // Default to 10 RPS
	}
	if burst <= 0 {
		burst = rps * 2 // Default burst is 2x RPS
	}

	rl := &RateLimiter{
		tokens:    make(chan struct{}, burst),
		maxTokens: burst,
		rps:       rps,
	}

	// Fill the bucket initially
	for i := 0; i < burst; i++ {
		rl.tokens <- struct{}{}
	}

	// Start the token refill ticker
	if rps > 0 {
		interval := time.Second / time.Duration(rps)
		rl.ticker = time.NewTicker(interval)
		go rl.refillTokens()
	}

	return rl
}

// Wait waits for a token to become available
func (rl *RateLimiter) Wait(ctx context.Context) error {
	select {
	case <-rl.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// TryWait attempts to get a token without blocking
func (rl *RateLimiter) TryWait() bool {
	select {
	case <-rl.tokens:
		return true
	default:
		return false
	}
}

// refillTokens adds tokens to the bucket at the specified rate
func (rl *RateLimiter) refillTokens() {
	for range rl.ticker.C {
		rl.mu.Lock()
		if rl.closed {
			rl.mu.Unlock()
			return
		}

		// Try to add a token if there's space
		select {
		case rl.tokens <- struct{}{}:
		default:
			// Bucket is full, skip this token
		}
		rl.mu.Unlock()
	}
}

// Close stops the rate limiter
func (rl *RateLimiter) Close() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if !rl.closed {
		rl.closed = true
		if rl.ticker != nil {
			rl.ticker.Stop()
		}
		close(rl.tokens)
	}
}

// Stats returns current rate limiter statistics
func (rl *RateLimiter) Stats() map[string]interface{} {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	return map[string]interface{}{
		"available_tokens": len(rl.tokens),
		"max_tokens":       rl.maxTokens,
		"rps":              rl.rps,
		"closed":           rl.closed,
	}
}
