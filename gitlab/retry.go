package gitlab

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/getplumber/plumber/configuration"
	"github.com/sirupsen/logrus"
)

// RetryConfig holds the configuration for retry logic
type RetryConfig struct {
	MaxRetries     int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	BackoffFactor  float64
}

// DefaultRetryConfig returns the default retry configuration
func DefaultRetryConfig(conf *configuration.Configuration) *RetryConfig {
	if conf == nil {
		return &RetryConfig{
			MaxRetries:     3,
			InitialBackoff: 1 * time.Second,
			MaxBackoff:     30 * time.Second,
			BackoffFactor:  2.0,
		}
	}
	return &RetryConfig{
		MaxRetries:     conf.GitlabRetryMaxRetries,
		InitialBackoff: conf.GitlabRetryInitialBackoff,
		MaxBackoff:     conf.GitlabRetryMaxBackoff,
		BackoffFactor:  conf.GitlabRetryBackoffFactor,
	}
}

// retryableTransport wraps an http.RoundTripper with retry logic
type retryableTransport struct {
	base    http.RoundTripper
	config  *RetryConfig
	timeout time.Duration
	logger  *logrus.Entry
}

// RoundTrip implements the http.RoundTripper interface with retry logic
func (t *retryableTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	// Store original context and timeout info for context recreation
	originalCtx := req.Context()
	var originalTimeout time.Duration

	// Extract timeout from context if it has a deadline
	if deadline, ok := originalCtx.Deadline(); ok {
		originalTimeout = time.Until(deadline)
	}

	// Clone the request body if present to allow retries
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		req.Body.Close()
	}

	for attempt := 0; attempt <= t.config.MaxRetries; attempt++ {
		// Reset body for each attempt
		if bodyBytes != nil {
			req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		// Create fresh context for retry attempts if the previous error was a timeout
		if attempt > 0 && isContextTimeoutError(err) {
			retryTimeout := t.timeout
			if originalTimeout > 0 {
				retryTimeout = originalTimeout
			}

			ctx, cancel := context.WithTimeout(context.Background(), retryTimeout)
			defer cancel()
			req = req.WithContext(ctx)
		}

		// Make the request
		resp, err = t.base.RoundTrip(req)

		// Check if we should retry
		if !shouldRetry(resp, err) {
			return resp, err
		}

		// Don't retry after the last attempt
		if attempt == t.config.MaxRetries {
			break
		}

		// Close the response body before retrying to prevent resource leaks
		if resp != nil && resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}

		// Calculate backoff duration
		backoff := t.calculateBackoff(attempt)

		// Log retry attempt
		t.logger.WithFields(logrus.Fields{
			"attempt":    attempt + 1,
			"maxRetries": t.config.MaxRetries,
			"backoff":    backoff,
			"method":     req.Method,
			"url":        req.URL.String(),
			"statusCode": getStatusCode(resp),
			"error":      err,
		}).Warn("Retrying GitLab API request due to rate limit or error")

		// Wait before retrying
		time.Sleep(backoff)
	}

	// If we exhausted all retries and have a 429 response, create a proper error
	if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
		if resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}

		errorJSON := fmt.Sprintf(`{"errors":[{"message":"Rate limit exceeded after %d retry attempts","extensions":{"code":"RATE_LIMITED"}}]}`, t.config.MaxRetries)
		resp.Body = io.NopCloser(bytes.NewBufferString(errorJSON))
		resp.ContentLength = int64(len(errorJSON))
		resp.Header.Set("Content-Type", "application/json")
	}

	return resp, err
}

// shouldRetry determines if a request should be retried
func shouldRetry(resp *http.Response, err error) bool {
	// Retry on network errors
	if err != nil {
		return true
	}

	// Retry on rate limit (429) or server errors (5xx)
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusTooManyRequests:
			return true
		case http.StatusInternalServerError,
			http.StatusBadGateway,
			http.StatusServiceUnavailable,
			http.StatusGatewayTimeout:
			return true
		}
	}

	return false
}

// calculateBackoff calculates the backoff duration for a given attempt
func (t *retryableTransport) calculateBackoff(attempt int) time.Duration {
	// Exponential backoff with jitter
	backoff := float64(t.config.InitialBackoff) * math.Pow(t.config.BackoffFactor, float64(attempt))

	// Add jitter (±25%)
	jitter := backoff * 0.25 * (2*rand.Float64() - 1)
	backoff += jitter

	// Cap at max backoff
	if backoff > float64(t.config.MaxBackoff) {
		backoff = float64(t.config.MaxBackoff)
	}

	return time.Duration(backoff)
}

// getStatusCode safely extracts status code from response
func getStatusCode(resp *http.Response) int {
	if resp != nil {
		return resp.StatusCode
	}
	return 0
}

// isContextTimeoutError checks if an error is related to context timeout
func isContextTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "context deadline exceeded") ||
		strings.Contains(errStr, "request canceled") ||
		err == context.DeadlineExceeded ||
		err == context.Canceled
}

// WrapTransportWithRetry wraps an existing http.RoundTripper with retry logic
func WrapTransportWithRetry(transport http.RoundTripper, conf *configuration.Configuration) http.RoundTripper {
	config := DefaultRetryConfig(conf)

	timeout := 30 * time.Second
	if conf != nil && conf.HTTPClientTimeout > 0 {
		timeout = conf.HTTPClientTimeout
	}

	return &retryableTransport{
		base:    transport,
		config:  config,
		timeout: timeout,
		logger:  logger.WithField("action", "retry"),
	}
}
