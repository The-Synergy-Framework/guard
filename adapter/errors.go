package adapter

import (
	"errors"
	"fmt"
)

var (
	// ErrProviderNotAvailable indicates the external provider is not accessible.
	ErrProviderNotAvailable = errors.New("auth provider not available")

	// ErrProviderTimeout indicates a request to the provider timed out.
	ErrProviderTimeout = errors.New("auth provider request timeout")

	// ErrProviderRateLimited indicates the provider's rate limit was exceeded.
	ErrProviderRateLimited = errors.New("auth provider rate limit exceeded")

	// ErrProviderInvalidResponse indicates the provider returned an invalid response.
	ErrProviderInvalidResponse = errors.New("invalid provider response")

	// ErrProviderMisconfigured indicates the provider configuration is invalid.
	ErrProviderMisconfigured = errors.New("provider misconfigured")
)

// ProviderError wraps an error from an external provider with context.
type ProviderError struct {
	Provider  string // Provider name
	Operation string // Operation being performed
	Err       error  // Underlying error
}

// Error implements the error interface.
func (e *ProviderError) Error() string {
	return fmt.Sprintf("provider %s %s failed: %v", e.Provider, e.Operation, e.Err)
}

// Unwrap returns the underlying error.
func (e *ProviderError) Unwrap() error {
	return e.Err
}

// NewProviderError creates a new ProviderError.
func NewProviderError(provider, operation string, err error) error {
	if err == nil {
		return nil
	}
	return &ProviderError{
		Provider:  provider,
		Operation: operation,
		Err:       err,
	}
}

// IsProviderError checks if an error is a ProviderError.
func IsProviderError(err error) bool {
	var pe *ProviderError
	return errors.As(err, &pe)
}

// IsProviderUnavailable checks if an error indicates the provider is unavailable.
func IsProviderUnavailable(err error) bool {
	return errors.Is(err, ErrProviderNotAvailable)
}

// IsProviderTimeout checks if an error indicates a provider timeout.
func IsProviderTimeout(err error) bool {
	return errors.Is(err, ErrProviderTimeout)
}

// IsProviderRateLimited checks if an error indicates rate limiting.
func IsProviderRateLimited(err error) bool {
	return errors.Is(err, ErrProviderRateLimited)
}

// IsProviderInvalidResponse checks if an error indicates an invalid response.
func IsProviderInvalidResponse(err error) bool {
	return errors.Is(err, ErrProviderInvalidResponse)
}

// IsProviderMisconfigured checks if an error indicates misconfiguration.
func IsProviderMisconfigured(err error) bool {
	return errors.Is(err, ErrProviderMisconfigured)
}
