// Package adapter provides interfaces and implementations for external auth providers.
package adapter

import (
	"context"
	"time"

	"core/metrics"
	"guard"
)

// Provider represents an external authentication provider.
type Provider interface {
	// Name returns the provider's unique identifier.
	Name() string

	// ValidateToken validates a token with the external provider.
	ValidateToken(ctx context.Context, token string) (*guard.Claims, error)

	// GenerateTokens generates new access and refresh tokens.
	GenerateTokens(ctx context.Context, userID string) (*guard.TokenPair, error)

	// RefreshTokens generates new tokens using a refresh token.
	RefreshTokens(ctx context.Context, refreshToken string) (*guard.TokenPair, error)

	// RevokeTokens revokes both access and refresh tokens.
	RevokeTokens(ctx context.Context, accessToken, refreshToken string) error

	// GetUser retrieves user information from the provider.
	GetUser(ctx context.Context, userID string) (*guard.User, error)

	// HasRole checks if a user has a specific role.
	HasRole(ctx context.Context, userID, role string) (bool, error)

	// Authorize checks if a user has permission for a resource/action.
	Authorize(ctx context.Context, userID, resource, action string) error

	// Close releases any resources held by the provider.
	Close() error
}

// Config holds common configuration for external providers.
type Config struct {
	// Required: Provider-specific configuration (e.g., OAuth2 settings)
	ProviderConfig any

	// Optional: Cache configuration
	TokenCacheTTL      time.Duration // Default: 5 minutes
	UserCacheTTL       time.Duration // Default: 1 minute
	PermissionCacheTTL time.Duration // Default: 30 seconds

	// Cache toggles
	EnableTokenCache      bool // Default: true
	EnableUserCache       bool // Default: true
	EnablePermissionCache bool // Default: true

	// Optional: Retry configuration
	MaxRetries      int           // Default: 3
	RetryBaseDelay  time.Duration // Default: 100ms
	RetryMaxDelay   time.Duration // Default: 2s
	RetryJitter     bool          // Default: true
	RetryableErrors []error       // Default: provider-classified retryable errors

	// Optional: Operation timeout (applied to provider calls)
	OperationTimeout time.Duration // Default: 0 (disabled)

	// Optional: Metrics configuration
	EnableMetrics bool           // Default: true
	MetricLabels  metrics.Labels // Default: {"provider": provider.Name()}

	// Optional: Error handling
	OnError func(ctx context.Context, operation string, err error) // Default: log error

	// Optional: Cache key function for token cache (e.g., SHA-256)
	TokenCacheKeyFunc func(token string) string
}

// Option configures a provider adapter.
type Option func(*Config)

// PermissionPair represents a resource-action permission pair.
type PermissionPair struct {
	Resource string
	Action   string
}
