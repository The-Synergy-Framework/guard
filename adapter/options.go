package adapter

import (
	"context"
	"time"

	"core/metrics"
)

// WithTokenCache configures token caching.
func WithTokenCache(ttl time.Duration) Option {
	return func(c *Config) {
		c.TokenCacheTTL = ttl
		c.EnableTokenCache = true
	}
}

// WithUserCache configures user caching.
func WithUserCache(ttl time.Duration) Option {
	return func(c *Config) {
		c.UserCacheTTL = ttl
		c.EnableUserCache = true
	}
}

// WithPermissionCache configures permission caching.
func WithPermissionCache(ttl time.Duration) Option {
	return func(c *Config) {
		c.PermissionCacheTTL = ttl
		c.EnablePermissionCache = true
	}
}

// DisableTokenCache disables token caching.
func DisableTokenCache() Option {
	return func(c *Config) {
		c.EnableTokenCache = false
	}
}

// DisableUserCache disables user caching.
func DisableUserCache() Option {
	return func(c *Config) {
		c.EnableUserCache = false
	}
}

// DisablePermissionCache disables permission caching.
func DisablePermissionCache() Option {
	return func(c *Config) {
		c.EnablePermissionCache = false
	}
}

// WithRetry configures retry behavior.
func WithRetry(maxRetries int, baseDelay, maxDelay time.Duration) Option {
	return func(c *Config) {
		c.MaxRetries = maxRetries
		c.RetryBaseDelay = baseDelay
		c.RetryMaxDelay = maxDelay
	}
}

// WithRetryableErrors specifies which errors should be retried.
func WithRetryableErrors(errors ...error) Option {
	return func(c *Config) {
		c.RetryableErrors = errors
	}
}

// WithOperationTimeout sets a timeout applied to provider operations.
func WithOperationTimeout(timeout time.Duration) Option {
	return func(c *Config) {
		c.OperationTimeout = timeout
	}
}

// WithMetrics enables/disables metrics collection.
func WithMetrics(enabled bool, labels metrics.Labels) Option {
	return func(c *Config) {
		c.EnableMetrics = enabled
		c.MetricLabels = labels
	}
}

// WithErrorHandler sets a custom error handler.
func WithErrorHandler(handler func(ctx context.Context, operation string, err error)) Option {
	return func(c *Config) {
		c.OnError = handler
	}
}

// WithTokenCacheKeyFunc sets custom token key hashing for the cache.
func WithTokenCacheKeyFunc(fn func(token string) string) Option {
	return func(c *Config) {
		c.TokenCacheKeyFunc = fn
	}
}
