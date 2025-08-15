package adapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"guard"
	"time"

	"core/cache"
	ctxpkg "core/context"
	"core/metrics"
	"core/retry"
)

// BaseAdapter provides common functionality for provider implementations.
type BaseAdapter struct {
	name       string
	config     Config
	tokenCache cache.Cache
	userCache  cache.Cache
	permCache  cache.Cache
	metrics    *adapterMetrics
}

// NewBaseAdapter creates a new base adapter with the given configuration.
func NewBaseAdapter(name string, registry metrics.Registry, opts ...Option) (*BaseAdapter, error) {
	if name == "" {
		return nil, fmt.Errorf("provider name cannot be empty")
	}

	// Default configuration
	config := Config{
		TokenCacheTTL:         5 * time.Minute,
		UserCacheTTL:          time.Minute,
		PermissionCacheTTL:    30 * time.Second,
		EnableTokenCache:      true,
		EnableUserCache:       true,
		EnablePermissionCache: true,
		MaxRetries:            3,
		RetryBaseDelay:        100 * time.Millisecond,
		RetryMaxDelay:         2 * time.Second,
		RetryJitter:           true,
		EnableMetrics:         true,
		MetricLabels:          metrics.Labels{"provider": name},
		TokenCacheKeyFunc: func(token string) string {
			sum := sha256.Sum256([]byte(token))
			return hex.EncodeToString(sum[:])
		},
	}

	// Apply options
	for _, opt := range opts {
		opt(&config)
	}

	// Create caches (toggle-aware)
	var tokenCache, userCache, permCache cache.Cache
	if config.EnableTokenCache {
		tokenCache = cache.NewMemory(
			cache.WithDefaultTTL(config.TokenCacheTTL),
			cache.WithSlidingTTL(),
			cache.WithStats(),
		)
	}
	if config.EnableUserCache {
		userCache = cache.NewMemory(
			cache.WithDefaultTTL(config.UserCacheTTL),
			cache.WithStats(),
		)
	}
	if config.EnablePermissionCache {
		permCache = cache.NewMemory(
			cache.WithDefaultTTL(config.PermissionCacheTTL),
			cache.WithStats(),
		)
	}

	// Create metrics if enabled
	var m *adapterMetrics
	if config.EnableMetrics && registry != nil {
		var err error
		m, err = newAdapterMetrics(registry, config.MetricLabels)
		if err != nil {
			return nil, fmt.Errorf("failed to create metrics: %w", err)
		}
	}

	return &BaseAdapter{
		name:       name,
		config:     config,
		tokenCache: tokenCache,
		userCache:  userCache,
		permCache:  permCache,
		metrics:    m,
	}, nil
}

// Name returns the provider's name.
func (a *BaseAdapter) Name() string {
	return a.name
}

// Close releases resources.
func (a *BaseAdapter) Close() error {
	if a.tokenCache != nil {
		a.tokenCache.Close()
	}
	if a.userCache != nil {
		a.userCache.Close()
	}
	if a.permCache != nil {
		a.permCache.Close()
	}
	return nil
}

// withRetry wraps an operation with retry logic.
func (a *BaseAdapter) withRetry(ctx context.Context, operation string, fn retry.ResultFunc[any]) (any, error) {
	// Compute effective ctx with operation timeout if set
	if a.config.OperationTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.config.OperationTimeout)
		defer cancel()
	}

	// Create retry options
	opts := []retry.Option{
		retry.WithMaxAttempts(a.config.MaxRetries),
		retry.WithPolicy(retry.Exponential(a.config.RetryBaseDelay, 2.0)),
		retry.WithMaxDelay(a.config.RetryMaxDelay),
	}

	// Add jitter if enabled
	if a.config.RetryJitter {
		opts = append(opts, retry.WithJitter(retry.FullJitter(nil)))
	}

	// Add retry predicate if specific errors are configured
	if len(a.config.RetryableErrors) > 0 {
		opts = append(opts, retry.WithRetryIf(func(err error) bool {
			for _, retryErr := range a.config.RetryableErrors {
				if errors.Is(err, retryErr) {
					return true
				}
			}
			return false
		}))
	}

	// Add metrics for retries if enabled
	if a.metrics != nil {
		opts = append(opts, retry.WithOnRetry(func(ctx context.Context, attempt int, err error, nextDelay time.Duration) {
			a.metrics.recordRetry(ctx, operation, attempt)
		}))
	}

	result, err := retry.DoWithResult(ctx, fn, opts...)

	// Handle error if configured
	if err != nil {
		if a.metrics != nil {
			a.metrics.recordError(ctx, operation, classifyError(err))
		}
		if a.config.OnError != nil {
			a.config.OnError(ctx, operation, err)
		}
	}

	return result, err
}

// enrichContext adds provider information to the request context.
func (a *BaseAdapter) enrichContext(ctx context.Context) context.Context {
	return ctxpkg.WithLabel(ctx, "auth_provider", a.name)
}

// withMetrics wraps an operation with metrics recording.
func (a *BaseAdapter) withMetrics(ctx context.Context, operation string, fn func() (any, error)) (any, error) {
	if a.metrics == nil {
		return fn()
	}

	start := time.Now()
	result, err := fn()
	duration := time.Since(start).Seconds()

	a.metrics.recordRequest(ctx, operation, duration)
	if err != nil {
		a.metrics.recordError(ctx, operation, classifyError(err))
	}

	return result, err
}

// withCache wraps an operation with caching.
func (a *BaseAdapter) withCache(ctx context.Context, c cache.Cache, key string, ttl time.Duration, fn func() (any, error)) (any, error) {
	// If cache disabled or nil, bypass
	if c == nil {
		return fn()
	}

	// Try cache first
	if value, ok := c.Get(key); ok {
		if a.metrics != nil {
			a.metrics.recordCacheHit(ctx, key)
		}
		return value, nil
	}

	if a.metrics != nil {
		a.metrics.recordCacheMiss(ctx, key)
	}

	// Compute value
	value, err := fn()
	if err != nil {
		return nil, err
	}

	// Cache result
	c.Set(key, value, ttl)
	return value, nil
}

// classifyError normalizes errors for metrics/decision-making.
func classifyError(err error) string {
	switch {
	case errors.Is(err, ErrProviderNotAvailable):
		return "unavailable"
	case errors.Is(err, ErrProviderTimeout):
		return "timeout"
	case errors.Is(err, ErrProviderRateLimited):
		return "rate_limited"
	case errors.Is(err, ErrProviderInvalidResponse):
		return "invalid_response"
	case errors.Is(err, ErrProviderMisconfigured):
		return "misconfigured"
	default:
		return "unknown"
	}
}

// ValidateTokenWithCache wraps token validation with caching and metrics.
func (a *BaseAdapter) ValidateTokenWithCache(ctx context.Context, token string, validate func(context.Context, string) (*guard.Claims, error)) (*guard.Claims, error) {
	ctx = a.enrichContext(ctx)

	cacheKey := token
	if a.config.TokenCacheKeyFunc != nil {
		cacheKey = a.config.TokenCacheKeyFunc(token)
	}

	result, err := a.withMetrics(ctx, "validate_token", func() (any, error) {
		return a.withCache(ctx, a.tokenCache, cacheKey, a.config.TokenCacheTTL, func() (any, error) {
			return a.withRetry(ctx, "validate_token", func(ctx context.Context) (any, error) {
				return validate(ctx, token)
			})
		})
	})
	if err != nil {
		return nil, err
	}
	return result.(*guard.Claims), nil
}

// GetUserWithCache wraps user retrieval with caching and metrics.
func (a *BaseAdapter) GetUserWithCache(ctx context.Context, userID string, get func(context.Context, string) (*guard.User, error)) (*guard.User, error) {
	ctx = a.enrichContext(ctx)

	result, err := a.withMetrics(ctx, "get_user", func() (any, error) {
		return a.withCache(ctx, a.userCache, userID, a.config.UserCacheTTL, func() (any, error) {
			return a.withRetry(ctx, "get_user", func(ctx context.Context) (any, error) {
				return get(ctx, userID)
			})
		})
	})
	if err != nil {
		return nil, err
	}
	return result.(*guard.User), nil
}

// HasRoleWithCache wraps role checking with caching and metrics.
func (a *BaseAdapter) HasRoleWithCache(ctx context.Context, userID, role string, check func(context.Context, string, string) (bool, error)) (bool, error) {
	ctx = a.enrichContext(ctx)

	result, err := a.withMetrics(ctx, "has_role", func() (any, error) {
		key := fmt.Sprintf("role:%s:%s", userID, role)
		return a.withCache(ctx, a.permCache, key, a.config.PermissionCacheTTL, func() (any, error) {
			return a.withRetry(ctx, "has_role", func(ctx context.Context) (any, error) {
				return check(ctx, userID, role)
			})
		})
	})
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}

// AuthorizeWithCache wraps permission checking with caching and metrics.
func (a *BaseAdapter) AuthorizeWithCache(ctx context.Context, userID, resource, action string, check func(context.Context, string, string, string) error) error {
	ctx = a.enrichContext(ctx)

	_, err := a.withMetrics(ctx, "authorize", func() (any, error) {
		key := fmt.Sprintf("perm:%s:%s:%s", userID, resource, action)
		return a.withCache(ctx, a.permCache, key, a.config.PermissionCacheTTL, func() (any, error) {
			result, err := a.withRetry(ctx, "authorize", func(ctx context.Context) (any, error) {
				if err := check(ctx, userID, resource, action); err != nil {
					return nil, err
				}
				return true, nil
			})
			return result, err
		})
	})
	return err
}
