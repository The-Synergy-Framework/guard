# Guard Adapter Package

The adapter package provides a standardized way to integrate external authentication providers with the Guard framework. It includes a base adapter implementation with common functionality like caching, retries, and metrics, which can be used to build provider-specific adapters.

## Features

- **Provider Interface**: A common interface that all auth providers must implement
- **Base Adapter**: Reusable implementation with:
  - Token, user, and permission caching
  - Retry logic with exponential backoff and jitter
  - Prometheus-style metrics
  - Error handling and logging
  - Context enrichment
- **Configuration Options**: Flexible configuration for:
  - Cache TTLs
  - Retry behavior
  - Metrics collection
  - Error handling
- **Example Providers**: Reference implementations for common auth providers

## Usage

### Creating a New Provider

```go
import (
    "guard/adapter"
    "core/metrics"
)

// Define provider-specific configuration
type Config struct {
    // Required settings
    ServerURL    string
    ClientID     string
    ClientSecret string

    // Optional settings
    HTTPTimeout time.Duration
    MaxRetries  int
}

// Implement the Provider interface
type MyProvider struct {
    *adapter.BaseAdapter
    config Config
    client *http.Client
}

// Create a new provider instance
func New(registry metrics.Registry, config Config) (*MyProvider, error) {
    // Validate configuration
    if config.ServerURL == "" {
        return nil, fmt.Errorf("server URL is required")
    }

    // Create base adapter
    base, err := adapter.NewBaseAdapter("myprovider", registry,
        adapter.WithTokenCache(5*time.Minute),
        adapter.WithUserCache(time.Minute),
        adapter.WithPermissionCache(30*time.Second),
        adapter.WithRetry(3, 100*time.Millisecond, 2*time.Second),
        adapter.WithMetrics(true, metrics.Labels{
            "env": "production",
        }),
    )
    if err != nil {
        return nil, err
    }

    return &MyProvider{
        BaseAdapter: base,
        config:     config,
        client:     &http.Client{},
    }, nil
}

// Implement required methods using base adapter helpers
func (p *MyProvider) ValidateToken(ctx context.Context, token string) (*guard.Claims, error) {
    return p.BaseAdapter.ValidateTokenWithCache(ctx, token, p.doValidateToken)
}

func (p *MyProvider) doValidateToken(ctx context.Context, token string) (*guard.Claims, error) {
    // Provider-specific token validation logic
}
```

### Using a Provider

```go
import (
    "guard/adapter/keycloak"
    "core/metrics"
)

// Create metrics registry
registry := metrics.NewRegistry()

// Create provider instance
provider, err := keycloak.New(registry, keycloak.Config{
    ServerURL:    "https://auth.example.com",
    Realm:        "myrealm",
    ClientID:     "myclient",
    ClientSecret: "mysecret",
})
if err != nil {
    log.Fatal(err)
}
defer provider.Close()

// Use the provider
claims, err := provider.ValidateToken(ctx, "mytoken")
if err != nil {
    log.Printf("token validation failed: %v", err)
    return
}

user, err := provider.GetUser(ctx, claims.UserID)
if err != nil {
    log.Printf("user lookup failed: %v", err)
    return
}

if err := provider.Authorize(ctx, user.ID, "documents", "read"); err != nil {
    log.Printf("permission denied: %v", err)
    return
}
```

## Available Providers

- **Keycloak**: Full-featured adapter for Keycloak servers
- More providers coming soon...

## Metrics

The following metrics are collected when enabled:

- `auth_provider_requests_total`: Total number of requests to the auth provider
- `auth_provider_request_duration_seconds`: Duration of auth provider requests
- `auth_provider_cache_hits_total`: Total number of cache hits
- `auth_provider_cache_misses_total`: Total number of cache misses
- `auth_provider_retries_total`: Total number of retried operations
- `auth_provider_errors_total`: Total number of provider errors

All metrics include the following labels:
- `provider`: The provider name
- Additional labels can be configured via `WithMetrics`

## Error Handling

The package defines common error types for provider interactions:

- `ErrProviderNotAvailable`: Provider is temporarily unavailable
- `ErrProviderTimeout`: Request timed out
- `ErrProviderRateLimited`: Rate limit exceeded
- `ErrProviderInvalidResponse`: Invalid or unauthorized response
- `ErrProviderMisconfigured`: Provider configuration is invalid

Helper functions are available to check error types:
```go
if adapter.IsProviderUnavailable(err) {
    // Handle temporary unavailability
}
if adapter.IsProviderRateLimited(err) {
    // Handle rate limiting
}
```

## Contributing

To add a new provider:

1. Create a new package under `adapter/`
2. Implement the `Provider` interface
3. Use the `BaseAdapter` for common functionality
4. Add comprehensive tests
5. Document the provider in this README

## License

Same as the Guard framework. 