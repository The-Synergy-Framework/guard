# Guard Adapter Package

The adapter package provides a standardized way to integrate external authentication providers with the Guard framework. It includes a base adapter with caching, retries, metrics, timeouts, and context enrichment.

## Features

- **Provider Interface**: Contract for external auth providers (`ValidateToken`, `GetUser`, `HasRole`, `Authorize`, etc.)
- **Base Adapter**: Reusable infrastructure
  - Token/user/permission caching (TTL + sliding options)
  - Retries (exponential + jitter), operation timeouts
  - Metrics (low-cardinality `error_class`), labels
  - Context enrichment (labels) and error hooks
- **Configurable**: Cache toggles, retry behavior, metrics, token cache key hashing
- **Built-in Providers**: `adapter/oidc` (RS256/ES256 via discovery + JWKS)

## Usage

### Compose a Service with a Provider

```go
p, _ := oidc.New(nil, oidc.Config{ IssuerURL: "...", ClientID: "...", Audience: "..." })
svc := adapter.NewService(p) // or adapter.NewService(p, adapter.WithAuthorizer(rbacAuthorizer))
```

### Implementing a Provider

```go
import (
    "guard/adapter"
    "core/metrics"
)

type Config struct { /* provider-specific */ }

type MyProvider struct {
    *adapter.BaseAdapter
    config Config
}

func New(registry metrics.Registry, cfg Config) (*MyProvider, error) {
    base, err := adapter.NewBaseAdapter("myprovider", registry,
        adapter.WithTokenCache(5*time.Minute),
        adapter.WithRetry(3, 100*time.Millisecond, 2*time.Second),
        adapter.WithMetrics(true, metrics.Labels{"provider": "myprovider"}),
    )
    if err != nil { return nil, err }
    return &MyProvider{ BaseAdapter: base, config: cfg }, nil
}

func (p *MyProvider) ValidateToken(ctx context.Context, token string) (*guard.Claims, error) {
    return p.ValidateTokenWithCache(ctx, token, p.doValidateToken)
}
```

## OIDC Provider

- Generic OIDC provider with:
  - Discovery + JWKS caching; RS256 and ES256
  - `iss`/`aud` validation; `exp`/`nbf`/`iat` with leeway
  - Issuer-aware claims caching
- Map roles/permissions from claims (configurable claim names)

## Metrics

- `auth_provider_requests_total`, `auth_provider_request_duration_seconds`
- `auth_provider_cache_hits_total`, `auth_provider_cache_misses_total`
- `auth_provider_retries_total`, `auth_provider_errors_total` (with `error_class` label)

## Error Handling

Common error types:
- `ErrProviderNotAvailable`, `ErrProviderTimeout`, `ErrProviderRateLimited`
- `ErrProviderInvalidResponse`, `ErrProviderMisconfigured`

## Tips

- Use `adapter.WithOperationTimeout` for external calls
- Hash token cache keys via `adapter.WithTokenCacheKeyFunc`
- Keep retryable errors explicit via `adapter.WithRetryableErrors`
- Provide constant metric labels (e.g., `env`, `service`) 