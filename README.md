![](https://github.com/The-Synergy-Framework/media-assets/blob/main/guard_logo.png)

## Guard - Authentication & Authorization

Standards-based authentication and flexible authorization for the Synergy Framework.

- OIDC authentication (discovery + JWKS, RS256/ES256)
- HTTP middleware and gRPC interceptors (unary + streaming)
- Pluggable authorization: token-driven or RBAC (store-backed)
- Production-ready adapters: caching, retries, metrics, timeouts

### What's inside

- `guard`: Core interfaces (`Authenticator`, `Authorizer`, `Service`, `UserManager`, `RoleManager`), types, and helpers
- `guard/http`: HTTP middleware and helpers (auth, roles, permissions)
- `guard/grpc`: gRPC interceptors (auth, roles, permissions; unary + stream)
- `guard/adapter`: External provider integration (base adapter + provider interface)
  - `guard/adapter/oidc`: Generic OIDC provider (discovery + JWKS; RS256/ES256)
- `guard/rbac`: Store-backed RBAC authorizer (in-memory store provided)
- `guard/context`: Context helpers for claims/user/permission context

### Quickstart (OIDC + RBAC + HTTP)

```go
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"guard"
	"guard/adapter"
	"guard/adapter/oidc"
	httpguard "guard/http"
	"guard/rbac"
)

func main() {
	// 1) OIDC provider (Auth0/Okta/Azure/Cognito/Keycloak)
	p, err := oidc.New(nil, oidc.Config{
		IssuerURL: os.Getenv("OIDC_ISSUER"),
		ClientID:  os.Getenv("OIDC_CLIENT_ID"),
		Audience:  os.Getenv("OIDC_AUDIENCE"),
	},
		adapter.WithOperationTimeout(5*time.Second),
		adapter.WithTokenCache(5*time.Minute),
		adapter.WithUserCache(time.Minute),
		adapter.WithPermissionCache(30*time.Second),
	)
	if err != nil { log.Fatalf("oidc: %v", err) }

	// 2) RBAC authorizer (in-memory for dev; swap with DB store later)
	store := rbac.NewMemoryStore()
	authz := rbac.NewAuthorizer(store, rbac.Options{ CacheTTL: 30 * time.Second })

	// 3) Compose service (AuthN via OIDC, AuthZ via RBAC)
	svc := adapter.NewService(p, adapter.WithAuthorizer(authz))
	m := httpguard.New(svc)

	// 4) Seed RBAC (dev/demo)
	ctx := context.Background()
	tenant := ""
	_ = store.UpsertRole(ctx, tenant, "admin", "Administrator", true)
	_ = store.GrantPermissionToRole(ctx, tenant, "admin", "*", "*")
	_ = store.UpsertRole(ctx, tenant, "reader", "Read-only", true)
	_ = store.GrantPermissionToRole(ctx, tenant, "reader", "files", "read")
	_ = store.AssignRole(ctx, tenant, "user-123", "reader")

	// 5) HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	mux.Handle("/me", m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := guard.ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello " + claims.UserID))
	})))

	mux.Handle("/files/read", httpguard.Chain(
		m.RequireAuth,
		m.RequirePermission("files", "read"),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("files:read ok"))
	})))

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

### gRPC (unary) example

```go
import (
	grpcguard "guard/grpc"
	"google.golang.org/grpc"
)

// svc := adapter.NewService(provider, adapter.WithAuthorizer(authz))

srv := grpc.NewServer(
	grpc.UnaryInterceptor(
		grpcguard.ChainUnaryInterceptors(
			grpcguard.AuthInterceptor(svc),
			grpcguard.PermissionInterceptor(svc, "files", "read"),
		),
	),
)
```

### HTTP helpers

- `RequireAuth`, `RequireRole`, `RequirePermission`
- `RequireAnyPermission`, `RequireAllPermissions`, `RequirePermissionOnResource`
- `RequirePermissionWithContext` (adds `PermissionContext` to request context)
- `AttachUserFromClaims` (populate `guard.User` from claims for OIDC-only apps)

### Architecture

- AuthN: OIDC provider validates JWTs via discovery + JWKS
  - RS256 and ES256 supported; `iss`/`aud` checks; `exp`/`nbf`/`iat` with leeway
  - Issuer-aware claims cache to avoid cross-issuer bleed
- AuthZ: Pluggable
  - Token-driven (claims) via provider
  - RBAC authorizer (`guard/rbac`) with wildcard matching and tenant scoping
  - Invalidation: TTL caches by default; explicit invalidation helpers available
- Adapter Infra: `guard/adapter`
  - Caching (TTL + sliding), retries (exponential + jitter), metrics, timeouts

### When to add a UserManager

- Not required for OIDC-only apps (use claims and `AttachUserFromClaims`)
- Add a UserManager if you need app-specific profiles/CRUD or provider-admin flows

### Production checklist

- OIDC
  - Set `AllowedAlgs` if you need ES256/PS256
  - Optionally enable UserInfo enrichment (future)
- RBAC
  - Replace memory store with DB-backed store; use short TTL caches
  - Use `TenantResolver` to scope correctly in multi-tenant apps
  - Add cache invalidation on admin updates
- Observability
  - Enable adapter metrics; ensure low-cardinality labels
- Security
  - Custom HTTP error handlers; confirm consistent 401/403

### Roadmap

- DB-backed RBAC store (Postgres)
- Optional OIDC UserInfo enrichment
- Provider-specific admin managers (Okta/Keycloak) for user CRUD
- Examples: `examples/oidc-http`, `examples/oidc-grpc`, `examples/rbac`
