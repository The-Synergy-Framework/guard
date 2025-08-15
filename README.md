![](https://github.com/The-Synergy-Framework/media-assets/blob/main/guard_logo.png)

# Guard - Authentication & Authorization

Authentication and authorization framework for the Synergy Framework: JWT handling, RBAC, middleware, and secure access control patterns. Interface-first, in-memory defaults, and adapter-ready.

## Overview

- Clean, composable interfaces you can adopt incrementally
- In-memory implementation for development and testing
- Adapter-ready for production auth services (Keycloak, Auth0, Firebase)

## What's inside

- `guard`: Core interfaces (Authenticator, Authorizer, Service, UserManager, RoleManager)
- `guard/jwt`: JWT token management with HS256/RS256 support
- `guard/memory`: In-memory implementation for dev/testing
- `guard/context`: Context helpers for user/claims extraction
- Support for password, token, and API key authentication
- Role-based access control (RBAC) with permissions
- Token blacklisting and session management

## Quick examples

### Basic Authentication
```go
import (
  "guard/memory"
  "guard"
)

func main() {
  // Create in-memory auth service
  authService := memory.NewService(memory.DefaultConfig())
  
  // Create a test user
  user, _ := authService.CreateUser(ctx, "admin", "admin@example.com", "password", []string{"admin"})
  
  // Authenticate
  user, _ = authService.Authenticate(ctx, guard.PasswordCredentials{
    Username: "admin",
    Password: "password",
  })
  
  // Generate tokens
  tokens, _ := authService.GenerateTokens(ctx, user.ID)
}
```

### Token Validation + Context
```go
import (
  "guard"
  "guard/memory"
)

func protectedHandler(w http.ResponseWriter, r *http.Request) {
  // Validate token from Authorization header
  token := extractBearerToken(r)
  claims, err := authService.ValidateToken(r.Context(), token)
  if err != nil {
    http.Error(w, "Unauthorized", 401)
    return
  }
  
  // Add user to context
  ctx := guard.WithClaims(r.Context(), claims)
  user, _ := guard.UserFromContext(ctx)
  
  w.Write([]byte("Hello, " + user.Username))
}
```

### Authorization + RBAC
```go
import "guard"

func adminHandler(w http.ResponseWriter, r *http.Request) {
  userID, _ := guard.UserIDFromContext(r.Context())
  
  // Check permission
  err := authService.Authorize(r.Context(), userID, "users", "manage")
  if err != nil {
    http.Error(w, "Forbidden", 403)
    return
  }
  
  // Check role
  hasRole, _ := authService.HasRole(r.Context(), userID, "admin")
  if !hasRole {
    http.Error(w, "Forbidden", 403)
    return
  }
  
  w.Write([]byte("Admin access granted"))
}
```

## Package docs

- Core interfaces and types
- [`jwt`](./jwt/) — JWT token management
- [`memory`](./memory/) — In-memory implementation
- Context helpers and middleware patterns

## Design principles

- Interface-first (clean abstractions for any auth backend)
- In-memory defaults for tests/dev; adapters for production backends  
- Integrates with Synergy Core (context, cache, validation, logging)
- Easy to reason about; easy to remove

## Roadmap (adapters)

- Keycloak adapter
- Auth0 adapter  
- Firebase Auth adapter
- HTTP middleware package
- OpenID Connect support
