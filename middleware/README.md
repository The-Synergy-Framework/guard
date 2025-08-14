# Middleware - HTTP Authentication & Authorization

HTTP middleware for authentication and authorization using Guard services.

## Overview

The middleware package provides ready-to-use HTTP middleware that integrates with any Guard service implementation. It supports authentication, authorization, and context enrichment with flexible configuration.

## Features

- **Token Authentication** - Bearer token validation from Authorization header
- **Role-Based Authorization** - Require specific roles or any of multiple roles
- **Permission-Based Authorization** - Check fine-grained permissions
- **Optional Authentication** - Enrich context without requiring auth
- **Configurable Error Handling** - Custom error responses and handlers
- **Path Skipping** - Skip authentication for specific paths
- **Context Integration** - Automatic user/claims injection into request context

## Quick Start

```go
package main

import (
    "net/http"
    
    "guard/memory"
    "guard/middleware"
)

func main() {
    // Create auth service
    authService := memory.NewService(memory.DefaultConfig())
    
    // Create middleware
    authMiddleware := middleware.New(authService)
    
    // Setup routes
    mux := http.NewServeMux()
    
    // Public route
    mux.HandleFunc("/", homeHandler)
    
    // Protected routes
    mux.Handle("/profile", authMiddleware.RequireAuth(http.HandlerFunc(profileHandler)))
    mux.Handle("/admin", authMiddleware.WithRole("admin", http.HandlerFunc(adminHandler)))
    mux.Handle("/users", authMiddleware.WithPermission("users", "read", http.HandlerFunc(usersHandler)))
    
    http.ListenAndServe(":8080", mux)
}
```

## Middleware Types

### 1. RequireAuth
Validates token and adds claims to context:

```go
// Require authentication for all requests
protected := authMiddleware.RequireAuth(handler)

// Or use the shorthand
protected := authMiddleware.WithAuth(handler)
```

### 2. RequireRole
Requires a specific role (must be used after RequireAuth):

```go
// Require admin role
adminOnly := authMiddleware.RequireRole("admin")(handler)

// Shorthand
adminOnly := authMiddleware.WithRole("admin", handler)
```

### 3. RequirePermission
Requires a specific permission:

```go
// Require permission to read users
usersRead := authMiddleware.RequirePermission("users", "read")(handler)

// Shorthand
usersRead := authMiddleware.WithPermission("users", "read", handler)
```

### 4. RequireAnyRole
Requires any of the specified roles:

```go
// Require user OR admin role
userOrAdmin := authMiddleware.RequireAnyRole("user", "admin")(handler)

// Convenience method
userOrAdmin := authMiddleware.UserOrAdmin(handler)
```

### 5. OptionalAuth
Adds user context if token is present, but doesn't require it:

```go
// Optional authentication
optional := authMiddleware.OptionalAuth(handler)
```

## Configuration

```go
config := middleware.Config{
    TokenHeader:  "Authorization",     // Header for token extraction
    TokenPrefix:  "Bearer ",           // Token prefix
    SkipPaths:    []string{"/health"}, // Paths to skip auth
    
    // Custom error handlers
    ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
        http.Error(w, "Auth failed", 401)
    },
    UnauthorizedHandler: func(w http.ResponseWriter, r *http.Request) {
        http.Error(w, "Unauthorized", 401)
    },
    ForbiddenHandler: func(w http.ResponseWriter, r *http.Request) {
        http.Error(w, "Forbidden", 403)
    },
}

authMiddleware := middleware.New(authService, config)
```

## Chaining Middleware

```go
// Chain multiple middleware together
protected := middleware.Chain(
    authMiddleware.RequireAuth,
    authMiddleware.RequireRole("admin"),
    loggingMiddleware,
)(handler)

// Or use the shorthand methods
protected := authMiddleware.WithRole("admin", handler)
```

## Context Usage

Access user information in handlers:

```go
func profileHandler(w http.ResponseWriter, r *http.Request) {
    // Get user ID from context
    userID, ok := guard.UserIDFromContext(r.Context())
    if !ok {
        http.Error(w, "No user in context", 500)
        return
    }
    
    // Get full user (if using RequireAuthenticatedUser helper)
    user, ok := guard.UserFromContext(r.Context())
    if ok {
        fmt.Fprintf(w, "Hello, %s!", user.Username)
        return
    }
    
    // Get claims
    claims, ok := guard.ClaimsFromContext(r.Context())
    if ok {
        fmt.Fprintf(w, "User: %s, Roles: %v", claims.UserID, claims.Roles)
    }
}
```

## Error Handling

Default error responses are JSON:

```json
{
    "error": "unauthorized",
    "message": "Authentication required",
    "code": 401
}
```

Customize by providing your own handlers in the config.

## Helper Functions

### ExtractBearerToken
Standalone token extraction:

```go
token, err := middleware.ExtractBearerToken(r)
if err != nil {
    // Handle error
}
```

### RequireAuthenticatedUser
Load full user into context:

```go
// This middleware loads the full User object
userMiddleware := middleware.RequireAuthenticatedUser(authService)
protected := userMiddleware(handler)
```

## Examples

### REST API with different auth levels

```go
func setupRoutes(authService guard.Service) http.Handler {
    auth := middleware.New(authService)
    mux := http.NewServeMux()
    
    // Public
    mux.HandleFunc("/", publicHandler)
    
    // Authenticated
    mux.Handle("/profile", auth.WithAuth(http.HandlerFunc(profileHandler)))
    
    // Role-based
    mux.Handle("/admin", auth.WithRole("admin", http.HandlerFunc(adminHandler)))
    mux.Handle("/moderator", auth.RequireAnyRole("admin", "moderator")(http.HandlerFunc(modHandler)))
    
    // Permission-based
    mux.Handle("/users", auth.WithPermission("users", "read", http.HandlerFunc(usersHandler)))
    mux.Handle("/users/create", auth.WithPermission("users", "write", http.HandlerFunc(createUserHandler)))
    
    return mux
}
```

### Custom error handling

```go
config := middleware.Config{
    ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
        // Log error
        log.Printf("Auth error: %v", err)
        
        // Custom response
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(401)
        json.NewEncoder(w).Encode(map[string]string{
            "error": "Please login to continue",
        })
    },
}

auth := middleware.New(authService, config)
```

This middleware package provides everything needed for HTTP authentication and authorization in a clean, composable way! 