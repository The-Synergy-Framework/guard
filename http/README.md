# HTTP Middleware - Authentication & Authorization

Comprehensive HTTP middleware for authentication and authorization using Guard services with advanced permission checking, context enrichment, and flexible configuration.

## Overview

The HTTP middleware package provides production-ready middleware that integrates with any Guard service implementation. It supports sophisticated authentication, fine-grained authorization, permission context enrichment, and flexible error handling.

## Features

- **🔐 Token Authentication** - Bearer token validation with configurable headers
- **👥 Role-Based Authorization** - Require specific roles or any of multiple roles
- **🔑 Permission-Based Authorization** - Fine-grained permission checking with multiple strategies
- **🔄 Optional Authentication** - Enrich context without requiring authentication
- **⚙️ Configurable Error Handling** - Custom error responses and handlers
- **🛣️ Path Skipping** - Skip authentication for specific paths
- **📋 Context Integration** - Automatic user/claims/permission injection
- **🔗 Middleware Chaining** - Compose multiple middleware easily
- **🎯 Permission Context** - Rich permission metadata and context enrichment
- **🔄 Dynamic Resource Permissions** - Extract resources from requests dynamically

## Quick Start

```go
package main

import (
    "context"
    "net/http"
    "os"
    "time"

    "guard"
    "guard/adapter"
    "guard/adapter/oidc"
    httpguard "guard/http"
)

func main() {
    // OIDC provider (Auth0/Okta/Azure/Cognito/Keycloak)
    p, _ := oidc.New(nil, oidc.Config{
        IssuerURL: os.Getenv("OIDC_ISSUER"),
        ClientID:  os.Getenv("OIDC_CLIENT_ID"),
        Audience:  os.Getenv("OIDC_AUDIENCE"),
    },
        adapter.WithOperationTimeout(5*time.Second),
        adapter.WithTokenCache(5*time.Minute),
        adapter.WithUserCache(time.Minute),
        adapter.WithPermissionCache(30*time.Second),
    )

    // Compose service (AuthN via OIDC; token-driven AuthZ by default)
    svc := adapter.NewService(p)

    // Optional: If using RBAC, pass a custom authorizer via adapter.WithAuthorizer(...)
    // svc := adapter.NewService(p, adapter.WithAuthorizer(rbacAuthorizer))

    // HTTP middleware
    m := httpguard.New(svc)

    mux := http.NewServeMux()

    // Public route
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    })

    // Authenticated route (claims in context)
    mux.Handle("/profile", m.WithAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        claims, _ := guard.ClaimsFromContext(r.Context())
        _, _ = w.Write([]byte("hello " + claims.UserID))
    })))

    // Role-protected
    mux.Handle("/admin", m.WithRole("admin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    })))

    // Permission-protected
    mux.Handle("/users", m.WithPermission("users", "read", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
    })))

    http.ListenAndServe(":8080", mux)
}
```

### Attaching a User without a UserManager (OIDC-only)

If your handlers expect a `guard.User` in context but you do not have a `UserManager`, use:

```go
mux.Handle("/me-user", httpguard.Chain(
    m.RequireAuth,
    httpguard.AttachUserFromClaims, // builds guard.User from claims
)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    user, _ := guard.UserFromContext(r.Context())
    _, _ = w.Write([]byte(user.Username))
})))
```

#### What is a UserManager?

In Guard, a `UserManager` is an optional interface for application-managed user CRUD (create/update/delete users, change passwords, lookups). Many OIDC-based apps don’t need it because the identity provider (Auth0/Okta/Keycloak/etc.) owns user accounts and issues tokens. In that common case, you can:

- Rely on JWT claims for identity, roles, and permissions
- Use `AttachUserFromClaims` to materialize a lightweight `guard.User` in context for handlers that expect one
- Add a `UserManager` later only if you need app-specific user profiles or admin workflows

## Core Middleware

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

// Convenience method
adminOnly := authMiddleware.AdminOnly(handler)
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

## Advanced Permission Middleware

### 1. RequireAnyPermission
Requires any of the specified permissions:

```go
// Require any of these permissions
anyPerms := authMiddleware.RequireAnyPermission(
    http.Perm("documents", "read"),
    http.Perm("documents", "write"),
    http.Perm("admin", "*"),
)(handler)

// Shorthand
anyPerms := authMiddleware.WithAnyPermission([]http.PermissionPair{
    http.Perm("documents", "read"),
    http.Perm("documents", "write"),
}, handler)
```

### 2. RequireAllPermissions
Requires all of the specified permissions:

```go
// Require all of these permissions
allPerms := authMiddleware.RequireAllPermissions(
    http.Perm("users", "read"),
    http.Perm("users", "write"),
    http.Perm("users", "delete"),
)(handler)

// Shorthand
allPerms := authMiddleware.WithAllPermissions([]http.PermissionPair{
    http.Perm("users", "read"),
    http.Perm("users", "write"),
}, handler)
```

### 3. RequirePermissionOnResource
Dynamic resource extraction from request:

```go
// Extract document ID from URL and check permission
resourceExtractor := func(r *http.Request) (string, error) {
    parts := strings.Split(r.URL.Path, "/")
    if len(parts) >= 3 {
        return "document:" + parts[2], nil
    }
    return "", nil
}

dynamicPerm := authMiddleware.RequirePermissionOnResource("read", resourceExtractor)(handler)
```

### 4. RequirePermissionWithContext
Permission checking with context enrichment:

```go
// Check permission and add permission context
permWithContext := authMiddleware.RequirePermissionWithContext("files", "read")(handler)
```

### 5. OptionalPermissionCheck
Non-blocking permission checking:

```go
// Check permissions without blocking access
optionalCheck := authMiddleware.OptionalPermissionCheck("files", "delete")(handler)

// Shorthand
optionalCheck := authMiddleware.WithOptionalPermissionCheck("files", "delete", handler)
```

## Permission Helper Functions

### Common Permission Patterns

```go
// Read-only access
readOnly := authMiddleware.ReadOnlyAccess("documents")(handler)

// Write access
writeAccess := authMiddleware.WriteAccess("documents")(handler)

// Manage access
manageAccess := authMiddleware.ManageAccess("users")(handler)
```

### Permission Utilities

```go
// Create permission pairs
perm := http.Perm("users", "read")

// Use common permissions
handler := authMiddleware.WithAnyPermission([]http.PermissionPair{
    http.CommonPermissions.UsersRead,
    http.CommonPermissions.UsersWrite,
    http.CommonPermissions.AdminAll,
}, handler)
```

## Configuration

```go
config := http.Config{
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
    // Specific permission denial handler
    PermissionDeniedHandler: func(w http.ResponseWriter, r *http.Request, resource, action string) {
        http.Error(w, "Access denied", 403)
    },
}

authMiddleware := http.New(authService, config)
```

## Context Usage

### Basic Context Access

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

### Permission Context Access

```go
func documentsHandler(w http.ResponseWriter, r *http.Request) {
    // Check if user has specific permission
    if guard.HasPermissionInContext(r.Context(), "documents", "delete") {
        w.Header().Set("X-Can-Delete", "true")
    }
    
    // Get full permission context
    if permCtx, ok := guard.PermissionContextFromContext(r.Context()); ok {
        log.Printf("Permission check: %s:%s granted=%v", 
            permCtx.Resource, permCtx.Action, permCtx.Granted)
    }
}
```

## Chaining Middleware

```go
// Chain multiple middleware together
protected := http.Chain(
    authMiddleware.RequireAuth,
    authMiddleware.RequireRole("admin"),
    loggingMiddleware,
)(handler)

// Or use the shorthand methods
protected := authMiddleware.WithRole("admin", handler)
```

## Error Handling

### Default Error Responses

Default error responses are JSON:

```json
{
    "error": "unauthorized",
    "message": "Authentication required",
    "code": 401
}
```

### Custom Error Handling

```go
config := http.Config{
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
    PermissionDeniedHandler: func(w http.ResponseWriter, r *http.Request, resource, action string) {
        // Log permission denials with user info
        userID, _ := guard.UserIDFromContext(r.Context())
        log.Printf("Permission denied: user=%s resource=%s action=%s path=%s", 
            userID, resource, action, r.URL.Path)
        
        // Return detailed permission error
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(403)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "error": "permission_denied",
            "message": fmt.Sprintf("You don't have permission to %s %s", action, resource),
            "resource": resource,
            "action": action,
            "request_id": getRequestID(r),
        })
    },
}
```

## Helper Functions

### ExtractBearerToken
Standalone token extraction:

```go
token, err := http.ExtractBearerToken(r)
if err != nil {
    // Handle error
}
```

### RequireAuthenticatedUser
Load full user into context:

```go
// This middleware loads the full User object
userMiddleware := http.RequireAuthenticatedUser(authService)
protected := userMiddleware(handler)
```

### Permission Context Helpers

```go
// Check permissions in handlers
if http.HasPermissionInRequest(r, "documents", "delete") {
    // Show delete button
}

// Get permission context
if permCtx, ok := http.GetPermissionContext(r); ok {
    // Use permission context
}
```

## Comprehensive Examples

### REST API with Advanced Permission Levels

```go
func setupRoutes(authService guard.Service) http.Handler {
    auth := http.New(authService)
    mux := http.NewServeMux()
    
    // Public routes
    mux.HandleFunc("/", publicHandler)
    mux.HandleFunc("/health", healthHandler)
    
    // Authenticated routes
    mux.Handle("/profile", auth.WithAuth(http.HandlerFunc(profileHandler)))
    
    // Role-based routes
    mux.Handle("/admin", auth.WithRole("admin", http.HandlerFunc(adminHandler)))
    mux.Handle("/moderator", auth.RequireAnyRole("admin", "moderator")(http.HandlerFunc(modHandler)))
    
    // Permission-based routes
    mux.Handle("/users", auth.WithPermission("users", "read", http.HandlerFunc(usersHandler)))
    mux.Handle("/users/create", auth.WithPermission("users", "write", http.HandlerFunc(createUserHandler)))
    mux.Handle("/users/delete", auth.WithPermission("users", "delete", http.HandlerFunc(deleteUserHandler)))
    
    // Advanced permission routes
    mux.Handle("/documents", auth.ReadOnlyAccess("documents")(http.HandlerFunc(documentsHandler)))
    mux.Handle("/documents/create", auth.WriteAccess("documents")(http.HandlerFunc(createDocumentHandler)))
    mux.Handle("/documents/manage", auth.ManageAccess("documents")(http.HandlerFunc(manageDocumentsHandler)))
    
    // Multiple permission routes
    mux.Handle("/reports", auth.WithAnyPermission([]http.PermissionPair{
        http.Perm("reports", "read"),
        http.Perm("reports", "write"),
        http.Perm("admin", "*"),
    }, http.HandlerFunc(reportsHandler)))
    
    // Dynamic resource permission routes
    mux.Handle("/documents/", auth.RequirePermissionOnResource("read", extractDocumentID)(http.HandlerFunc(documentHandler)))
    
    return mux
}

func extractDocumentID(r *http.Request) (string, error) {
    parts := strings.Split(r.URL.Path, "/")
    if len(parts) >= 3 {
        return "document:" + parts[2], nil
    }
    return "", fmt.Errorf("invalid document path")
}
```

### Optional Permission UI

```go
func setupOptionalRoutes(authService guard.Service) http.Handler {
    auth := http.New(authService)
    mux := http.NewServeMux()
    
    // Optional authentication with permission checking
    mux.Handle("/posts", http.Chain(
        auth.OptionalAuth,
        auth.OptionalPermissionCheck("posts", "delete"),
    )(http.HandlerFunc(postsHandler)))
    
    return mux
}

func postsHandler(w http.ResponseWriter, r *http.Request) {
    // Check if user is authenticated
    if !guard.IsAuthenticated(r.Context()) {
        // Show public posts only
        renderPosts(w, getPublicPosts())
        return
    }
    
    // Check permissions for UI elements
    canDelete := http.HasPermissionInRequest(r, "posts", "delete")
    canEdit := http.HasPermissionInRequest(r, "posts", "edit")
    
    // Get permission context for detailed info
    if permCtx, ok := http.GetPermissionContext(r); ok {
        log.Printf("User %s has delete permission: %v", permCtx.UserID, permCtx.Granted)
    }
    
    // Render with appropriate UI controls
    renderPosts(w, getAllPosts(), PostOptions{
        CanDelete: canDelete,
        CanEdit:   canEdit,
    })
}
```

### Custom Error Handling with Logging

```go
func setupCustomErrorHandling(authService guard.Service) http.Handler {
    config := http.Config{
        ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
            // Log authentication errors
            log.Printf("Authentication error for %s: %v", r.URL.Path, err)
            
            // Return user-friendly error
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(401)
            json.NewEncoder(w).Encode(map[string]string{
                "error": "Please login to continue",
                "login_url": "/login",
            })
        },
        PermissionDeniedHandler: func(w http.ResponseWriter, r *http.Request, resource, action string) {
            // Log permission denials with user info
            userID, _ := guard.UserIDFromContext(r.Context())
            log.Printf("Permission denied: user=%s resource=%s action=%s path=%s", 
                userID, resource, action, r.URL.Path)
            
            // Return detailed permission error
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(403)
            json.NewEncoder(w).Encode(map[string]interface{}{
                "error": "permission_denied",
                "message": fmt.Sprintf("You don't have permission to %s %s", action, resource),
                "resource": resource,
                "action": action,
                "request_id": getRequestID(r),
            })
        },
    }
    
    auth := http.New(authService, config)
    mux := http.NewServeMux()
    
    // Routes with custom error handling
    mux.Handle("/admin", auth.WithRole("admin", http.HandlerFunc(adminHandler)))
    mux.Handle("/users", auth.WithPermission("users", "manage", http.HandlerFunc(usersHandler)))
    
    return mux
}
```

## Common Permission Patterns

### Pre-defined Common Permissions

```go
// Use common permission patterns
var commonPerms = http.CommonPermissions

// Check common permissions
handler := auth.WithAnyPermission([]http.PermissionPair{
    commonPerms.UsersRead,
    commonPerms.UsersWrite,
    commonPerms.AdminAll,
}, handler)

// Or use convenience methods
handler := auth.ReadOnlyAccess("documents")(handler)
handler := auth.WriteAccess("documents")(handler)
handler := auth.ManageAccess("users")(handler)
```

### Permission Pair Creation

```go
// Create permission pairs
perms := []http.PermissionPair{
    http.Perm("users", "read"),
    http.Perm("users", "write"),
    http.Perm("users", "delete"),
}

// Use in middleware
handler := auth.WithAllPermissions(perms, handler)
```

This middleware package provides everything needed for sophisticated HTTP authentication and authorization with advanced permission checking, context enrichment, and flexible configuration! 🚀 