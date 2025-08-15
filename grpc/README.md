# gRPC - Authentication & Authorization Interceptors

gRPC interceptors for authentication and authorization using Guard services.

## Overview

The gRPC package provides ready-to-use interceptors that integrate with any Guard service implementation. It supports both unary and streaming RPCs with authentication, authorization, and context enrichment.

## Features

- **Token Authentication** - Bearer token validation from gRPC metadata
- **Role-Based Authorization** - Require specific roles 
- **Permission-Based Authorization** - Check fine-grained permissions
- **Unary & Stream Support** - Works with both RPC types
- **Configurable Error Handling** - Custom error responses
- **Method Skipping** - Skip authentication for specific methods
- **Context Integration** - Automatic user/claims injection into request context

## Quick Start (OIDC + RBAC)

```go
package main

import (
    "os"
    "time"

    "google.golang.org/grpc"

    "guard/adapter"
    "guard/adapter/oidc"
    guardGrpc "guard/grpc"
    "guard/rbac"
)

func main() {
    // AuthN: OIDC provider
    p, _ := oidc.New(nil, oidc.Config{
        IssuerURL: os.Getenv("OIDC_ISSUER"),
        ClientID:  os.Getenv("OIDC_CLIENT_ID"),
        Audience:  os.Getenv("OIDC_AUDIENCE"),
    }, adapter.WithOperationTimeout(5*time.Second))

    // AuthZ: RBAC (in-memory for dev)
    authz := rbac.NewAuthorizer(rbac.NewMemoryStore())

    // Compose service
    svc := adapter.NewService(p, adapter.WithAuthorizer(authz))

    // Interceptors
    server := grpc.NewServer(
        grpc.UnaryInterceptor(guardGrpc.ChainUnaryInterceptors(
            guardGrpc.AuthInterceptor(svc),
            guardGrpc.PermissionInterceptor(svc, "files", "read"),
        )),
    )

    // Register services and serve...
}
```

## Interceptor Types

### 1. Authentication Interceptors

Validate tokens and add claims to context:

```go
// Unary RPC authentication
server := grpc.NewServer(
    grpc.UnaryInterceptor(guardGrpc.AuthInterceptor(svc)),
)

// Stream RPC authentication
server := grpc.NewServer(
    grpc.StreamInterceptor(guardGrpc.StreamAuthInterceptor(svc)),
)
```

### 2. Role-Based Authorization

Require specific roles:

```go
// Require admin role
adminUnary := guardGrpc.RoleInterceptor(svc, "admin")

// Convenience methods
adminUnary = guardGrpc.AdminOnly(svc)
userOrAdminUnary := guardGrpc.UserOrAdmin(svc)
```

### 3. Permission-Based Authorization

Require specific permissions:

```go
// Require permission to read users
usersReadUnary := guardGrpc.PermissionInterceptor(svc, "users", "read")
```

## Configuration

```go
config := guardGrpc.Config{
    MetadataKey: "authorization",     // Metadata key for token
    TokenPrefix: "bearer ",           // Token prefix  
    SkipMethods: []string{             // Methods to skip auth
        "/grpc.health.v1.Health/Check",
    },
    ErrorHandler: func(ctx context.Context, err error) error {
        return status.Error(codes.Unauthenticated, "auth failed")
    },
}

// Apply config if using constructor variant that accepts it
```

## Context Usage

Access user information in gRPC handlers:

```go
func (s *server) ProtectedMethod(ctx context.Context, req *pb.Request) (*pb.Response, error) {
    userID, ok := guard.UserIDFromContext(ctx)
    if !ok { return nil, status.Error(codes.Internal, "no user in context") }
    return &pb.Response{Message: "Hello " + userID}, nil
}
```

## Error Handling

Default gRPC status codes:

- **Missing token**: `codes.Unauthenticated`
- **Invalid token**: `codes.Unauthenticated` 
- **Insufficient role**: `codes.PermissionDenied`
- **Insufficient permission**: `codes.PermissionDenied`

Customize by providing your own `ErrorHandler` in the config.

## Examples

See the main README quickstart for a combined HTTP + gRPC setup using OIDC and RBAC. 