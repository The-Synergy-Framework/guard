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

## Quick Start

```go
package main

import (
    "google.golang.org/grpc"
    
    "guard/memory"
    guardGrpc "guard/grpc"
)

func main() {
    // Create auth service
    authService := memory.NewService(memory.DefaultConfig())
    
    // Create gRPC interceptor
    authInterceptor := guardGrpc.New(authService)
    
    // Create gRPC server with authentication
    server := grpc.NewServer(
        grpc.UnaryInterceptor(authInterceptor.UnaryAuthInterceptor()),
        grpc.StreamInterceptor(authInterceptor.StreamAuthInterceptor()),
    )
    
    // Register your services and start server
    // pb.RegisterYourServiceServer(server, &yourService{})
    // ...
}
```

## Interceptor Types

### 1. Authentication Interceptors

Validate tokens and add claims to context:

```go
// Unary RPC authentication
server := grpc.NewServer(
    grpc.UnaryInterceptor(authInterceptor.UnaryAuthInterceptor()),
)

// Stream RPC authentication  
server := grpc.NewServer(
    grpc.StreamInterceptor(authInterceptor.StreamAuthInterceptor()),
)

// Both unary and stream
unaryAuth, streamAuth := authInterceptor.WithAuth()
server := grpc.NewServer(
    grpc.UnaryInterceptor(unaryAuth),
    grpc.StreamInterceptor(streamAuth),
)
```

### 2. Role-Based Authorization

Require specific roles:

```go
// Require admin role
adminInterceptor := authInterceptor.WithRole("admin")

// Convenience methods
adminInterceptor := authInterceptor.AdminOnly()
userOrAdminInterceptor := authInterceptor.UserOrAdmin()
```

### 3. Permission-Based Authorization

Require specific permissions:

```go
// Require permission to read users
usersReadInterceptor := authInterceptor.WithPermission("users", "read")
```

## Configuration

```go
config := guardGrpc.Config{
    MetadataKey: "authorization",     // Metadata key for token
    TokenPrefix: "bearer ",           // Token prefix  
    SkipMethods: []string{            // Methods to skip auth
        "/grpc.health.v1.Health/Check",
    },
    ErrorHandler: func(ctx context.Context, err error) error {
        // Custom error handling
        return status.Error(codes.Unauthenticated, "auth failed")
    },
}

authInterceptor := guardGrpc.New(authService, config)
```

## Client Authentication

### Option 1: Per-RPC Credentials

```go
package main

import (
    "context"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

// Implement PerRPCCredentials
type tokenAuth struct {
    token string
}

func (t tokenAuth) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
    return map[string]string{
        "authorization": "Bearer " + t.token,
    }, nil
}

func (tokenAuth) RequireTransportSecurity() bool {
    return false // Set to true for production
}

func main() {
    // Create client with automatic token injection
    conn, err := grpc.Dial("localhost:50051",
        grpc.WithInsecure(),
        grpc.WithPerRPCCredentials(tokenAuth{token: "your-jwt-token"}),
    )
    
    // All calls will include the authorization metadata
}
```

### Option 2: Manual Metadata

```go
import (
    "context"
    "google.golang.org/grpc/metadata"
)

func callWithToken(ctx context.Context, client pb.YourServiceClient, token string) {
    // Add token to metadata
    md := metadata.Pairs("authorization", "Bearer "+token)
    ctx = metadata.NewOutgoingContext(ctx, md)
    
    // Make RPC call
    response, err := client.YourMethod(ctx, &pb.YourRequest{})
    // ...
}
```

## Chaining Interceptors

```go
// Chain multiple interceptors
server := grpc.NewServer(
    grpc.UnaryInterceptor(guardGrpc.ChainUnaryInterceptors(
        loggingInterceptor,
        authInterceptor.UnaryAuthInterceptor(),
        authInterceptor.UnaryRoleInterceptor("admin"),
        metricsInterceptor,
    )),
)

// Or use convenience methods
server := grpc.NewServer(
    grpc.UnaryInterceptor(authInterceptor.WithRole("admin")),
)
```

## Context Usage

Access user information in gRPC handlers:

```go
func (s *server) ProtectedMethod(ctx context.Context, req *pb.Request) (*pb.Response, error) {
    // Get user ID from context
    userID, ok := guard.UserIDFromContext(ctx)
    if !ok {
        return nil, status.Error(codes.Internal, "no user in context")
    }
    
    // Get full user (if using RequireAuthenticatedUser)
    user, ok := guard.UserFromContext(ctx)
    if ok {
        log.Printf("Request from user: %s", user.Username)
    }
    
    // Get claims
    claims, ok := guard.ClaimsFromContext(ctx)
    if ok {
        log.Printf("User roles: %v", claims.Roles)
    }
    
    // Check if authenticated
    if guard.IsAuthenticated(ctx) {
        // User is authenticated
    }
    
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

## Helper Functions

### ExtractBearerToken
Standalone token extraction:

```go
token, err := guardGrpc.ExtractBearerToken(ctx)
if err != nil {
    // Handle error
}
```

### RequireAuthenticatedUser
Load full user into context:

```go
// This interceptor loads the full User object
userInterceptor := guardGrpc.RequireAuthenticatedUser(authService)
server := grpc.NewServer(
    grpc.UnaryInterceptor(guardGrpc.ChainUnaryInterceptors(
        authInterceptor.UnaryAuthInterceptor(),
        userInterceptor,
    )),
)
```

## Examples

### Basic gRPC Server with Auth

```go
func main() {
    authService := memory.NewService(memory.DefaultConfig())
    authInterceptor := guardGrpc.New(authService)
    
    server := grpc.NewServer(
        grpc.UnaryInterceptor(authInterceptor.UnaryAuthInterceptor()),
    )
    
    pb.RegisterYourServiceServer(server, &yourService{})
    
    lis, _ := net.Listen("tcp", ":50051")
    server.Serve(lis)
}
```

### Role-Based Service Protection

```go
func main() {
    authService := memory.NewService(memory.DefaultConfig())
    authInterceptor := guardGrpc.New(authService)
    
    server := grpc.NewServer(
        grpc.UnaryInterceptor(guardGrpc.ChainUnaryInterceptors(
            authInterceptor.UnaryAuthInterceptor(),
            // Apply different role requirements per method
            methodRoleInterceptor(authInterceptor),
        )),
    )
    
    pb.RegisterYourServiceServer(server, &yourService{})
    
    lis, _ := net.Listen("tcp", ":50051")
    server.Serve(lis)
}

func methodRoleInterceptor(auth *guardGrpc.Interceptor) grpc.UnaryServerInterceptor {
    return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
        switch info.FullMethod {
        case "/your.service.Admin/DeleteUser":
            return auth.UnaryRoleInterceptor("admin")(ctx, req, info, handler)
        case "/your.service.Admin/GetUsers":
            return auth.UnaryRoleInterceptor("user")(ctx, req, info, handler)
        default:
            return handler(ctx, req)
        }
    }
}
```

### Custom Error Handling

```go
config := guardGrpc.Config{
    ErrorHandler: func(ctx context.Context, err error) error {
        // Log the error
        log.Printf("Auth error: %v", err)
        
        // Return custom gRPC error
        switch {
        case errors.Is(err, guardGrpc.ErrMissingToken):
            return status.Error(codes.Unauthenticated, "Please provide authentication token")
        default:
            return status.Error(codes.Unauthenticated, "Authentication failed")
        }
    },
}

authInterceptor := guardGrpc.New(authService, config)
```

## Integration with HTTP Gateway

If using gRPC-Gateway for HTTP/JSON API:

```go
// The gateway automatically converts HTTP Authorization headers 
// to gRPC metadata, so the same tokens work for both!

func main() {
    // gRPC server with auth
    grpcServer := grpc.NewServer(
        grpc.UnaryInterceptor(authInterceptor.UnaryAuthInterceptor()),
    )
    
    // HTTP gateway (converts HTTP to gRPC)
    mux := runtime.NewServeMux()
    gateway.RegisterYourServiceHandlerServer(ctx, mux, &yourService{})
    
    // Both servers use the same authentication!
}
```

This gRPC package provides seamless authentication and authorization for gRPC services, with the same power and flexibility as the HTTP middleware! 