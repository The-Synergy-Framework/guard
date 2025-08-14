// Package grpc provides gRPC interceptors for authentication and authorization
// using Guard services.
package grpc

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"guard"
)

// Interceptor handles gRPC authentication and authorization.
type Interceptor struct {
	service guard.Service
	config  Config
}

// Config holds interceptor configuration.
type Config struct {
	// MetadataKey is the metadata key for token extraction (default: "authorization")
	MetadataKey string

	// TokenPrefix is the prefix for token extraction (default: "bearer ")
	TokenPrefix string

	// SkipMethods are full method names to skip authentication (e.g., ["/health.Health/Check"])
	SkipMethods []string

	// ErrorHandler handles authentication/authorization errors
	ErrorHandler func(ctx context.Context, err error) error
}

// DefaultConfig returns a default interceptor configuration.
func DefaultConfig() Config {
	return Config{
		MetadataKey:  "authorization",
		TokenPrefix:  "bearer ",
		SkipMethods:  []string{},
		ErrorHandler: defaultErrorHandler,
	}
}

// New creates a new gRPC interceptor with the given service and config.
func New(service guard.Service, config ...Config) *Interceptor {
	cfg := DefaultConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	return &Interceptor{
		service: service,
		config:  cfg,
	}
}

// UnaryAuthInterceptor returns a unary server interceptor for authentication.
func (i *Interceptor) UnaryAuthInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Skip authentication for configured methods
		if i.shouldSkip(info.FullMethod) {
			return handler(ctx, req)
		}

		// Extract token from metadata
		token, err := i.extractToken(ctx)
		if err != nil {
			return nil, i.config.ErrorHandler(ctx, err)
		}

		// Validate token
		claims, err := i.service.ValidateToken(ctx, token)
		if err != nil {
			return nil, i.config.ErrorHandler(ctx, err)
		}

		// Add claims to context
		ctx = guard.WithClaims(ctx, claims)

		// Continue with enriched context
		return handler(ctx, req)
	}
}

// StreamAuthInterceptor returns a stream server interceptor for authentication.
func (i *Interceptor) StreamAuthInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Skip authentication for configured methods
		if i.shouldSkip(info.FullMethod) {
			return handler(srv, ss)
		}

		ctx := ss.Context()

		// Extract token from metadata
		token, err := i.extractToken(ctx)
		if err != nil {
			return i.config.ErrorHandler(ctx, err)
		}

		// Validate token
		claims, err := i.service.ValidateToken(ctx, token)
		if err != nil {
			return i.config.ErrorHandler(ctx, err)
		}

		// Add claims to context
		ctx = guard.WithClaims(ctx, claims)

		// Create new stream with enriched context
		wrappedStream := &contextStream{ServerStream: ss, ctx: ctx}

		// Continue with enriched context
		return handler(srv, wrappedStream)
	}
}

// UnaryRoleInterceptor returns a unary interceptor that requires a specific role.
func (i *Interceptor) UnaryRoleInterceptor(role string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		userID, ok := guard.UserIDFromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "no user in context")
		}

		hasRole, err := i.service.HasRole(ctx, userID, role)
		if err != nil {
			return nil, i.config.ErrorHandler(ctx, err)
		}

		if !hasRole {
			return nil, status.Error(codes.PermissionDenied, "insufficient role")
		}

		return handler(ctx, req)
	}
}

// UnaryPermissionInterceptor returns a unary interceptor that requires a specific permission.
func (i *Interceptor) UnaryPermissionInterceptor(resource, action string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		userID, ok := guard.UserIDFromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "no user in context")
		}

		err := i.service.Authorize(ctx, userID, resource, action)
		if err != nil {
			return nil, status.Error(codes.PermissionDenied, "insufficient permissions")
		}

		return handler(ctx, req)
	}
}

// extractToken extracts the authentication token from gRPC metadata.
func (i *Interceptor) extractToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ErrMissingMetadata
	}

	// Get authorization metadata (keys are always lowercase in gRPC)
	authValues := md[i.config.MetadataKey]
	if len(authValues) == 0 {
		return "", ErrMissingToken
	}

	authValue := authValues[0]

	// Check for the correct prefix (case-insensitive)
	if !strings.HasPrefix(strings.ToLower(authValue), strings.ToLower(i.config.TokenPrefix)) {
		return "", ErrInvalidTokenFormat
	}

	// Extract the token
	token := strings.TrimPrefix(authValue, i.config.TokenPrefix)
	if token == "" {
		return "", ErrMissingToken
	}

	return token, nil
}

// shouldSkip checks if the method should skip authentication.
func (i *Interceptor) shouldSkip(fullMethod string) bool {
	for _, skipMethod := range i.config.SkipMethods {
		if fullMethod == skipMethod {
			return true
		}
	}
	return false
}

// contextStream wraps grpc.ServerStream to provide a custom context.
type contextStream struct {
	grpc.ServerStream
	ctx context.Context
}

// Context returns the custom context.
func (s *contextStream) Context() context.Context {
	return s.ctx
}

// defaultErrorHandler handles authentication/authorization errors.
func defaultErrorHandler(ctx context.Context, err error) error {
	switch {
	case err == ErrMissingMetadata, err == ErrMissingToken:
		return status.Error(codes.Unauthenticated, "missing authentication token")
	case err == ErrInvalidTokenFormat:
		return status.Error(codes.Unauthenticated, "invalid token format")
	default:
		return status.Error(codes.Unauthenticated, "authentication failed")
	}
}
