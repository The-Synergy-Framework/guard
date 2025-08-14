package grpc

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"guard"
)

// ExtractBearerToken extracts a Bearer token from gRPC metadata.
// This is a standalone helper that can be used outside of interceptors.
func ExtractBearerToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ErrMissingMetadata
	}

	authValues := md["authorization"]
	if len(authValues) == 0 {
		return "", ErrMissingToken
	}

	authValue := authValues[0]
	if len(authValue) < 7 || authValue[:7] != "Bearer " {
		return "", ErrInvalidTokenFormat
	}

	token := authValue[7:]
	if token == "" {
		return "", ErrMissingToken
	}

	return token, nil
}

// ChainUnaryInterceptors chains multiple unary interceptors together.
func ChainUnaryInterceptors(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Build the chain
		chained := handler
		for i := len(interceptors) - 1; i >= 0; i-- {
			interceptor := interceptors[i]
			next := chained
			chained = func(currentCtx context.Context, currentReq interface{}) (interface{}, error) {
				return interceptor(currentCtx, currentReq, info, next)
			}
		}

		return chained(ctx, req)
	}
}

// ChainStreamInterceptors chains multiple stream interceptors together.
func ChainStreamInterceptors(interceptors ...grpc.StreamServerInterceptor) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Build the chain
		chained := handler
		for i := len(interceptors) - 1; i >= 0; i-- {
			interceptor := interceptors[i]
			next := chained
			chained = func(currentSrv interface{}, currentSs grpc.ServerStream) error {
				return interceptor(currentSrv, currentSs, info, next)
			}
		}

		return chained(srv, ss)
	}
}

// WithAuth is a convenience function for requiring authentication.
func (i *Interceptor) WithAuth() (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	return i.UnaryAuthInterceptor(), i.StreamAuthInterceptor()
}

// WithRole is a convenience function for requiring authentication + role.
func (i *Interceptor) WithRole(role string) grpc.UnaryServerInterceptor {
	return ChainUnaryInterceptors(
		i.UnaryAuthInterceptor(),
		i.UnaryRoleInterceptor(role),
	)
}

// WithPermission is a convenience function for requiring authentication + permission.
func (i *Interceptor) WithPermission(resource, action string) grpc.UnaryServerInterceptor {
	return ChainUnaryInterceptors(
		i.UnaryAuthInterceptor(),
		i.UnaryPermissionInterceptor(resource, action),
	)
}

// AdminOnly is a convenience function that requires admin role.
func (i *Interceptor) AdminOnly() grpc.UnaryServerInterceptor {
	return i.WithRole("admin")
}

// UserOrAdmin is a convenience function that requires user or admin role.
func (i *Interceptor) UserOrAdmin() grpc.UnaryServerInterceptor {
	return ChainUnaryInterceptors(
		i.UnaryAuthInterceptor(),
		func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
			userID, ok := guard.UserIDFromContext(ctx)
			if !ok {
				return nil, status.Error(codes.Unauthenticated, "no user in context")
			}

			// Check if user has either role
			hasUser, _ := i.service.HasRole(ctx, userID, "user")
			hasAdmin, _ := i.service.HasRole(ctx, userID, "admin")

			if !hasUser && !hasAdmin {
				return nil, status.Error(codes.PermissionDenied, "insufficient role")
			}

			return handler(ctx, req)
		},
	)
}

// RequireAuthenticatedUser loads the full user into context.
func RequireAuthenticatedUser(service guard.Service) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		userID, ok := guard.UserIDFromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "no user in context")
		}

		// Get full user details
		user, err := service.(guard.UserManager).GetUser(ctx, userID)
		if err != nil {
			return nil, status.Error(codes.Internal, "failed to load user")
		}

		// Add user to context
		ctx = guard.WithUser(ctx, user)
		return handler(ctx, req)
	}
}
