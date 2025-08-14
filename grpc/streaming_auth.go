package grpc

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"guard"
)

// StreamingAuthConfig configures streaming authentication behavior.
type StreamingAuthConfig struct {
	// ReauthInterval is how often to re-check authentication (default: 5 minutes)
	ReauthInterval time.Duration

	// PermissionCheckInterval is how often to re-check permissions (default: 1 minute)
	PermissionCheckInterval time.Duration

	// OnAuthFailure is called when re-authentication fails
	OnAuthFailure func(ctx context.Context, err error)
}

// DefaultStreamingAuthConfig returns default streaming auth configuration.
func DefaultStreamingAuthConfig() StreamingAuthConfig {
	return StreamingAuthConfig{
		ReauthInterval:          5 * time.Minute,
		PermissionCheckInterval: 1 * time.Minute,
		OnAuthFailure: func(ctx context.Context, err error) {
			// Default: log the failure (implement your logging)
		},
	}
}

// StreamingAuthWrapper wraps a streaming handler with periodic authentication checks.
func (i *Interceptor) StreamingAuthWrapper(
	resource, action string,
	config StreamingAuthConfig,
) func(grpc.StreamHandler) grpc.StreamHandler {

	return func(handler grpc.StreamHandler) grpc.StreamHandler {
		return func(srv interface{}, stream grpc.ServerStream) error {
			ctx := stream.Context()

			// Initial authentication (already done by StreamAuthInterceptor)
			userID, ok := guard.UserIDFromContext(ctx)
			if !ok {
				return status.Error(codes.Unauthenticated, "no user in context")
			}

			// Create a context that we can cancel if auth fails
			streamCtx, cancel := context.WithCancel(ctx)
			defer cancel()

			// Start periodic auth checking in background
			go i.periodicAuthCheck(streamCtx, userID, resource, action, config, cancel)

			// Wrap the stream with our cancellable context
			wrappedStream := &authCheckingStream{
				ServerStream: stream,
				ctx:          streamCtx,
			}

			// Run the actual handler
			return handler(srv, wrappedStream)
		}
	}
}

// periodicAuthCheck runs in background to periodically verify user permissions.
func (i *Interceptor) periodicAuthCheck(
	ctx context.Context,
	userID, resource, action string,
	config StreamingAuthConfig,
	cancel context.CancelFunc,
) {
	authTicker := time.NewTicker(config.ReauthInterval)
	permTicker := time.NewTicker(config.PermissionCheckInterval)
	defer authTicker.Stop()
	defer permTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-authTicker.C:
			// Re-validate the user exists and is active
			_, err := i.service.(guard.UserManager).GetUser(ctx, userID)
			if err != nil {
				config.OnAuthFailure(ctx, err)
				cancel() // This will terminate the stream
				return
			}

		case <-permTicker.C:
			// Re-check permissions
			err := i.service.Authorize(ctx, userID, resource, action)
			if err != nil {
				config.OnAuthFailure(ctx, err)
				cancel() // This will terminate the stream
				return
			}
		}
	}
}

// authCheckingStream wraps a ServerStream with a custom context.
type authCheckingStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authCheckingStream) Context() context.Context {
	return s.ctx
}

// Example usage patterns are documented in the README.
// This file provides the core streaming authentication implementation.
