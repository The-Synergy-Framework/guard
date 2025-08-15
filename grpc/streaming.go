package grpc

import (
	"context"
	"core/chrono"
	"guard"
	"log"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// StreamingAuthConfig configures streaming authentication behavior.
type StreamingAuthConfig struct {
	// ReauthInterval is how often to re-check authentication (default: 5 minutes)
	ReauthInterval time.Duration

	// PermissionCheckInterval is how often to re-check permissions (default: 1 minute)
	PermissionCheckInterval time.Duration

	// TokenRefreshInterval is how often to attempt token refresh (default: 10 minutes)
	TokenRefreshInterval time.Duration

	// EnableTokenRefresh enables automatic token refresh for long-running streams
	EnableTokenRefresh bool

	// OnAuthFailure is called when re-authentication fails
	OnAuthFailure func(ctx context.Context, err error)

	// OnTokenRefresh is called when a token is successfully refreshed
	OnTokenRefresh func(ctx context.Context, oldToken, newToken string)

	// OnPermissionFailure is called when permission check fails
	OnPermissionFailure func(ctx context.Context, userID, resource, action string, err error)
}

// DefaultStreamingAuthConfig returns default streaming auth configuration.
func DefaultStreamingAuthConfig() StreamingAuthConfig {
	return StreamingAuthConfig{
		ReauthInterval:          chrono.FiveMinutes,
		PermissionCheckInterval: chrono.Minute,
		TokenRefreshInterval:    10 * chrono.Minute,
		EnableTokenRefresh:      false,
		OnAuthFailure: func(ctx context.Context, err error) {
			log.Printf("Stream authentication failed: %v", err)
		},
		OnTokenRefresh: func(ctx context.Context, oldToken, newToken string) {
			log.Println("Stream token refreshed successfully")
		},
		OnPermissionFailure: func(ctx context.Context, userID, resource, action string, err error) {
			log.Printf("Stream permission check failed for user %s on %s:%s - %v", userID, resource, action, err)
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

			userID, ok := guard.UserIDFromContext(ctx)
			if !ok {
				return status.Error(codes.Unauthenticated, "no user in context")
			}

			streamCtx, cancel := context.WithCancel(ctx)
			defer cancel()

			// Create a stream monitor for this stream
			monitor := &streamMonitor{
				interceptor: i,
				userID:      userID,
				resource:    resource,
				action:      action,
				config:      config,
				cancel:      cancel,
				stream:      stream,
			}

			go monitor.start(streamCtx)

			wrappedStream := &authCheckingStream{
				ServerStream: stream,
				ctx:          streamCtx,
				monitor:      monitor,
			}

			return handler(srv, wrappedStream)
		}
	}
}

// streamMonitor manages authentication and authorization for a single stream.
type streamMonitor struct {
	interceptor *Interceptor
	userID      string
	resource    string
	action      string
	config      StreamingAuthConfig
	cancel      context.CancelFunc
	stream      grpc.ServerStream
	mu          sync.RWMutex
	lastToken   string
}

// start begins the periodic monitoring of the stream.
func (m *streamMonitor) start(ctx context.Context) {
	authTicker := time.NewTicker(m.config.ReauthInterval)
	permTicker := time.NewTicker(m.config.PermissionCheckInterval)
	defer authTicker.Stop()
	defer permTicker.Stop()

	var refreshTicker *time.Ticker
	if m.config.EnableTokenRefresh {
		refreshTicker = time.NewTicker(m.config.TokenRefreshInterval)
		defer refreshTicker.Stop()
	}

	for {
		if m.config.EnableTokenRefresh && refreshTicker != nil {
			select {
			case <-ctx.Done():
				return

			case <-authTicker.C:
				if !m.checkUserExists(ctx) {
					return
				}

			case <-permTicker.C:
				if !m.checkPermissions(ctx) {
					return
				}

			case <-refreshTicker.C:
				m.attemptTokenRefresh(ctx)
			}
		} else {
			select {
			case <-ctx.Done():
				return

			case <-authTicker.C:
				if !m.checkUserExists(ctx) {
					return
				}

			case <-permTicker.C:
				if !m.checkPermissions(ctx) {
					return
				}
			}
		}
	}
}

// checkUserExists verifies the user still exists and is active.
func (m *streamMonitor) checkUserExists(ctx context.Context) bool {
	_, err := m.interceptor.service.(guard.UserManager).GetUser(ctx, m.userID)
	if err != nil {
		m.config.OnAuthFailure(ctx, err)
		m.cancel()
		return false
	}
	return true
}

// checkPermissions verifies the user still has required permissions.
func (m *streamMonitor) checkPermissions(ctx context.Context) bool {
	err := m.interceptor.service.Authorize(ctx, m.userID, m.resource, m.action)
	if err != nil {
		m.config.OnPermissionFailure(ctx, m.userID, m.resource, m.action, err)
		m.cancel()
		return false
	}
	return true
}

// attemptTokenRefresh tries to refresh the token for long-running streams.
func (m *streamMonitor) attemptTokenRefresh(ctx context.Context) {
	// Extract current token from the stream context
	currentToken, err := m.interceptor.extractToken(ctx)
	if err != nil {
		return // Can't refresh if we can't get current token
	}

	m.mu.RLock()
	if currentToken == m.lastToken {
		m.mu.RUnlock()
		return // Token hasn't changed, no need to refresh
	}
	m.mu.RUnlock()

	// Validate current token to get claims
	claims, err := m.interceptor.service.ValidateToken(ctx, currentToken)
	if err != nil {
		return // Token is invalid, can't refresh
	}

	// Check if token is close to expiry (within refresh interval)
	if claims.ExpiresAt.After(time.Now().Add(m.config.TokenRefreshInterval)) {
		return // Token is still valid for a while
	}

	// Attempt to generate new tokens
	newTokens, err := m.interceptor.service.GenerateTokens(ctx, m.userID)
	if err != nil {
		m.config.OnAuthFailure(ctx, err)
		return
	}

	m.mu.Lock()
	m.lastToken = newTokens.AccessToken
	m.mu.Unlock()

	m.config.OnTokenRefresh(ctx, currentToken, newTokens.AccessToken)
}

// periodicAuthCheck runs in background to periodically verify user permissions.
// This is kept for backward compatibility with the simpler API.
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
			_, err := i.service.(guard.UserManager).GetUser(ctx, userID)
			if err != nil {
				config.OnAuthFailure(ctx, err)
				cancel()
				return
			}

		case <-permTicker.C:
			err := i.service.Authorize(ctx, userID, resource, action)
			if err != nil {
				config.OnAuthFailure(ctx, err)
				cancel()
				return
			}
		}
	}
}

// authCheckingStream wraps a ServerStream with a custom context and monitoring.
type authCheckingStream struct {
	grpc.ServerStream
	ctx     context.Context
	monitor *streamMonitor
}

func (s *authCheckingStream) Context() context.Context {
	return s.ctx
}

// GetCurrentToken returns the current token from the monitor (if available).
func (s *authCheckingStream) GetCurrentToken() string {
	if s.monitor == nil {
		return ""
	}
	s.monitor.mu.RLock()
	defer s.monitor.mu.RUnlock()
	return s.monitor.lastToken
}

// IsMonitored returns true if this stream has active monitoring.
func (s *authCheckingStream) IsMonitored() bool {
	return s.monitor != nil
}
