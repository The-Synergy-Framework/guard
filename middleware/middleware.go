// Package middleware provides HTTP middleware for authentication and authorization
// using Guard services.
package middleware

import (
	"net/http"
	"strings"

	"guard"
)

// Middleware handles HTTP authentication and authorization.
type Middleware struct {
	service guard.Service
	config  Config
}

// Config holds middleware configuration.
type Config struct {
	// TokenHeader is the header name for token extraction (default: "Authorization")
	TokenHeader string

	// TokenPrefix is the prefix for token extraction (default: "Bearer ")
	TokenPrefix string

	// SkipPaths are paths to skip authentication (e.g., ["/health", "/metrics"])
	SkipPaths []string

	// ErrorHandler handles authentication/authorization errors
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)

	// UnauthorizedHandler handles missing authentication
	UnauthorizedHandler func(w http.ResponseWriter, r *http.Request)

	// ForbiddenHandler handles authorization failures
	ForbiddenHandler func(w http.ResponseWriter, r *http.Request)
}

// DefaultConfig returns a default middleware configuration.
func DefaultConfig() Config {
	return Config{
		TokenHeader:         "Authorization",
		TokenPrefix:         "Bearer ",
		SkipPaths:           []string{},
		ErrorHandler:        defaultErrorHandler,
		UnauthorizedHandler: defaultUnauthorizedHandler,
		ForbiddenHandler:    defaultForbiddenHandler,
	}
}

// New creates a new middleware instance with the given service and config.
func New(service guard.Service, config ...Config) *Middleware {
	cfg := DefaultConfig()
	if len(config) > 0 {
		cfg = config[0]
	}

	return &Middleware{
		service: service,
		config:  cfg,
	}
}

// RequireAuth returns middleware that requires authentication.
// It validates the token and adds user/claims to the context.
func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for configured paths
		if m.shouldSkip(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Extract token from request
		token, err := m.extractToken(r)
		if err != nil {
			m.config.UnauthorizedHandler(w, r)
			return
		}

		// Validate token
		claims, err := m.service.ValidateToken(r.Context(), token)
		if err != nil {
			m.config.ErrorHandler(w, r, err)
			return
		}

		// Add claims to context
		ctx := guard.WithClaims(r.Context(), claims)

		// Continue with enriched context
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole returns middleware that requires a specific role.
// Must be used after RequireAuth.
func (m *Middleware) RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := guard.UserIDFromContext(r.Context())
			if !ok {
				m.config.UnauthorizedHandler(w, r)
				return
			}

			hasRole, err := m.service.HasRole(r.Context(), userID, role)
			if err != nil {
				m.config.ErrorHandler(w, r, err)
				return
			}

			if !hasRole {
				m.config.ForbiddenHandler(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission returns middleware that requires a specific permission.
// Must be used after RequireAuth.
func (m *Middleware) RequirePermission(resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := guard.UserIDFromContext(r.Context())
			if !ok {
				m.config.UnauthorizedHandler(w, r)
				return
			}

			err := m.service.Authorize(r.Context(), userID, resource, action)
			if err != nil {
				m.config.ForbiddenHandler(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyRole returns middleware that requires any of the specified roles.
// Must be used after RequireAuth.
func (m *Middleware) RequireAnyRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := guard.UserIDFromContext(r.Context())
			if !ok {
				m.config.UnauthorizedHandler(w, r)
				return
			}

			for _, role := range roles {
				hasRole, err := m.service.HasRole(r.Context(), userID, role)
				if err != nil {
					m.config.ErrorHandler(w, r, err)
					return
				}

				if hasRole {
					next.ServeHTTP(w, r)
					return
				}
			}

			m.config.ForbiddenHandler(w, r)
		})
	}
}

// OptionalAuth returns middleware that optionally authenticates.
// It adds user/claims to context if token is present and valid, but doesn't require it.
func (m *Middleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to extract and validate token
		token, err := m.extractToken(r)
		if err == nil {
			claims, err := m.service.ValidateToken(r.Context(), token)
			if err == nil {
				// Add claims to context if valid
				ctx := guard.WithClaims(r.Context(), claims)
				r = r.WithContext(ctx)
			}
		}

		next.ServeHTTP(w, r)
	})
}

// extractToken extracts the authentication token from the request.
func (m *Middleware) extractToken(r *http.Request) (string, error) {
	// Get the authorization header
	authHeader := r.Header.Get(m.config.TokenHeader)
	if authHeader == "" {
		return "", ErrMissingToken
	}

	// Check for the correct prefix
	if !strings.HasPrefix(authHeader, m.config.TokenPrefix) {
		return "", ErrInvalidTokenFormat
	}

	// Extract the token
	token := strings.TrimPrefix(authHeader, m.config.TokenPrefix)
	if token == "" {
		return "", ErrMissingToken
	}

	return token, nil
}

// shouldSkip checks if the path should skip authentication.
func (m *Middleware) shouldSkip(path string) bool {
	for _, skipPath := range m.config.SkipPaths {
		if path == skipPath {
			return true
		}
	}
	return false
}
