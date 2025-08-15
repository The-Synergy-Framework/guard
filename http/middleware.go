package http

import (
	"guard"
	"net/http"
	"strings"
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

	// PermissionDeniedHandler handles specific permission denials
	PermissionDeniedHandler func(w http.ResponseWriter, r *http.Request, resource, action string)
}

// DefaultConfig returns a default middleware configuration.
func DefaultConfig() Config {
	return Config{
		TokenHeader:             "Authorization",
		TokenPrefix:             "Bearer ",
		SkipPaths:               []string{},
		ErrorHandler:            defaultErrorHandler,
		UnauthorizedHandler:     defaultUnauthorizedHandler,
		ForbiddenHandler:        defaultForbiddenHandler,
		PermissionDeniedHandler: defaultPermissionDeniedHandler,
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
				// Use specific permission denied handler if available
				if m.config.PermissionDeniedHandler != nil {
					m.config.PermissionDeniedHandler(w, r, resource, action)
				} else {
					m.config.ForbiddenHandler(w, r)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyPermission returns middleware that requires any of the specified permissions.
// Must be used after RequireAuth.
func (m *Middleware) RequireAnyPermission(permissions ...PermissionPair) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := guard.UserIDFromContext(r.Context())
			if !ok {
				m.config.UnauthorizedHandler(w, r)
				return
			}

			for _, perm := range permissions {
				err := m.service.Authorize(r.Context(), userID, perm.Resource, perm.Action)
				if err == nil {
					next.ServeHTTP(w, r)
					return
				}
			}

			// None of the permissions were satisfied
			m.config.ForbiddenHandler(w, r)
		})
	}
}

// RequireAllPermissions returns middleware that requires all of the specified permissions.
// Must be used after RequireAuth.
func (m *Middleware) RequireAllPermissions(permissions ...PermissionPair) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := guard.UserIDFromContext(r.Context())
			if !ok {
				m.config.UnauthorizedHandler(w, r)
				return
			}

			for _, perm := range permissions {
				err := m.service.Authorize(r.Context(), userID, perm.Resource, perm.Action)
				if err != nil {
					// Use specific permission denied handler if available
					if m.config.PermissionDeniedHandler != nil {
						m.config.PermissionDeniedHandler(w, r, perm.Resource, perm.Action)
					} else {
						m.config.ForbiddenHandler(w, r)
					}
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermissionOnResource returns middleware that checks permission on a resource extracted from the request.
// The resourceExtractor function should extract the resource ID from the request (e.g., from URL path).
// Must be used after RequireAuth.
func (m *Middleware) RequirePermissionOnResource(
	action string,
	resourceExtractor func(r *http.Request) (string, error),
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := guard.UserIDFromContext(r.Context())
			if !ok {
				m.config.UnauthorizedHandler(w, r)
				return
			}

			resource, err := resourceExtractor(r)
			if err != nil {
				m.config.ErrorHandler(w, r, err)
				return
			}

			err = m.service.Authorize(r.Context(), userID, resource, action)
			if err != nil {
				if m.config.PermissionDeniedHandler != nil {
					m.config.PermissionDeniedHandler(w, r, resource, action)
				} else {
					m.config.ForbiddenHandler(w, r)
				}
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermissionWithContext returns middleware that checks permission and adds permission context.
// Must be used after RequireAuth.
func (m *Middleware) RequirePermissionWithContext(resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := guard.UserIDFromContext(r.Context())
			if !ok {
				m.config.UnauthorizedHandler(w, r)
				return
			}

			err := m.service.Authorize(r.Context(), userID, resource, action)
			if err != nil {
				if m.config.PermissionDeniedHandler != nil {
					m.config.PermissionDeniedHandler(w, r, resource, action)
				} else {
					m.config.ForbiddenHandler(w, r)
				}
				return
			}

			// Add permission context for later use
			ctx := guard.WithPermissionContext(r.Context(), &guard.PermissionContext{
				UserID:   userID,
				Resource: resource,
				Action:   action,
				Granted:  true,
			})

			next.ServeHTTP(w, r.WithContext(ctx))
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

// OptionalPermissionCheck returns middleware that checks permissions if user is authenticated.
// Unlike RequirePermission, this doesn't fail if user is not authenticated or lacks permission.
// It adds permission context indicating whether the permission was granted.
func (m *Middleware) OptionalPermissionCheck(resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := guard.UserIDFromContext(r.Context())
			if !ok {
				// No user context, skip permission check
				next.ServeHTTP(w, r)
				return
			}

			err := m.service.Authorize(r.Context(), userID, resource, action)
			granted := err == nil

			// Add permission context regardless of result
			ctx := guard.WithPermissionContext(r.Context(), &guard.PermissionContext{
				UserID:   userID,
				Resource: resource,
				Action:   action,
				Granted:  granted,
			})

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
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

// PermissionPair represents a resource-action permission pair.
type PermissionPair struct {
	Resource string
	Action   string
}
