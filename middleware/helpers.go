package middleware

import (
	"net/http"
	"strings"

	"guard"
)

// ExtractBearerToken extracts a Bearer token from the Authorization header.
// This is a standalone helper that can be used outside of middleware.
func ExtractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", ErrMissingToken
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", ErrInvalidTokenFormat
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return "", ErrMissingToken
	}

	return token, nil
}

// RequireAuthenticatedUser is a helper that requires authentication and returns the user.
// It handles the common pattern of extracting and validating user from context.
func RequireAuthenticatedUser(service guard.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if user is authenticated
			userID, ok := guard.UserIDFromContext(r.Context())
			if !ok {
				defaultUnauthorizedHandler(w, r)
				return
			}

			// Get full user details
			user, err := service.(guard.UserManager).GetUser(r.Context(), userID)
			if err != nil {
				defaultErrorHandler(w, r, err)
				return
			}

			// Add user to context
			ctx := guard.WithUser(r.Context(), user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AdminOnly is a convenience function that requires admin role.
func (m *Middleware) AdminOnly(next http.Handler) http.Handler {
	return m.RequireRole("admin")(next)
}

// UserOrAdmin is a convenience function that requires user or admin role.
func (m *Middleware) UserOrAdmin(next http.Handler) http.Handler {
	return m.RequireAnyRole("user", "admin")(next)
}

// Chain combines multiple middleware functions into one.
func Chain(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}

// WithAuth is a shorthand for requiring authentication.
func (m *Middleware) WithAuth(handler http.Handler) http.Handler {
	return m.RequireAuth(handler)
}

// WithRole is a shorthand for requiring authentication + role.
func (m *Middleware) WithRole(role string, handler http.Handler) http.Handler {
	return Chain(
		m.RequireAuth,
		m.RequireRole(role),
	)(handler)
}

// WithPermission is a shorthand for requiring authentication + permission.
func (m *Middleware) WithPermission(resource, action string, handler http.Handler) http.Handler {
	return Chain(
		m.RequireAuth,
		m.RequirePermission(resource, action),
	)(handler)
}
