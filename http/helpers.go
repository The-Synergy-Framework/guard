package http

import (
	"guard"
	"net/http"
	"strings"
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
			userID, ok := guard.UserIDFromContext(r.Context())
			if !ok {
				defaultUnauthorizedHandler(w, r)
				return
			}

			user, err := service.(guard.UserManager).GetUser(r.Context(), userID)
			if err != nil {
				defaultErrorHandler(w, r, err)
				return
			}

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

// ReadOnlyAccess is a convenience function that requires read permission on a resource.
func (m *Middleware) ReadOnlyAccess(resource string) func(http.Handler) http.Handler {
	return m.RequirePermission(resource, "read")
}

// WriteAccess is a convenience function that requires write permission on a resource.
func (m *Middleware) WriteAccess(resource string) func(http.Handler) http.Handler {
	return m.RequirePermission(resource, "write")
}

// ManageAccess is a convenience function that requires manage permission on a resource.
func (m *Middleware) ManageAccess(resource string) func(http.Handler) http.Handler {
	return m.RequirePermission(resource, "manage")
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

// WithAnyPermission is a shorthand for requiring authentication + any of the specified permissions.
func (m *Middleware) WithAnyPermission(permissions []PermissionPair, handler http.Handler) http.Handler {
	return Chain(
		m.RequireAuth,
		m.RequireAnyPermission(permissions...),
	)(handler)
}

// WithAllPermissions is a shorthand for requiring authentication + all of the specified permissions.
func (m *Middleware) WithAllPermissions(permissions []PermissionPair, handler http.Handler) http.Handler {
	return Chain(
		m.RequireAuth,
		m.RequireAllPermissions(permissions...),
	)(handler)
}

// WithOptionalPermissionCheck is a shorthand for optional permission checking.
func (m *Middleware) WithOptionalPermissionCheck(resource, action string, handler http.Handler) http.Handler {
	return Chain(
		m.OptionalAuth,
		m.OptionalPermissionCheck(resource, action),
	)(handler)
}

// PermissionCheckMiddleware creates a middleware that checks if user has permission and enriches context.
// This is useful for APIs that need to know permission status without blocking access.
func (m *Middleware) PermissionCheckMiddleware(resource, action string) func(http.Handler) http.Handler {
	return m.RequirePermissionWithContext(resource, action)
}

// Perm is a convenience function to create a PermissionPair.
func Perm(resource, action string) PermissionPair {
	return PermissionPair{Resource: resource, Action: action}
}

// CommonPermissions provides common permission pairs.
var CommonPermissions = struct {
	UsersRead   PermissionPair
	UsersWrite  PermissionPair
	UsersManage PermissionPair
	FilesRead   PermissionPair
	FilesWrite  PermissionPair
	FilesDelete PermissionPair
	AdminAll    PermissionPair
}{
	UsersRead:   Perm("users", "read"),
	UsersWrite:  Perm("users", "write"),
	UsersManage: Perm("users", "manage"),
	FilesRead:   Perm("files", "read"),
	FilesWrite:  Perm("files", "write"),
	FilesDelete: Perm("files", "delete"),
	AdminAll:    Perm("*", "*"),
}

// HasPermissionInRequest checks if the current request has a specific permission granted.
// This is useful in handlers to check permission context set by middleware.
func HasPermissionInRequest(r *http.Request, resource, action string) bool {
	return guard.HasPermissionInContext(r.Context(), resource, action)
}

// GetPermissionContext extracts permission context from the request.
func GetPermissionContext(r *http.Request) (*guard.PermissionContext, bool) {
	return guard.PermissionContextFromContext(r.Context())
}

// AttachUserFromClaims attaches a synthetic user to context using claims only.
// Useful in OIDC stateless setups where no UserManager is configured.
func AttachUserFromClaims(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if claims, ok := guard.ClaimsFromContext(r.Context()); ok {
			user := &guard.User{
				ID:          claims.UserID,
				Username:    claims.Username,
				Email:       claims.Email,
				Roles:       claims.Roles,
				Permissions: claims.Permissions,
			}
			r = r.WithContext(guard.WithUser(r.Context(), user))
		}
		next.ServeHTTP(w, r)
	})
}
