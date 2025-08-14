package guard

import (
	"context"

	ctxpkg "core/context"
)

// contextKey is an unexported type for keys defined in this package.
type contextKey string

const (
	userContextKey   contextKey = "guard.user"
	claimsContextKey contextKey = "guard.claims"
)

// WithUser adds a user to the context.
func WithUser(ctx context.Context, user *User) context.Context {
	ctx = context.WithValue(ctx, userContextKey, user)

	// Also add to Synergy's context for logging/tracing
	if user != nil {
		ctx = ctxpkg.WithUser(ctx, user.ID)
	}

	return ctx
}

// UserFromContext extracts the user from the context.
func UserFromContext(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(userContextKey).(*User)
	return user, ok && user != nil
}

// MustUserFromContext extracts the user from context or panics.
func MustUserFromContext(ctx context.Context) *User {
	user, ok := UserFromContext(ctx)
	if !ok {
		panic("no user in context")
	}
	return user
}

// WithClaims adds claims to the context.
func WithClaims(ctx context.Context, claims *Claims) context.Context {
	ctx = context.WithValue(ctx, claimsContextKey, claims)

	// Also enrich Synergy's context
	if claims != nil {
		if claims.UserID != "" {
			ctx = ctxpkg.WithUser(ctx, claims.UserID)
		}
		if claims.SessionID != "" {
			ctx = ctxpkg.WithSession(ctx, claims.SessionID)
		}
		if claims.TenantID != "" {
			ctx = ctxpkg.WithTenant(ctx, claims.TenantID)
		}
	}

	return ctx
}

// ClaimsFromContext extracts the claims from the context.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*Claims)
	return claims, ok && claims != nil
}

// MustClaimsFromContext extracts the claims from context or panics.
func MustClaimsFromContext(ctx context.Context) *Claims {
	claims, ok := ClaimsFromContext(ctx)
	if !ok {
		panic("no claims in context")
	}
	return claims
}

// UserIDFromContext extracts the user ID from context (either from Guard or Synergy context).
func UserIDFromContext(ctx context.Context) (string, bool) {
	// Try Guard context first
	if user, ok := UserFromContext(ctx); ok {
		return user.ID, true
	}

	// Try claims
	if claims, ok := ClaimsFromContext(ctx); ok && claims.UserID != "" {
		return claims.UserID, true
	}

	// Fall back to Synergy context
	return ctxpkg.UserID(ctx)
}

// IsAuthenticated checks if there's an authenticated user in the context.
func IsAuthenticated(ctx context.Context) bool {
	userID, ok := UserIDFromContext(ctx)
	return ok && userID != ""
}
