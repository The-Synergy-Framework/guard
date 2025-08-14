package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"

	"guard"
	"guard/memory"
	"guard/middleware"
)

// Example_basicAuth demonstrates basic authentication middleware usage.
func Example_basicAuth() {
	// Create auth service
	authService := memory.NewService(memory.DefaultConfig())

	// Create a test user
	ctx := context.Background()
	user, _ := authService.CreateUser(ctx, "testuser", "test@example.com", "password", []string{"user"})

	// Generate token
	tokens, _ := authService.GenerateTokens(ctx, user.ID)

	// Create middleware
	auth := middleware.New(authService)

	// Create protected handler
	protectedHandler := auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, _ := guard.UserIDFromContext(r.Context())
		w.Write([]byte("Hello, " + userID))
	}))

	// Test with valid token
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	w := httptest.NewRecorder()

	protectedHandler.ServeHTTP(w, req)

	// Output: 200 OK with user ID
}

// Example_roleBasedAuth demonstrates role-based authorization.
func Example_roleBasedAuth() {
	// Setup
	authService := memory.NewService(memory.DefaultConfig())
	ctx := context.Background()

	// Create users with different roles
	admin, _ := authService.CreateUser(ctx, "admin", "admin@example.com", "password", []string{"admin"})
	user, _ := authService.CreateUser(ctx, "user", "user@example.com", "password", []string{"user"})

	adminTokens, _ := authService.GenerateTokens(ctx, admin.ID)
	userTokens, _ := authService.GenerateTokens(ctx, user.ID)

	// Create middleware
	auth := middleware.New(authService)

	// Admin-only handler
	adminHandler := auth.WithRole("admin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Admin access granted"))
	}))

	// Test admin access
	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
	w := httptest.NewRecorder()
	adminHandler.ServeHTTP(w, req)
	// Returns: 200 OK

	// Test user access (should fail)
	req.Header.Set("Authorization", "Bearer "+userTokens.AccessToken)
	w = httptest.NewRecorder()
	adminHandler.ServeHTTP(w, req)
	// Returns: 403 Forbidden
}

// Example_permissionBasedAuth demonstrates permission-based authorization.
func Example_permissionBasedAuth() {
	// Setup
	authService := memory.NewService(memory.DefaultConfig())
	ctx := context.Background()

	// Create user with admin role (has all permissions)
	admin, _ := authService.CreateUser(ctx, "admin", "admin@example.com", "password", []string{"admin"})
	tokens, _ := authService.GenerateTokens(ctx, admin.ID)

	// Create middleware
	auth := middleware.New(authService)

	// Permission-based handler
	usersHandler := auth.WithPermission("users", "read", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Users list"))
	}))

	// Test with permission
	req := httptest.NewRequest("GET", "/users", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	w := httptest.NewRecorder()

	usersHandler.ServeHTTP(w, req)
	// Returns: 200 OK (admin has * permission)
}

// Example_optionalAuth demonstrates optional authentication.
func Example_optionalAuth() {
	// Setup
	authService := memory.NewService(memory.DefaultConfig())
	ctx := context.Background()

	user, _ := authService.CreateUser(ctx, "user", "user@example.com", "password", []string{"user"})
	tokens, _ := authService.GenerateTokens(ctx, user.ID)

	// Create middleware
	auth := middleware.New(authService)

	// Optional auth handler
	optionalHandler := auth.OptionalAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if guard.IsAuthenticated(r.Context()) {
			userID, _ := guard.UserIDFromContext(r.Context())
			w.Write([]byte("Hello, " + userID))
		} else {
			w.Write([]byte("Hello, anonymous"))
		}
	}))

	// Test without token
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	optionalHandler.ServeHTTP(w, req)
	// Returns: "Hello, anonymous"

	// Test with token
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	w = httptest.NewRecorder()
	optionalHandler.ServeHTTP(w, req)
	// Returns: "Hello, user_id"
}

// Example_customConfig demonstrates custom middleware configuration.
func Example_customConfig() {
	authService := memory.NewService(memory.DefaultConfig())

	// Custom configuration
	config := middleware.Config{
		TokenHeader: "X-API-Token",
		TokenPrefix: "Token ",
		SkipPaths:   []string{"/health", "/metrics"},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(401)
			w.Write([]byte("Custom auth error"))
		},
	}

	auth := middleware.New(authService, config)

	// Handler that uses custom config
	handler := auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Protected"))
	}))

	// Test with custom header
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("X-API-Token", "Token invalid_token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	// Returns: 401 with "Custom auth error"
}

// Example_middlewareChaining demonstrates chaining multiple middleware.
func Example_middlewareChaining() {
	authService := memory.NewService(memory.DefaultConfig())
	auth := middleware.New(authService)

	// Custom logging middleware
	loggingMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Log request
			next.ServeHTTP(w, r)
		})
	}

	// Chain middleware
	handler := middleware.Chain(
		loggingMiddleware,
		auth.RequireAuth,
		auth.RequireRole("admin"),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Admin endpoint"))
	}))

	// Now handler has logging + auth + admin role requirement
	_ = handler
}

// Example_contextUsage demonstrates extracting user info from context.
func Example_contextUsage() {
	authService := memory.NewService(memory.DefaultConfig())
	ctx := context.Background()

	user, _ := authService.CreateUser(ctx, "testuser", "test@example.com", "password", []string{"user"})
	tokens, _ := authService.GenerateTokens(ctx, user.ID)

	auth := middleware.New(authService)

	handler := auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Method 1: Get user ID
		userID, ok := guard.UserIDFromContext(r.Context())
		if ok {
			w.Write([]byte("User ID: " + userID))
		}

		// Method 2: Get claims
		claims, ok := guard.ClaimsFromContext(r.Context())
		if ok {
			w.Write([]byte("Username: " + claims.Username))
		}

		// Method 3: Check if authenticated
		if guard.IsAuthenticated(r.Context()) {
			w.Write([]byte("User is authenticated"))
		}
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
}
