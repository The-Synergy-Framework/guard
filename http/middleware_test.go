package http

import (
	"context"
	"guard"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mem "guard/memory"
)

func withAuthService(t *testing.T) *mem.Service {
	t.Helper()
	svc, err := mem.NewService(mem.DefaultConfig())
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}
	_, _ = svc.CreateUser(context.Background(), "john", "john@example.com", "pw", []string{"user"})
	_, _ = svc.CreateUser(context.Background(), "admin", "admin@example.com", "adminpw", []string{"admin"})
	return svc
}

func TestMiddleware_RequireAuth(t *testing.T) {
	svc := withAuthService(t)
	m := New(svc)

	user, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "john", Password: "pw"})
	pair, _ := svc.GenerateTokens(context.Background(), user.ID)

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := guard.ClaimsFromContext(r.Context()); !ok {
			t.Fatalf("claims not in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name   string
		header string
		want   int
	}{
		{name: "valid bearer", header: "Bearer " + pair.AccessToken, want: http.StatusOK},
		{name: "missing", header: "", want: http.StatusUnauthorized},
		{name: "bad prefix", header: "Token " + pair.AccessToken, want: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.want {
				t.Fatalf("status=%d want=%d", rr.Code, tt.want)
			}
		})
	}
}

func TestMiddleware_RequireAuth_SkipPaths(t *testing.T) {
	svc := withAuthService(t)
	config := DefaultConfig()
	config.SkipPaths = []string{"/health", "/metrics"}
	m := New(svc, config)

	handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name string
		path string
		want int
	}{
		{name: "skip health", path: "/health", want: http.StatusOK},
		{name: "skip metrics", path: "/metrics", want: http.StatusOK},
		{name: "protected path", path: "/protected", want: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, http.NoBody)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.want {
				t.Fatalf("status=%d want=%d", rr.Code, tt.want)
			}
		})
	}
}

func TestMiddleware_RequireRole(t *testing.T) {
	svc := withAuthService(t)
	m := New(svc)

	// Test with user role
	user, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "john", Password: "pw"})
	userTokens, _ := svc.GenerateTokens(context.Background(), user.ID)

	// Test with admin role
	admin, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "admin", Password: "adminpw"})
	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)

	handler := Chain(m.RequireAuth, m.RequireRole("admin"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name  string
		token string
		want  int
	}{
		{name: "admin access", token: adminTokens.AccessToken, want: http.StatusOK},
		{name: "user denied", token: userTokens.AccessToken, want: http.StatusForbidden},
		{name: "no auth context", token: "", want: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/admin", http.NoBody)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.want {
				t.Fatalf("status=%d want=%d", rr.Code, tt.want)
			}
		})
	}
}

func TestMiddleware_RequirePermission(t *testing.T) {
	svc := withAuthService(t)
	m := New(svc)

	// Test with admin (should have all permissions)
	admin, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "admin", Password: "adminpw"})
	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)

	// Test with regular user
	user, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "john", Password: "pw"})
	userTokens, _ := svc.GenerateTokens(context.Background(), user.ID)

	handler := Chain(m.RequireAuth, m.RequirePermission("users", "manage"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name  string
		token string
		want  int
	}{
		{name: "admin access", token: adminTokens.AccessToken, want: http.StatusOK},
		{name: "user denied", token: userTokens.AccessToken, want: http.StatusForbidden},
		{name: "no auth context", token: "", want: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/users/manage", http.NoBody)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.want {
				t.Fatalf("status=%d want=%d", rr.Code, tt.want)
			}
		})
	}
}

func TestMiddleware_RequireAnyPermission(t *testing.T) {
	svc := withAuthService(t)
	m := New(svc)

	admin, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "admin", Password: "adminpw"})
	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)

	user, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "john", Password: "pw"})
	userTokens, _ := svc.GenerateTokens(context.Background(), user.ID)

	permissions := []PermissionPair{
		{Resource: "users", Action: "read"},
		{Resource: "users", Action: "manage"},
	}

	handler := Chain(m.RequireAuth, m.RequireAnyPermission(permissions...))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name  string
		token string
		want  int
	}{
		{name: "admin access", token: adminTokens.AccessToken, want: http.StatusOK},
		{name: "user denied", token: userTokens.AccessToken, want: http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/users", http.NoBody)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.want {
				t.Fatalf("status=%d want=%d", rr.Code, tt.want)
			}
		})
	}
}

func TestMiddleware_RequireAllPermissions(t *testing.T) {
	svc := withAuthService(t)
	m := New(svc)

	admin, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "admin", Password: "adminpw"})
	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)

	user, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "john", Password: "pw"})
	userTokens, _ := svc.GenerateTokens(context.Background(), user.ID)

	permissions := []PermissionPair{
		{Resource: "users", Action: "read"},
		{Resource: "users", Action: "write"},
	}

	handler := Chain(m.RequireAuth, m.RequireAllPermissions(permissions...))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name  string
		token string
		want  int
	}{
		{name: "admin access", token: adminTokens.AccessToken, want: http.StatusOK},
		{name: "user denied", token: userTokens.AccessToken, want: http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/users", http.NoBody)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.want {
				t.Fatalf("status=%d want=%d", rr.Code, tt.want)
			}
		})
	}
}

func TestMiddleware_RequirePermissionOnResource(t *testing.T) {
	svc := withAuthService(t)
	m := New(svc)

	admin, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "admin", Password: "adminpw"})
	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)

	// Resource extractor that gets document ID from URL path
	resourceExtractor := func(r *http.Request) (string, error) {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) >= 3 {
			return "document:" + parts[2], nil
		}
		return "", nil
	}

	handler := Chain(
		m.RequireAuth,
		m.RequirePermissionOnResource("read", resourceExtractor),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/documents/123", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Admin should have access
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}
}

func TestMiddleware_RequirePermissionWithContext(t *testing.T) {
	svc := withAuthService(t)
	m := New(svc)

	admin, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "admin", Password: "adminpw"})
	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)

	handler := Chain(
		m.RequireAuth,
		m.RequirePermissionWithContext("files", "read"),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if permission context was added
		permCtx, ok := guard.PermissionContextFromContext(r.Context())
		if !ok {
			t.Fatal("permission context not found")
		}
		if permCtx.Resource != "files" || permCtx.Action != "read" || !permCtx.Granted {
			t.Fatal("incorrect permission context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/files", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}
}

func TestMiddleware_OptionalPermissionCheck(t *testing.T) {
	svc := withAuthService(t)
	m := New(svc)

	admin, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "admin", Password: "adminpw"})
	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)

	user, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "john", Password: "pw"})
	userTokens, _ := svc.GenerateTokens(context.Background(), user.ID)

	handler := Chain(
		m.OptionalAuth,
		m.OptionalPermissionCheck("files", "delete"),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		permCtx, ok := guard.PermissionContextFromContext(r.Context())
		if ok {
			if permCtx.Granted {
				w.Header().Set("X-Can-Delete", "true")
			} else {
				w.Header().Set("X-Can-Delete", "false")
			}
		} else {
			w.Header().Set("X-Can-Delete", "unknown")
		}
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name          string
		token         string
		wantCanDelete string
	}{
		{name: "admin can delete", token: adminTokens.AccessToken, wantCanDelete: "true"},
		{name: "user cannot delete", token: userTokens.AccessToken, wantCanDelete: "false"},
		{name: "no auth", token: "", wantCanDelete: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/files", http.NoBody)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
			}

			canDelete := rr.Header().Get("X-Can-Delete")
			if canDelete != tt.wantCanDelete {
				t.Fatalf("X-Can-Delete=%s want=%s", canDelete, tt.wantCanDelete)
			}
		})
	}
}

func TestMiddleware_RequireAnyRole(t *testing.T) {
	svc := withAuthService(t)
	m := New(svc)

	// Create moderator user
	_, _ = svc.CreateUser(context.Background(), "mod", "mod@example.com", "modpw", []string{"moderator"})

	// Get tokens for different users
	user, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "john", Password: "pw"})
	userTokens, _ := svc.GenerateTokens(context.Background(), user.ID)

	admin, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "admin", Password: "adminpw"})
	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)

	mod, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "mod", Password: "modpw"})
	modTokens, _ := svc.GenerateTokens(context.Background(), mod.ID)

	handler := Chain(m.RequireAuth, m.RequireAnyRole("admin", "moderator"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name  string
		token string
		want  int
	}{
		{name: "admin access", token: adminTokens.AccessToken, want: http.StatusOK},
		{name: "moderator access", token: modTokens.AccessToken, want: http.StatusOK},
		{name: "user denied", token: userTokens.AccessToken, want: http.StatusForbidden},
		{name: "no auth context", token: "", want: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/moderation", http.NoBody)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.want {
				t.Fatalf("status=%d want=%d", rr.Code, tt.want)
			}
		})
	}
}

func TestMiddleware_OptionalAuth(t *testing.T) {
	svc := withAuthService(t)
	m := New(svc)

	user, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "john", Password: "pw"})
	pair, _ := svc.GenerateTokens(context.Background(), user.ID)

	handler := m.OptionalAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if user is authenticated
		if guard.IsAuthenticated(r.Context()) {
			w.Header().Set("X-Authenticated", "true")
		} else {
			w.Header().Set("X-Authenticated", "false")
		}
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name           string
		header         string
		wantAuth       string
		wantStatusCode int
	}{
		{name: "with valid token", header: "Bearer " + pair.AccessToken, wantAuth: "true", wantStatusCode: http.StatusOK},
		{name: "with invalid token", header: "Bearer invalid", wantAuth: "false", wantStatusCode: http.StatusOK},
		{name: "no token", header: "", wantAuth: "false", wantStatusCode: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/optional", http.NoBody)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatusCode {
				t.Fatalf("status=%d want=%d", rr.Code, tt.wantStatusCode)
			}

			if auth := rr.Header().Get("X-Authenticated"); auth != tt.wantAuth {
				t.Fatalf("authenticated=%s want=%s", auth, tt.wantAuth)
			}
		})
	}
}

func TestMiddleware_CustomPermissionDeniedHandler(t *testing.T) {
	svc := withAuthService(t)

	permissionDeniedHandlerCalled := false
	var deniedResource, deniedAction string

	config := DefaultConfig()
	config.PermissionDeniedHandler = func(w http.ResponseWriter, r *http.Request, resource, action string) {
		permissionDeniedHandlerCalled = true
		deniedResource = resource
		deniedAction = action
		w.WriteHeader(http.StatusTeapot) // Custom status for testing
	}

	m := New(svc, config)

	user, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "john", Password: "pw"})
	userTokens, _ := svc.GenerateTokens(context.Background(), user.ID)

	handler := Chain(m.RequireAuth, m.RequirePermission("admin", "delete"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodDelete, "/admin", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+userTokens.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !permissionDeniedHandlerCalled {
		t.Fatal("custom permission denied handler not called")
	}
	if rr.Code != http.StatusTeapot {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusTeapot)
	}
	if deniedResource != "admin" || deniedAction != "delete" {
		t.Fatalf("denied resource:action=%s:%s want=admin:delete", deniedResource, deniedAction)
	}
}

func TestMiddleware_CustomErrorHandlers(t *testing.T) {
	svc := withAuthService(t)

	errorHandlerCalled := false
	unauthorizedHandlerCalled := false
	forbiddenHandlerCalled := false

	config := Config{
		TokenHeader: "Authorization",
		TokenPrefix: "Bearer ",
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			errorHandlerCalled = true
			w.WriteHeader(http.StatusTeapot) // Custom status for testing
		},
		UnauthorizedHandler: func(w http.ResponseWriter, r *http.Request) {
			unauthorizedHandlerCalled = true
			w.WriteHeader(http.StatusPaymentRequired) // Custom status for testing
		},
		ForbiddenHandler: func(w http.ResponseWriter, r *http.Request) {
			forbiddenHandlerCalled = true
			w.WriteHeader(http.StatusNotAcceptable) // Custom status for testing
		},
	}

	m := New(svc, config)

	t.Run("custom unauthorized handler", func(t *testing.T) {
		unauthorizedHandlerCalled = false
		handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if !unauthorizedHandlerCalled {
			t.Fatal("custom unauthorized handler not called")
		}
		if rr.Code != http.StatusPaymentRequired {
			t.Fatalf("status=%d want=%d", rr.Code, http.StatusPaymentRequired)
		}
	})

	t.Run("custom error handler", func(t *testing.T) {
		errorHandlerCalled = false
		handler := m.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set("Authorization", "Bearer invalid-token")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if !errorHandlerCalled {
			t.Fatal("custom error handler not called")
		}
		if rr.Code != http.StatusTeapot {
			t.Fatalf("status=%d want=%d", rr.Code, http.StatusTeapot)
		}
	})

	t.Run("custom forbidden handler", func(t *testing.T) {
		forbiddenHandlerCalled = false

		// Use admin role requirement but authenticate as regular user
		user, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "john", Password: "pw"})
		userTokens, _ := svc.GenerateTokens(context.Background(), user.ID)

		handler := Chain(m.RequireAuth, m.RequireRole("admin"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/admin", http.NoBody)
		req.Header.Set("Authorization", "Bearer "+userTokens.AccessToken)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if !forbiddenHandlerCalled {
			t.Fatal("custom forbidden handler not called")
		}
		if rr.Code != http.StatusNotAcceptable {
			t.Fatalf("status=%d want=%d", rr.Code, http.StatusNotAcceptable)
		}
	})
}

func TestMiddleware_RoleAndOptional(t *testing.T) {
	svc := withAuthService(t)
	m := New(svc)

	user, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "john", Password: "pw"})
	pair, _ := svc.GenerateTokens(context.Background(), user.ID)

	roleHandler := Chain(m.RequireAuth, m.RequireRole("user"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/role", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	rr := httptest.NewRecorder()
	roleHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("role check failed: %d", rr.Code)
	}

	optional := m.OptionalAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rr = httptest.NewRecorder()
	optional.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/opt", http.NoBody))
	if rr.Code != http.StatusOK {
		t.Fatalf("optional auth failed: %d", rr.Code)
	}
}
