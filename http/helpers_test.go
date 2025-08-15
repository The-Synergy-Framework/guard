package http

import (
	"context"
	"guard"
	"net/http"
	"net/http/httptest"
	"testing"

	mem "guard/memory"
)

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		wantErr bool
	}{
		{name: "ok", header: "Bearer abc", wantErr: false},
		{name: "missing", header: "", wantErr: true},
		{name: "bad prefix", header: "Token abc", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			if tt.header != "" {
				r.Header.Set("Authorization", tt.header)
			}
			_, err := ExtractBearerToken(r)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestRequireAuthenticatedUser(t *testing.T) {
	svc, err := mem.NewService(mem.DefaultConfig())
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	// Create test user
	user, _ := svc.CreateUser(context.Background(), "john", "john@example.com", "pw", []string{"user"})
	_, _ = svc.GenerateTokens(context.Background(), user.ID)

	middleware := RequireAuthenticatedUser(svc)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if user is in context
		if contextUser, ok := guard.UserFromContext(r.Context()); !ok {
			t.Fatal("user not in context")
		} else if contextUser.ID != user.ID {
			t.Fatalf("wrong user in context: got %s, want %s", contextUser.ID, user.ID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("with authenticated user", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		// Add user ID to context (simulating RequireAuth middleware)
		ctx := guard.WithClaims(req.Context(), &guard.Claims{UserID: user.ID})
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
		}
	})

	t.Run("without user context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d want=%d", rr.Code, http.StatusUnauthorized)
		}
	})
}

func TestMiddleware_AdminOnly(t *testing.T) {
	svc, err := mem.NewService(mem.DefaultConfig())
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	// Create users
	admin, _ := svc.CreateUser(context.Background(), "admin", "admin@example.com", "adminpw", []string{"admin"})
	user, _ := svc.CreateUser(context.Background(), "user", "user@example.com", "userpw", []string{"user"})

	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)
	userTokens, _ := svc.GenerateTokens(context.Background(), user.ID)

	m := New(svc)
	handler := Chain(m.RequireAuth, m.AdminOnly)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			req := httptest.NewRequest(http.MethodGet, "/admin", http.NoBody)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.want {
				t.Fatalf("status=%d want=%d", rr.Code, tt.want)
			}
		})
	}
}

func TestMiddleware_UserOrAdmin(t *testing.T) {
	svc, err := mem.NewService(mem.DefaultConfig())
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	// Create users
	admin, _ := svc.CreateUser(context.Background(), "admin", "admin@example.com", "adminpw", []string{"admin"})
	user, _ := svc.CreateUser(context.Background(), "user", "user@example.com", "userpw", []string{"user"})
	guest, _ := svc.CreateUser(context.Background(), "guest", "guest@example.com", "guestpw", []string{"guest"})

	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)
	userTokens, _ := svc.GenerateTokens(context.Background(), user.ID)
	guestTokens, _ := svc.GenerateTokens(context.Background(), guest.ID)

	m := New(svc)
	handler := Chain(m.RequireAuth, m.UserOrAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name  string
		token string
		want  int
	}{
		{name: "admin access", token: adminTokens.AccessToken, want: http.StatusOK},
		{name: "user access", token: userTokens.AccessToken, want: http.StatusOK},
		{name: "guest denied", token: guestTokens.AccessToken, want: http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/user-or-admin", http.NoBody)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.want {
				t.Fatalf("status=%d want=%d", rr.Code, tt.want)
			}
		})
	}
}

func TestMiddleware_WithAuth(t *testing.T) {
	svc, err := mem.NewService(mem.DefaultConfig())
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	user, _ := svc.CreateUser(context.Background(), "john", "john@example.com", "pw", []string{"user"})
	pair, _ := svc.GenerateTokens(context.Background(), user.ID)

	m := New(svc)
	handler := m.WithAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := guard.ClaimsFromContext(r.Context()); !ok {
			t.Fatal("claims not in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}
}

func TestMiddleware_WithRole(t *testing.T) {
	svc, err := mem.NewService(mem.DefaultConfig())
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	admin, _ := svc.CreateUser(context.Background(), "admin", "admin@example.com", "adminpw", []string{"admin"})
	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)

	m := New(svc)
	handler := m.WithRole("admin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}
}

func TestMiddleware_WithPermission(t *testing.T) {
	svc, err := mem.NewService(mem.DefaultConfig())
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	admin, _ := svc.CreateUser(context.Background(), "admin", "admin@example.com", "adminpw", []string{"admin"})
	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)

	m := New(svc)
	handler := m.WithPermission("users", "manage", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/users/manage", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}
}

func TestChain(t *testing.T) {
	svc, err := mem.NewService(mem.DefaultConfig())
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	admin, _ := svc.CreateUser(context.Background(), "admin", "admin@example.com", "adminpw", []string{"admin"})
	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)

	m := New(svc)

	// Test middleware chaining
	handler := Chain(
		m.RequireAuth,
		m.RequireRole("admin"),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify both auth and role are applied
		if _, ok := guard.ClaimsFromContext(r.Context()); !ok {
			t.Fatal("claims not in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}
}

func TestChain_Empty(t *testing.T) {
	handler := Chain()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}
}
