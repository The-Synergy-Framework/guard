package http

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"guard"
	mem "guard/memory"
)

func withAuthService(t *testing.T) guard.Service {
	t.Helper()
	svc, err := mem.NewService(mem.DefaultConfig())
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}
	_, _ = svc.CreateUser(context.Background(), "john", "john@example.com", "pw", []string{"user"})
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
			req := httptest.NewRequest(http.MethodGet, "/", nil)
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

func TestMiddleware_RoleAndOptional(t *testing.T) {
	svc := withAuthService(t)
	m := New(svc)

	user, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "john", Password: "pw"})
	pair, _ := svc.GenerateTokens(context.Background(), user.ID)

	roleHandler := Chain(m.RequireAuth, m.RequireRole("user"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/role", nil)
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
	optional.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/opt", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("optional auth failed: %d", rr.Code)
	}
}
