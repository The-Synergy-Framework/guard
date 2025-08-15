package http

import (
	"context"
	"guard"
	"net/http"
	"net/http/httptest"
	"testing"

	mem "guard/memory"
)

func withTestService(t *testing.T) *mem.Service {
	t.Helper()
	svc, err := mem.NewService(mem.DefaultConfig())
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}
	_, _ = svc.CreateUser(context.Background(), "user", "user@example.com", "pw", []string{"user"})
	_, _ = svc.CreateUser(context.Background(), "admin", "admin@example.com", "pw", []string{"admin"})
	return svc
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantToken string
		wantErr   bool
	}{
		{name: "valid", header: "Bearer token123", wantToken: "token123", wantErr: false},
		{name: "missing", header: "", wantToken: "", wantErr: true},
		{name: "wrong prefix", header: "Basic token123", wantToken: "", wantErr: true},
		{name: "no token", header: "Bearer ", wantToken: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}

			token, err := ExtractBearerToken(req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
			if token != tt.wantToken {
				t.Fatalf("token=%s want=%s", token, tt.wantToken)
			}
		})
	}
}

func TestRequireAuthenticatedUser(t *testing.T) {
	svc := withTestService(t)
	user, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "user", Password: "pw"})

	t.Run("with user context", func(t *testing.T) {
		ctx := guard.WithClaims(context.Background(), &guard.Claims{UserID: user.ID})
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler := RequireAuthenticatedUser(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := guard.UserFromContext(r.Context()); !ok {
				t.Fatal("user not in context")
			}
			w.WriteHeader(http.StatusOK)
		}))

		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
		}
	})

	t.Run("without user context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		rr := httptest.NewRecorder()
		handler := RequireAuthenticatedUser(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d want=%d", rr.Code, http.StatusUnauthorized)
		}
	})

	t.Run("user not found", func(t *testing.T) {
		ctx := guard.WithClaims(context.Background(), &guard.Claims{UserID: "nonexistent"})
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		handler := RequireAuthenticatedUser(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d want=%d", rr.Code, http.StatusUnauthorized)
		}
	})
}

func TestMiddleware_AdminOnly(t *testing.T) {
	svc := withTestService(t)
	m := New(svc)

	admin, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "admin", Password: "pw"})
	user, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "user", Password: "pw"})

	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)
	userTokens, _ := svc.GenerateTokens(context.Background(), user.ID)

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
	svc := withTestService(t)
	m := New(svc)

	// Create guest user
	_, _ = svc.CreateUser(context.Background(), "guest", "guest@example.com", "pw", []string{"guest"})

	admin, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "admin", Password: "pw"})
	user, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "user", Password: "pw"})
	guest, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "guest", Password: "pw"})

	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)
	userTokens, _ := svc.GenerateTokens(context.Background(), user.ID)
	guestTokens, _ := svc.GenerateTokens(context.Background(), guest.ID)

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
			req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
			req.Header.Set("Authorization", "Bearer "+tt.token)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != tt.want {
				t.Fatalf("status=%d want=%d", rr.Code, tt.want)
			}
		})
	}
}

func TestMiddleware_ReadOnlyAccess(t *testing.T) {
	svc := withTestService(t)
	m := New(svc)

	admin, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "admin", Password: "pw"})
	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)

	handler := Chain(m.RequireAuth, m.ReadOnlyAccess("documents"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/documents", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}
}

func TestMiddleware_WriteAccess(t *testing.T) {
	svc := withTestService(t)
	m := New(svc)

	admin, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "admin", Password: "pw"})
	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)

	handler := Chain(m.RequireAuth, m.WriteAccess("documents"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/documents", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}
}

func TestMiddleware_ManageAccess(t *testing.T) {
	svc := withTestService(t)
	m := New(svc)

	admin, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "admin", Password: "pw"})
	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)

	handler := Chain(m.RequireAuth, m.ManageAccess("users"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodDelete, "/users", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}
}

func TestMiddleware_WithAuth(t *testing.T) {
	svc := withTestService(t)
	m := New(svc)

	user, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "user", Password: "pw"})
	userTokens, _ := svc.GenerateTokens(context.Background(), user.ID)

	handler := m.WithAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := guard.ClaimsFromContext(r.Context()); !ok {
			t.Fatal("claims not in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+userTokens.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}
}

func TestMiddleware_WithRole(t *testing.T) {
	svc := withTestService(t)
	m := New(svc)

	admin, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "admin", Password: "pw"})
	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)

	handler := m.WithRole("admin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func TestMiddleware_WithPermission(t *testing.T) {
	svc := withTestService(t)
	m := New(svc)

	admin, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "admin", Password: "pw"})
	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)

	handler := m.WithPermission("users", "read", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := guard.ClaimsFromContext(r.Context()); !ok {
			t.Fatal("claims not in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/users", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}
}

func TestMiddleware_WithAnyPermission(t *testing.T) {
	svc := withTestService(t)
	m := New(svc)

	admin, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "admin", Password: "pw"})
	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)

	permissions := []PermissionPair{
		{Resource: "users", Action: "read"},
		{Resource: "users", Action: "write"},
	}

	handler := m.WithAnyPermission(permissions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := guard.ClaimsFromContext(r.Context()); !ok {
			t.Fatal("claims not in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/users", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}
}

func TestMiddleware_WithAllPermissions(t *testing.T) {
	svc := withTestService(t)
	m := New(svc)

	admin, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "admin", Password: "pw"})
	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)

	permissions := []PermissionPair{
		{Resource: "users", Action: "read"},
		{Resource: "users", Action: "write"},
	}

	handler := m.WithAllPermissions(permissions, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := guard.ClaimsFromContext(r.Context()); !ok {
			t.Fatal("claims not in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/users", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}
}

func TestMiddleware_WithOptionalPermissionCheck(t *testing.T) {
	svc := withTestService(t)
	m := New(svc)

	admin, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "admin", Password: "pw"})
	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)

	handler := m.WithOptionalPermissionCheck("files", "delete", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if permCtx, ok := guard.PermissionContextFromContext(r.Context()); ok {
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

	req := httptest.NewRequest(http.MethodGet, "/files", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}

	canDelete := rr.Header().Get("X-Can-Delete")
	if canDelete != "true" {
		t.Fatalf("X-Can-Delete=%s want=true", canDelete)
	}
}

func TestMiddleware_PermissionCheckMiddleware(t *testing.T) {
	svc := withTestService(t)
	m := New(svc)

	admin, _ := svc.Authenticate(context.Background(), guard.PasswordCredentials{Username: "admin", Password: "pw"})
	adminTokens, _ := svc.GenerateTokens(context.Background(), admin.ID)

	handler := Chain(
		m.RequireAuth,
		m.PermissionCheckMiddleware("reports", "generate"),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		permCtx, ok := guard.PermissionContextFromContext(r.Context())
		if !ok {
			t.Fatal("permission context not found")
		}
		if !permCtx.Granted {
			t.Fatal("permission should be granted for admin")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/reports", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+adminTokens.AccessToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}
}

func TestPerm(t *testing.T) {
	perm := Perm("users", "read")
	if perm.Resource != "users" || perm.Action != "read" {
		t.Fatalf("Perm(%q, %q) = %+v, want Resource=users Action=read", "users", "read", perm)
	}
}

func TestCommonPermissions(t *testing.T) {
	if CommonPermissions.UsersRead.Resource != "users" || CommonPermissions.UsersRead.Action != "read" {
		t.Fatalf("UsersRead = %+v, want Resource=users Action=read", CommonPermissions.UsersRead)
	}

	if CommonPermissions.FilesWrite.Resource != "files" || CommonPermissions.FilesWrite.Action != "write" {
		t.Fatalf("FilesWrite = %+v, want Resource=files Action=write", CommonPermissions.FilesWrite)
	}

	if CommonPermissions.AdminAll.Resource != "*" || CommonPermissions.AdminAll.Action != "*" {
		t.Fatalf("AdminAll = %+v, want Resource=* Action=*", CommonPermissions.AdminAll)
	}
}

func TestHasPermissionInRequest(t *testing.T) {
	ctx := guard.WithPermissionContext(context.Background(), &guard.PermissionContext{
		UserID:   "user123",
		Resource: "documents",
		Action:   "read",
		Granted:  true,
	})
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req = req.WithContext(ctx)

	if !HasPermissionInRequest(req, "documents", "read") {
		t.Fatal("HasPermissionInRequest should return true for granted permission")
	}

	if HasPermissionInRequest(req, "documents", "write") {
		t.Fatal("HasPermissionInRequest should return false for different permission")
	}
}

func TestGetPermissionContext(t *testing.T) {
	expectedCtx := &guard.PermissionContext{
		UserID:   "user123",
		Resource: "files",
		Action:   "delete",
		Granted:  false,
	}

	ctx := guard.WithPermissionContext(context.Background(), expectedCtx)
	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	req = req.WithContext(ctx)

	permCtx, ok := GetPermissionContext(req)
	if !ok {
		t.Fatal("GetPermissionContext should return true when context exists")
	}

	if permCtx.UserID != expectedCtx.UserID ||
		permCtx.Resource != expectedCtx.Resource ||
		permCtx.Action != expectedCtx.Action ||
		permCtx.Granted != expectedCtx.Granted {
		t.Fatalf("GetPermissionContext = %+v, want %+v", permCtx, expectedCtx)
	}
}

func TestChain(t *testing.T) {
	var callOrder []string

	middleware1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callOrder = append(callOrder, "middleware1")
			next.ServeHTTP(w, r)
		})
	}

	middleware2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callOrder = append(callOrder, "middleware2")
			next.ServeHTTP(w, r)
		})
	}

	handler := Chain(middleware1, middleware2)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callOrder = append(callOrder, "handler")
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	expectedOrder := []string{"middleware1", "middleware2", "handler"}
	if len(callOrder) != len(expectedOrder) {
		t.Fatalf("call order length=%d want=%d", len(callOrder), len(expectedOrder))
	}

	for i, expected := range expectedOrder {
		if callOrder[i] != expected {
			t.Fatalf("call order[%d]=%s want=%s", i, callOrder[i], expected)
		}
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
