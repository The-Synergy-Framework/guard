package memory

import (
	"context"
	"testing"

	"guard"
)

func TestService_BasicFlows(t *testing.T) {
	ctx := context.Background()
	svc, err := NewService(DefaultConfig())
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	user, err := svc.CreateUser(ctx, "alice", "alice@example.com", "s3cr3t", []string{"user"})
	if err != nil || user.ID == "" {
		t.Fatalf("CreateUser error: %v", err)
	}

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "authenticate password",
			run: func(t *testing.T) {
				authed, err := svc.Authenticate(ctx, guard.PasswordCredentials{Username: "alice", Password: "s3cr3t"})
				if err != nil || authed.ID != user.ID {
					t.Fatalf("auth failed: %v", err)
				}
			},
		},
		{
			name: "tokens and claims",
			run: func(t *testing.T) {
				pair, err := svc.GenerateTokens(ctx, user.ID)
				if err != nil {
					t.Fatalf("GenerateTokens error: %v", err)
				}
				claims, err := svc.ValidateToken(ctx, pair.AccessToken)
				if err != nil || claims.UserID != user.ID {
					t.Fatalf("claims mismatch: %v %+v", err, claims)
				}
			},
		},
		{
			name: "authorize allowed",
			run: func(t *testing.T) {
				if err := svc.Authorize(ctx, user.ID, "profile", "read"); err != nil {
					t.Fatalf("authorize read: %v", err)
				}
				if err := svc.Authorize(ctx, user.ID, "profile", "write"); err != nil {
					t.Fatalf("authorize write: %v", err)
				}
			},
		},
		{
			name: "authorize denied",
			run: func(t *testing.T) {
				if err := svc.Authorize(ctx, user.ID, "admin", "manage"); err == nil {
					t.Fatalf("expected permission denied")
				}
			},
		},
		{
			name: "role helpers",
			run: func(t *testing.T) {
				hasUser, err := svc.HasRole(ctx, user.ID, "user")
				if err != nil || !hasUser {
					t.Fatalf("expected user role: %v", err)
				}
				hasAdmin, err := svc.HasRole(ctx, user.ID, "admin")
				if err != nil || hasAdmin {
					t.Fatalf("did not expect admin role: %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}
