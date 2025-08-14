package memory

import (
	"context"
	"testing"

	"guard"
)

func TestService_RefreshAndRevoke(t *testing.T) {
	ctx := context.Background()
	svc, err := NewService(DefaultConfig())
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}
	u, _ := svc.CreateUser(ctx, "ref", "ref@example.com", "pw", []string{"user"})
	pair, _ := svc.GenerateTokens(ctx, u.ID)

	newPair, err := svc.RefreshToken(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshToken error: %v", err)
	}
	if newPair.AccessToken == pair.AccessToken {
		t.Fatalf("expected new access token")
	}

	if err := svc.RevokeToken(ctx, pair.AccessToken); err != nil {
		t.Fatalf("RevokeToken error: %v", err)
	}
	if _, err := svc.ValidateToken(ctx, pair.AccessToken); err == nil {
		t.Fatalf("expected revoked token to fail validation")
	}
}

func TestService_AuthenticateTokenCredentials(t *testing.T) {
	ctx := context.Background()
	svc, _ := NewService(DefaultConfig())
	u, _ := svc.CreateUser(ctx, "tok", "tok@example.com", "pw", []string{"user"})
	pair, _ := svc.GenerateTokens(ctx, u.ID)
	user, err := svc.Authenticate(ctx, guard.TokenCredentials{Token: pair.AccessToken})
	if err != nil || user.ID != u.ID {
		t.Fatalf("authenticate token failed: %v", err)
	}
}
