package guard

import (
	"context"
	"testing"
)

func TestContext_UserAndClaims(t *testing.T) {
	base := context.Background()

	user := &User{ID: "u1", Username: "bob"}
	ctx := WithUser(base, user)

	gotUser, ok := UserFromContext(ctx)
	if !ok || gotUser.ID != "u1" {
		t.Fatalf("expected user in context")
	}

	claims := &Claims{UserID: "u1", TokenType: "access"}
	ctx2 := WithClaims(ctx, claims)

	gotClaims, ok := ClaimsFromContext(ctx2)
	if !ok || gotClaims.UserID != "u1" || !gotClaims.IsAccessToken() {
		t.Fatalf("expected claims in context with access token")
	}

	id, ok := UserIDFromContext(ctx2)
	if !ok || id != "u1" {
		t.Fatalf("expected user id from context")
	}

	if !IsAuthenticated(ctx2) {
		t.Fatalf("expected authenticated context")
	}
}

func TestContext_MustPanics(t *testing.T) {
	defer func() { _ = recover() }()
	// MustUserFromContext should panic
	func() {
		defer func() { _ = recover() }()
		_ = MustUserFromContext(context.Background())
		t.Fatalf("expected panic for missing user")
	}()
	// MustClaimsFromContext should panic
	func() {
		defer func() { _ = recover() }()
		_ = MustClaimsFromContext(context.Background())
		t.Fatalf("expected panic for missing claims")
	}()
}
