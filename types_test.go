package guard

import (
	"testing"
	"time"
)

func TestUser_Methods(t *testing.T) {
	u := &User{ID: "1", Username: "u", FirstName: "A", LastName: "B", Roles: []string{"r"}, Permissions: []string{"p"}}
	if u.FullName() != "A B" {
		t.Fatalf("fullname: %q", u.FullName())
	}
	if !u.HasRole("r") || u.HasRole("x") {
		t.Fatalf("has role mismatch")
	}
	if !u.HasPermission("p") || u.HasPermission("x") {
		t.Fatalf("has perm mismatch")
	}
}

func TestClaims_Methods(t *testing.T) {
	now := time.Now()
	c := &Claims{TokenType: "access", ExpiresAt: now.Add(10 * time.Millisecond)}
	if !c.IsAccessToken() || c.IsRefreshToken() {
		t.Fatalf("token type mismatch")
	}
	if c.IsExpired() {
		t.Fatalf("should not be expired")
	}
}
