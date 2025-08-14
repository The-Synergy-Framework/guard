package memory

import (
	"context"
	"guard"
	"testing"
)

func TestUserManager_CRUDAndPassword(t *testing.T) {
	ctx := context.Background()
	svc, _ := NewService(DefaultConfig())

	user, err := svc.CreateUser(ctx, "bob", "bob@example.com", "pw1", []string{"user"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := svc.GetUser(ctx, user.ID); err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if u, err := svc.GetUserByUsername(ctx, "bob"); err != nil || u.ID != user.ID {
		t.Fatalf("get by username: %v", err)
	}
	if u, err := svc.GetUserByEmail(ctx, "bob@example.com"); err != nil || u.ID != user.ID {
		t.Fatalf("get by email: %v", err)
	}

	newEmail := "bobby@example.com"
	if err := svc.UpdateUser(ctx, user.ID, guard.UserUpdate{Email: &newEmail, Roles: []string{"admin"}, Metadata: map[string]string{"k": "v"}}); err != nil {
		t.Fatalf("update: %v", err)
	}
	_, _ = svc.CreateUser(ctx, "alice", "dup@example.com", "pw", nil)
	if err := svc.UpdateUser(ctx, user.ID, guard.UserUpdate{Email: strPtr("dup@example.com")}); err == nil {
		t.Fatalf("expected duplicate email error")
	}

	if err := svc.ChangePassword(ctx, user.ID, "bad", "new"); err == nil {
		t.Fatalf("expected wrong old password error")
	}
	if err := svc.ChangePassword(ctx, user.ID, "pw1", "new"); err != nil {
		t.Fatalf("change password: %v", err)
	}

	if err := svc.DeleteUser(ctx, user.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := svc.GetUser(ctx, user.ID); err == nil {
		t.Fatalf("expected not found after delete")
	}
}

func strPtr(s string) *string { return &s }
