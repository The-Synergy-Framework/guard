package guard_test

import (
	"context"
	"guard"
	"testing"

	mem "guard/memory"
)

func TestIntegration_FullAuthFlow(t *testing.T) {
	// Create service
	svc, err := mem.NewService(mem.DefaultConfig())
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	ctx := context.Background()

	// 1. Create users with different roles
	admin, err := svc.CreateUser(ctx, "admin", "admin@example.com", "password123", []string{"admin"})
	if err != nil {
		t.Fatalf("CreateUser admin error: %v", err)
	}

	user, err := svc.CreateUser(ctx, "user", "user@example.com", "password123", []string{"user"})
	if err != nil {
		t.Fatalf("CreateUser user error: %v", err)
	}

	moderator, err := svc.CreateUser(ctx, "moderator", "mod@example.com", "password123", []string{"moderator"})
	if err != nil {
		t.Fatalf("CreateUser moderator error: %v", err)
	}

	// 2. Test authentication with password credentials
	t.Run("password authentication", func(t *testing.T) {
		authUser, err := svc.Authenticate(ctx, guard.PasswordCredentials{
			Username: "admin",
			Password: "password123",
		})
		if err != nil {
			t.Fatalf("Authentication error: %v", err)
		}
		if authUser.ID != admin.ID {
			t.Fatalf("Wrong user authenticated: got %s, want %s", authUser.ID, admin.ID)
		}
	})

	// 3. Test token generation and validation
	t.Run("token generation and validation", func(t *testing.T) {
		tokens, err := svc.GenerateTokens(ctx, admin.ID)
		if err != nil {
			t.Fatalf("GenerateTokens error: %v", err)
		}

		claims, err := svc.ValidateToken(ctx, tokens.AccessToken)
		if err != nil {
			t.Fatalf("ValidateToken error: %v", err)
		}

		if claims.UserID != admin.ID {
			t.Fatalf("Wrong user ID in claims: got %s, want %s", claims.UserID, admin.ID)
		}

		// Test refresh token
		newTokens, err := svc.RefreshToken(ctx, tokens.RefreshToken)
		if err != nil {
			t.Fatalf("RefreshToken error: %v", err)
		}

		if newTokens.AccessToken == tokens.AccessToken {
			t.Fatal("New access token should be different")
		}
	})

	// 4. Test role-based authorization
	t.Run("role authorization", func(t *testing.T) {
		// Admin should have admin role
		hasAdmin, err := svc.HasRole(ctx, admin.ID, "admin")
		if err != nil {
			t.Fatalf("HasRole admin error: %v", err)
		}
		if !hasAdmin {
			t.Fatal("Admin should have admin role")
		}

		// User should not have admin role
		hasAdmin, err = svc.HasRole(ctx, user.ID, "admin")
		if err != nil {
			t.Fatalf("HasRole user error: %v", err)
		}
		if hasAdmin {
			t.Fatal("User should not have admin role")
		}

		// Get all roles for admin
		roles, err := svc.GetUserRoles(ctx, admin.ID)
		if err != nil {
			t.Fatalf("GetUserRoles error: %v", err)
		}
		if len(roles) == 0 {
			t.Fatal("Admin should have at least one role")
		}
	})

	// 5. Test permission-based authorization
	t.Run("permission authorization", func(t *testing.T) {
		// Admin should be able to manage users
		err := svc.Authorize(ctx, admin.ID, "users", "manage")
		if err != nil {
			t.Fatalf("Admin should be authorized to manage users: %v", err)
		}

		// Regular user should not be able to manage users
		err = svc.Authorize(ctx, user.ID, "users", "manage")
		if err == nil {
			t.Fatal("User should not be authorized to manage users")
		}

		// Get permissions
		permissions, err := svc.GetUserPermissions(ctx, admin.ID)
		if err != nil {
			t.Fatalf("GetUserPermissions error: %v", err)
		}
		if len(permissions) == 0 {
			t.Fatal("Admin should have permissions")
		}
	})

	// 6. Test user management operations
	t.Run("user management", func(t *testing.T) {
		// Update user
		newEmail := "newemail@example.com"
		updates := guard.UserUpdate{
			Email: &newEmail,
		}
		err := svc.UpdateUser(ctx, user.ID, updates)
		if err != nil {
			t.Fatalf("UpdateUser error: %v", err)
		}

		// Get updated user
		updatedUser, err := svc.GetUser(ctx, user.ID)
		if err != nil {
			t.Fatalf("GetUser error: %v", err)
		}
		if updatedUser.Email != "newemail@example.com" {
			t.Fatalf("Email not updated: got %s, want newemail@example.com", updatedUser.Email)
		}

		// Get user by username
		userByUsername, err := svc.GetUserByUsername(ctx, "user")
		if err != nil {
			t.Fatalf("GetUserByUsername error: %v", err)
		}
		if userByUsername.ID != user.ID {
			t.Fatalf("Wrong user by username: got %s, want %s", userByUsername.ID, user.ID)
		}

		// Get user by email
		userByEmail, err := svc.GetUserByEmail(ctx, "newemail@example.com")
		if err != nil {
			t.Fatalf("GetUserByEmail error: %v", err)
		}
		if userByEmail.ID != user.ID {
			t.Fatalf("Wrong user by email: got %s, want %s", userByEmail.ID, user.ID)
		}

		// Change password
		err = svc.ChangePassword(ctx, user.ID, "password123", "newpassword123")
		if err != nil {
			t.Fatalf("ChangePassword error: %v", err)
		}

		// Test authentication with new password
		_, err = svc.Authenticate(ctx, guard.PasswordCredentials{
			Username: "user",
			Password: "newpassword123",
		})
		if err != nil {
			t.Fatalf("Authentication with new password failed: %v", err)
		}

		// Test old password should fail
		_, err = svc.Authenticate(ctx, guard.PasswordCredentials{
			Username: "user",
			Password: "password123",
		})
		if err == nil {
			t.Fatal("Authentication with old password should fail")
		}
	})

	// 7. Test token revocation
	t.Run("token revocation", func(t *testing.T) {
		tokens, err := svc.GenerateTokens(ctx, user.ID)
		if err != nil {
			t.Fatalf("GenerateTokens error: %v", err)
		}

		// Validate token before revocation
		_, err = svc.ValidateToken(ctx, tokens.AccessToken)
		if err != nil {
			t.Fatalf("Token should be valid before revocation: %v", err)
		}

		// Revoke token
		err = svc.RevokeToken(ctx, tokens.AccessToken)
		if err != nil {
			t.Fatalf("RevokeToken error: %v", err)
		}

		// Token should be invalid after revocation
		_, err = svc.ValidateToken(ctx, tokens.AccessToken)
		if err == nil {
			t.Fatal("Token should be invalid after revocation")
		}
	})

	// 8. Test context helpers
	t.Run("context helpers", func(t *testing.T) {
		claims := &guard.Claims{
			UserID: admin.ID,
			Roles:  []string{"admin"},
		}

		// Test WithClaims and ClaimsFromContext
		ctxWithClaims := guard.WithClaims(ctx, claims)
		retrievedClaims, ok := guard.ClaimsFromContext(ctxWithClaims)
		if !ok {
			t.Fatal("Claims not found in context")
		}
		if retrievedClaims.UserID != admin.ID {
			t.Fatalf("Wrong user ID in context claims: got %s, want %s", retrievedClaims.UserID, admin.ID)
		}

		// Test WithUser and UserFromContext
		ctxWithUser := guard.WithUser(ctx, admin)
		retrievedUser, ok := guard.UserFromContext(ctxWithUser)
		if !ok {
			t.Fatal("User not found in context")
		}
		if retrievedUser.ID != admin.ID {
			t.Fatalf("Wrong user in context: got %s, want %s", retrievedUser.ID, admin.ID)
		}

		// Test UserIDFromContext
		userID, ok := guard.UserIDFromContext(ctxWithClaims)
		if !ok {
			t.Fatal("User ID not found in context")
		}
		if userID != admin.ID {
			t.Fatalf("Wrong user ID from context: got %s, want %s", userID, admin.ID)
		}

		// Test IsAuthenticated
		if !guard.IsAuthenticated(ctxWithClaims) {
			t.Fatal("Context should be authenticated")
		}
		if guard.IsAuthenticated(ctx) {
			t.Fatal("Empty context should not be authenticated")
		}
	})

	// 9. Test user deletion (should be last)
	t.Run("user deletion", func(t *testing.T) {
		err := svc.DeleteUser(ctx, moderator.ID)
		if err != nil {
			t.Fatalf("DeleteUser error: %v", err)
		}

		// User should not be found after deletion
		_, err = svc.GetUser(ctx, moderator.ID)
		if err == nil {
			t.Fatal("Deleted user should not be found")
		}

		// Authentication should fail for deleted user
		_, err = svc.Authenticate(ctx, guard.PasswordCredentials{
			Username: "moderator",
			Password: "password123",
		})
		if err == nil {
			t.Fatal("Authentication should fail for deleted user")
		}
	})
}

func TestIntegration_CredentialTypes(t *testing.T) {
	svc, err := mem.NewService(mem.DefaultConfig())
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	ctx := context.Background()

	// Create test user
	user, err := svc.CreateUser(ctx, "testuser", "test@example.com", "password", []string{"user"})
	if err != nil {
		t.Fatalf("CreateUser error: %v", err)
	}

	// Generate tokens for token authentication
	tokens, err := svc.GenerateTokens(ctx, user.ID)
	if err != nil {
		t.Fatalf("GenerateTokens error: %v", err)
	}

	tests := []struct {
		name        string
		credentials guard.Credentials
		wantErr     bool
	}{
		{
			name: "password credentials",
			credentials: guard.PasswordCredentials{
				Username: "testuser",
				Password: "password",
			},
			wantErr: false,
		},
		{
			name: "token credentials",
			credentials: guard.TokenCredentials{
				Token: tokens.AccessToken,
			},
			wantErr: false,
		},
		{
			name: "api key credentials",
			credentials: guard.APIKeyCredentials{
				APIKey: "test-api-key",
			},
			wantErr: true, // Not implemented in memory service
		},
		{
			name: "invalid password",
			credentials: guard.PasswordCredentials{
				Username: "testuser",
				Password: "wrongpassword",
			},
			wantErr: true,
		},
		{
			name: "invalid token",
			credentials: guard.TokenCredentials{
				Token: "invalid-token",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authUser, err := svc.Authenticate(ctx, tt.credentials)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Authenticate error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && authUser.ID != user.ID {
				t.Fatalf("Wrong user authenticated: got %s, want %s", authUser.ID, user.ID)
			}
		})
	}
}

func TestIntegration_UserHelpers(t *testing.T) {
	svc, err := mem.NewService(mem.DefaultConfig())
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	ctx := context.Background()

	// Create test user
	user, err := svc.CreateUser(ctx, "testuser", "test@example.com", "password", []string{"user", "editor"})
	if err != nil {
		t.Fatalf("CreateUser error: %v", err)
	}

	t.Run("user has role", func(t *testing.T) {
		if !user.HasRole("user") {
			t.Fatal("User should have 'user' role")
		}
		if !user.HasRole("editor") {
			t.Fatal("User should have 'editor' role")
		}
		if user.HasRole("admin") {
			t.Fatal("User should not have 'admin' role")
		}
	})

	t.Run("user full name", func(t *testing.T) {
		// Update user with first and last name
		firstName := "Test"
		lastName := "User"
		updates := guard.UserUpdate{
			FirstName: &firstName,
			LastName:  &lastName,
		}
		err := svc.UpdateUser(ctx, user.ID, updates)
		if err != nil {
			t.Fatalf("UpdateUser error: %v", err)
		}

		// Get updated user
		updatedUser, err := svc.GetUser(ctx, user.ID)
		if err != nil {
			t.Fatalf("GetUser error: %v", err)
		}

		fullName := updatedUser.FullName()
		if fullName != "Test User" {
			t.Fatalf("FullName = %s, want 'Test User'", fullName)
		}
	})
}

func TestIntegration_ClaimsHelpers(t *testing.T) {
	svc, err := mem.NewService(mem.DefaultConfig())
	if err != nil {
		t.Fatalf("NewService error: %v", err)
	}

	ctx := context.Background()

	// Create test user
	user, err := svc.CreateUser(ctx, "testuser", "test@example.com", "password", []string{"user"})
	if err != nil {
		t.Fatalf("CreateUser error: %v", err)
	}

	// Generate tokens
	tokens, err := svc.GenerateTokens(ctx, user.ID)
	if err != nil {
		t.Fatalf("GenerateTokens error: %v", err)
	}

	// Validate token to get claims
	claims, err := svc.ValidateToken(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken error: %v", err)
	}

	t.Run("claims methods", func(t *testing.T) {
		if claims.IsExpired() {
			t.Fatal("Claims should not be expired")
		}

		if !claims.IsAccessToken() {
			t.Fatal("Claims should be access token")
		}

		if claims.IsRefreshToken() {
			t.Fatal("Claims should not be refresh token")
		}
	})

	// Test refresh token claims
	refreshClaims, err := svc.ValidateToken(ctx, tokens.RefreshToken)
	if err != nil {
		t.Fatalf("ValidateToken refresh error: %v", err)
	}

	t.Run("refresh token claims", func(t *testing.T) {
		if !refreshClaims.IsRefreshToken() {
			t.Fatal("Refresh claims should be refresh token")
		}

		if refreshClaims.IsAccessToken() {
			t.Fatal("Refresh claims should not be access token")
		}
	})
}
