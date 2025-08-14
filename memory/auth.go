package memory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	ctxpkg "core/context"
	"guard"

	"golang.org/x/crypto/bcrypt"
)

// Implement Authenticator interface

// Authenticate validates credentials and returns user information.
func (s *Service) Authenticate(ctx context.Context, credentials guard.Credentials) (*guard.User, error) {
	switch creds := credentials.(type) {
	case guard.PasswordCredentials:
		return s.authenticatePassword(ctx, creds)
	case guard.TokenCredentials:
		return s.authenticateToken(ctx, creds)
	default:
		return nil, fmt.Errorf("unsupported credential type: %s", credentials.Type())
	}
}

// ValidateToken validates a token and returns the claims.
func (s *Service) ValidateToken(ctx context.Context, token string) (*guard.Claims, error) {
	// Check if token is blacklisted
	if _, ok := s.tokenBlacklist.Get(token); ok {
		return nil, errors.New("token has been revoked")
	}

	claims, err := s.jwtManager.ValidateToken(token)
	if err != nil {
		return nil, err
	}

	// Enrich context with user information
	if claims.UserID != "" {
		ctx = ctxpkg.WithUser(ctx, claims.UserID)
	}
	if claims.SessionID != "" {
		ctx = ctxpkg.WithSession(ctx, claims.SessionID)
	}
	if claims.TenantID != "" {
		ctx = ctxpkg.WithTenant(ctx, claims.TenantID)
	}

	return claims, nil
}

// RefreshToken validates a refresh token and generates new tokens.
func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (*guard.TokenPair, error) {
	claims, err := s.ValidateToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	if !claims.IsRefreshToken() {
		return nil, errors.New("token is not a refresh token")
	}

	// Get user to get fresh roles and permissions
	user, err := s.GetUser(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Generate new tokens
	return s.GenerateTokens(ctx, user.ID)
}

// GenerateTokens creates new access and refresh tokens for a user.
func (s *Service) GenerateTokens(ctx context.Context, userID string) (*guard.TokenPair, error) {
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	if !user.IsActive {
		return nil, errors.New("user account is inactive")
	}

	// Get user permissions
	permissions, err := s.GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, err
	}

	return s.jwtManager.GenerateTokens(userID, user.Roles, permissions)
}

// RevokeToken invalidates a token by adding it to the blacklist.
func (s *Service) RevokeToken(ctx context.Context, tokenID string) error {
	// Add token to blacklist with TTL equal to max token expiry
	ttl := s.config.RefreshTokenExpiry
	if s.config.AccessTokenExpiry > ttl {
		ttl = s.config.AccessTokenExpiry
	}

	s.tokenBlacklist.Set(tokenID, true, ttl)
	return nil
}

// Private authentication helpers

// authenticatePassword validates username/password credentials.
func (s *Service) authenticatePassword(ctx context.Context, creds guard.PasswordCredentials) (*guard.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Find user by username or email
	var userID string
	var exists bool

	if strings.Contains(creds.Username, "@") {
		userID, exists = s.usersByEmail[creds.Username]
	} else {
		userID, exists = s.usersByName[creds.Username]
	}

	if !exists {
		return nil, guard.ErrInvalidCredentials
	}

	user, exists := s.users[userID]
	if !exists {
		return nil, guard.ErrInvalidCredentials
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Metadata["password_hash"]), []byte(creds.Password)); err != nil {
		return nil, guard.ErrInvalidCredentials
	}

	if !user.IsActive {
		return nil, errors.New("user account is inactive")
	}

	// Update last login
	now := time.Now()
	user.LastLoginAt = &now

	return user, nil
}

// authenticateToken validates token credentials.
func (s *Service) authenticateToken(ctx context.Context, creds guard.TokenCredentials) (*guard.User, error) {
	claims, err := s.ValidateToken(ctx, creds.Token)
	if err != nil {
		return nil, err
	}

	return s.GetUser(ctx, claims.UserID)
}
