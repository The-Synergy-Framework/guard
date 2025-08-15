package adapter

import (
	"context"
	"fmt"

	"guard"
)

// Service wraps a Provider and exposes the guard.Service interface.
type Service struct {
	Provider Provider
}

// NewService creates a new guard.Service backed by a Provider.
func NewService(provider Provider) *Service {
	return &Service{Provider: provider}
}

// Authenticate handles supported credential types using the provider.
func (s *Service) Authenticate(ctx context.Context, credentials guard.Credentials) (*guard.User, error) {
	switch credentials.Type() {
	case guard.TokenCredentialType:
		tc, _ := credentials.(guard.TokenCredentials)
		claims, err := s.Provider.ValidateToken(ctx, tc.Token)
		if err != nil {
			return nil, err
		}
		return s.Provider.GetUser(ctx, claims.UserID)
	case guard.PasswordCredentialType:
		return nil, NewProviderError(s.Provider.Name(), "authenticate_password", ErrProviderMisconfigured)
	case guard.APIKeyCredentialType:
		return nil, NewProviderError(s.Provider.Name(), "authenticate_apikey", ErrProviderMisconfigured)
	default:
		return nil, fmt.Errorf("unsupported credentials type: %s", credentials.Type())
	}
}

// ValidateToken delegates to the provider.
func (s *Service) ValidateToken(ctx context.Context, token string) (*guard.Claims, error) {
	return s.Provider.ValidateToken(ctx, token)
}

// RefreshToken delegates to the provider.
func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (*guard.TokenPair, error) {
	return s.Provider.RefreshTokens(ctx, refreshToken)
}

// GenerateTokens delegates to the provider.
func (s *Service) GenerateTokens(ctx context.Context, userID string) (*guard.TokenPair, error) {
	return s.Provider.GenerateTokens(ctx, userID)
}

// RevokeToken is not supported generically because providers differ on revoke semantics.
func (s *Service) RevokeToken(ctx context.Context, tokenID string) error {
	return NewProviderError(s.Provider.Name(), "revoke_token", ErrProviderMisconfigured)
}

// Authorize delegates to the provider.
func (s *Service) Authorize(ctx context.Context, userID string, resource, action string) error {
	return s.Provider.Authorize(ctx, userID, resource, action)
}

// HasRole delegates to the provider.
func (s *Service) HasRole(ctx context.Context, userID string, role string) (bool, error) {
	return s.Provider.HasRole(ctx, userID, role)
}

// HasPermission checks permission via user object.
// Assumes provider.User contains Permissions when available.
func (s *Service) HasPermission(ctx context.Context, userID string, permission string) (bool, error) {
	user, err := s.Provider.GetUser(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, p := range user.Permissions {
		if p == permission {
			return true, nil
		}
	}
	return false, nil
}

// GetUserRoles returns roles from the user object.
func (s *Service) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	user, err := s.Provider.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return user.Roles, nil
}

// GetUserPermissions returns permissions from the user object.
func (s *Service) GetUserPermissions(ctx context.Context, userID string) ([]string, error) {
	user, err := s.Provider.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return user.Permissions, nil
}
