package adapter

import (
	"context"
	"fmt"

	"guard"
)

// Service wraps a Provider and exposes the guard.Service interface.
type Service struct {
	Provider   Provider
	authorizer guard.Authorizer
}

// NewService creates a new guard.Service backed by a Provider.
func NewService(provider Provider, opts ...ServiceOption) *Service {
	s := &Service{Provider: provider}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ServiceOption configures the Service.
type ServiceOption func(*Service)

// WithAuthorizer sets a custom authorizer for the service.
func WithAuthorizer(a guard.Authorizer) ServiceOption {
	return func(s *Service) { s.authorizer = a }
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

// Authorize checks permission via custom authorizer if set; otherwise use provider-based.
func (s *Service) Authorize(ctx context.Context, userID string, resource, action string) error {
	if s.authorizer != nil {
		return s.authorizer.Authorize(ctx, userID, resource, action)
	}
	return s.Provider.Authorize(ctx, userID, resource, action)
}

// HasRole checks role via custom authorizer if set; otherwise provider-based.
func (s *Service) HasRole(ctx context.Context, userID string, role string) (bool, error) {
	if s.authorizer != nil {
		return s.authorizer.HasRole(ctx, userID, role)
	}
	return s.Provider.HasRole(ctx, userID, role)
}

// HasPermission checks permission via custom authorizer if set; otherwise derive from user object.
func (s *Service) HasPermission(ctx context.Context, userID string, permission string) (bool, error) {
	if s.authorizer != nil {
		return s.authorizer.HasPermission(ctx, userID, permission)
	}
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

// GetUserRoles returns roles using custom authorizer if set; otherwise from user object.
func (s *Service) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	if s.authorizer != nil {
		return s.authorizer.GetUserRoles(ctx, userID)
	}
	user, err := s.Provider.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return user.Roles, nil
}

// GetUserPermissions returns permissions using custom authorizer if set; otherwise from user object.
func (s *Service) GetUserPermissions(ctx context.Context, userID string) ([]string, error) {
	if s.authorizer != nil {
		return s.authorizer.GetUserPermissions(ctx, userID)
	}
	user, err := s.Provider.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return user.Permissions, nil
}
