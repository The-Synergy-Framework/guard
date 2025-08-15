// Package guard provides core authentication and authorization interfaces
// for the Synergy Framework with pluggable implementations.
package guard

import "context"

// Authenticator handles user authentication and token management.
type Authenticator interface {
	// Authenticate validates credentials and returns user information
	Authenticate(ctx context.Context, credentials Credentials) (*User, error)

	// ValidateToken validates a token and returns the claims
	ValidateToken(ctx context.Context, token string) (*Claims, error)

	// RefreshToken validates a refresh token and generates new tokens
	RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error)

	// GenerateTokens creates new access and refresh tokens for a user
	GenerateTokens(ctx context.Context, userID string) (*TokenPair, error)

	// RevokeToken invalidates a token (adds to blacklist)
	RevokeToken(ctx context.Context, tokenID string) error
}

// Authorizer handles authorization and permission checking.
type Authorizer interface {
	// Authorize checks if a user has permission to perform an action on a resource
	Authorize(ctx context.Context, userID string, resource, action string) error

	// HasRole checks if a user has a specific role
	HasRole(ctx context.Context, userID string, role string) (bool, error)

	// HasPermission checks if a user has a specific permission
	HasPermission(ctx context.Context, userID string, permission string) (bool, error)

	// GetUserRoles returns all roles for a user
	GetUserRoles(ctx context.Context, userID string) ([]string, error)

	// GetUserPermissions returns all permissions for a user
	GetUserPermissions(ctx context.Context, userID string) ([]string, error)
}

// Service combines authentication and authorization functionality.
type Service interface {
	Authenticator
	Authorizer
}

// UserManager provides user management capabilities (optional interface).
type UserManager interface {
	// CreateUser creates a new user
	CreateUser(ctx context.Context, username, email, password string, roles []string) (*User, error)

	// GetUser retrieves a user by ID
	GetUser(ctx context.Context, userID string) (*User, error)

	// GetUserByUsername retrieves a user by username
	GetUserByUsername(ctx context.Context, username string) (*User, error)

	// GetUserByEmail retrieves a user by email
	GetUserByEmail(ctx context.Context, email string) (*User, error)

	// UpdateUser updates user information
	UpdateUser(ctx context.Context, userID string, updates UserUpdate) error

	// DeleteUser deletes a user
	DeleteUser(ctx context.Context, userID string) error

	// ChangePassword changes a user's password
	ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error
}

// RoleManager provides role management capabilities (optional interface).
type RoleManager interface {
	// CreateRole creates a new role
	CreateRole(ctx context.Context, name, description string, permissions []string) (*Role, error)

	// GetRole retrieves a role by name
	GetRole(ctx context.Context, name string) (*Role, error)

	// UpdateRole updates role information
	UpdateRole(ctx context.Context, name string, updates RoleUpdate) error

	// DeleteRole deletes a role
	DeleteRole(ctx context.Context, name string) error

	// AssignRole assigns a role to a user
	AssignRole(ctx context.Context, userID, roleName string) error

	// UnassignRole removes a role from a user
	UnassignRole(ctx context.Context, userID, roleName string) error
}

// NewService composes an Authenticator and Authorizer into a guard.Service.
// If either is nil, the returned service will panic on respective method calls.
type composedService struct {
	Authenticator
	Authorizer
}

func NewService(authn Authenticator, authz Authorizer) Service {
	return &composedService{Authenticator: authn, Authorizer: authz}
}
