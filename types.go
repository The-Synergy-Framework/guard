package guard

import "time"

// User represents an authenticated user.
type User struct {
	ID          string            `json:"id"`
	Username    string            `json:"username"`
	Email       string            `json:"email"`
	FirstName   string            `json:"first_name,omitempty"`
	LastName    string            `json:"last_name,omitempty"`
	IsActive    bool              `json:"is_active"`
	Roles       []string          `json:"roles,omitempty"`
	Permissions []string          `json:"permissions,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	LastLoginAt *time.Time        `json:"last_login_at,omitempty"`
}

// FullName returns the user's full name or username if names are not set.
func (u *User) FullName() string {
	if u.FirstName != "" || u.LastName != "" {
		return u.FirstName + " " + u.LastName
	}
	return u.Username
}

// HasRole checks if the user has a specific role.
func (u *User) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasPermission checks if the user has a specific permission.
func (u *User) HasPermission(permission string) bool {
	for _, p := range u.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// Role represents a role in the system.
type Role struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Permissions []string  `json:"permissions,omitempty"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Claims represents JWT token claims.
type Claims struct {
	UserID      string         `json:"user_id"`
	Username    string         `json:"username,omitempty"`
	Email       string         `json:"email,omitempty"`
	Roles       []string       `json:"roles,omitempty"`
	Permissions []string       `json:"permissions,omitempty"`
	SessionID   string         `json:"session_id,omitempty"`
	TenantID    string         `json:"tenant_id,omitempty"`
	TokenType   string         `json:"token_type,omitempty"` // "access" or "refresh"
	TokenID     string         `json:"token_id,omitempty"`   // Unique token identifier
	IssuedAt    time.Time      `json:"iat"`
	ExpiresAt   time.Time      `json:"exp"`
	NotBefore   time.Time      `json:"nbf,omitempty"`
	Issuer      string         `json:"iss,omitempty"`
	Audience    string         `json:"aud,omitempty"`
	Subject     string         `json:"sub,omitempty"`
	Custom      map[string]any `json:"custom,omitempty"`
}

// IsExpired checks if the token is expired.
func (c *Claims) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// IsAccessToken checks if this is an access token.
func (c *Claims) IsAccessToken() bool {
	return c.TokenType == "access"
}

// IsRefreshToken checks if this is a refresh token.
func (c *Claims) IsRefreshToken() bool {
	return c.TokenType == "refresh"
}

// TokenPair represents access and refresh tokens.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"` // Usually "Bearer"
	ExpiresIn    int64     `json:"expires_in"` // Seconds until access token expires
	Scope        string    `json:"scope,omitempty"`
	IssuedAt     time.Time `json:"issued_at"`
}

// UserUpdate represents fields that can be updated for a user.
type UserUpdate struct {
	Email     *string           `json:"email,omitempty"`
	FirstName *string           `json:"first_name,omitempty"`
	LastName  *string           `json:"last_name,omitempty"`
	IsActive  *bool             `json:"is_active,omitempty"`
	Roles     []string          `json:"roles,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// RoleUpdate represents fields that can be updated for a role.
type RoleUpdate struct {
	Description *string  `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	IsActive    *bool    `json:"is_active,omitempty"`
}
