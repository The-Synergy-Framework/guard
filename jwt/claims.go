package jwt

import (
	"guard"

	"github.com/golang-jwt/jwt/v5"
)

// jwtClaims wraps guard.Claims for JWT compatibility.
type jwtClaims struct {
	jwt.RegisteredClaims
	UserID      string         `json:"user_id,omitempty"`
	Username    string         `json:"username,omitempty"`
	Email       string         `json:"email,omitempty"`
	Roles       []string       `json:"roles,omitempty"`
	Permissions []string       `json:"permissions,omitempty"`
	SessionID   string         `json:"session_id,omitempty"`
	TenantID    string         `json:"tenant_id,omitempty"`
	TokenType   string         `json:"token_type,omitempty"`
	TokenID     string         `json:"token_id,omitempty"`
	Custom      map[string]any `json:"custom,omitempty"`
}

// newJWTClaims creates jwt claims from guard claims.
func newJWTClaims(claims *guard.Claims) *jwtClaims {
	return &jwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    claims.Issuer,
			Subject:   claims.Subject,
			Audience:  jwt.ClaimStrings{claims.Audience},
			ExpiresAt: jwt.NewNumericDate(claims.ExpiresAt),
			NotBefore: jwt.NewNumericDate(claims.NotBefore),
			IssuedAt:  jwt.NewNumericDate(claims.IssuedAt),
			ID:        claims.TokenID,
		},
		UserID:      claims.UserID,
		Username:    claims.Username,
		Email:       claims.Email,
		Roles:       claims.Roles,
		Permissions: claims.Permissions,
		SessionID:   claims.SessionID,
		TenantID:    claims.TenantID,
		TokenType:   claims.TokenType,
		TokenID:     claims.TokenID,
		Custom:      claims.Custom,
	}
}

// toGuardClaims converts jwt claims to guard claims.
func (j *jwtClaims) toGuardClaims() *guard.Claims {
	claims := &guard.Claims{
		UserID:      j.UserID,
		Username:    j.Username,
		Email:       j.Email,
		Roles:       j.Roles,
		Permissions: j.Permissions,
		SessionID:   j.SessionID,
		TenantID:    j.TenantID,
		TokenType:   j.TokenType,
		TokenID:     j.TokenID,
		Custom:      j.Custom,
	}

	if j.ExpiresAt != nil {
		claims.ExpiresAt = j.ExpiresAt.Time
	}
	if j.NotBefore != nil {
		claims.NotBefore = j.NotBefore.Time
	}
	if j.IssuedAt != nil {
		claims.IssuedAt = j.IssuedAt.Time
	}
	if j.Issuer != "" {
		claims.Issuer = j.Issuer
	}
	if len(j.Audience) > 0 {
		claims.Audience = j.Audience[0]
	}
	if j.Subject != "" {
		claims.Subject = j.Subject
	}

	return claims
}
