package jwt

import (
	"core/crypto"
	"core/ids"
	"crypto/rsa"
	"errors"
	"fmt"
	"guard"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Manager handles JWT token operations.
type Manager struct {
	config     Config
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewManager creates a new JWT manager with the given configuration.
func NewManager(config Config) (*Manager, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	manager := &Manager{config: config}

	if config.Algorithm == RS256 {
		privateKey, err := crypto.ParseRSAPrivateKey(config.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		manager.privateKey = privateKey

		if config.PublicKey != "" {
			publicKey, err := crypto.ParseRSAPublicKey(config.PublicKey)
			if err != nil {
				return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
			}
			manager.publicKey = publicKey
		} else {
			manager.publicKey = &privateKey.PublicKey
		}
	}

	return manager, nil
}

// GenerateTokens creates both access and refresh tokens for a user.
func (m *Manager) GenerateTokens(userID string, roles, permissions []string) (*guard.TokenPair, error) {
	now := time.Now()

	accessClaims := &guard.Claims{
		UserID:      userID,
		Roles:       roles,
		Permissions: permissions,
		TokenType:   "access",
		TokenID:     ids.MustUUID(),
		IssuedAt:    now,
		ExpiresAt:   now.Add(m.config.AccessTokenExpiry),
		NotBefore:   now,
		Issuer:      m.config.Issuer,
		Audience:    m.config.Audience,
		Subject:     userID,
	}

	accessToken, err := m.generateToken(accessClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshClaims := &guard.Claims{
		UserID:    userID,
		TokenType: "refresh",
		TokenID:   ids.MustUUID(),
		IssuedAt:  now,
		ExpiresAt: now.Add(m.config.RefreshTokenExpiry),
		NotBefore: now,
		Issuer:    m.config.Issuer,
		Audience:  m.config.Audience,
		Subject:   userID,
	}

	refreshToken, err := m.generateToken(refreshClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &guard.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(m.config.AccessTokenExpiry.Seconds()),
		IssuedAt:     now,
	}, nil
}

// ValidateToken validates a JWT token and returns the claims.
func (m *Manager) ValidateToken(tokenString string) (*guard.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwtClaims{}, m.keyFunc)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("token expired: %w", err)
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, fmt.Errorf("token not yet valid: %w", err)
		}
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	jwtClaims, ok := token.Claims.(*jwtClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	return jwtClaims.toGuardClaims(), nil
}

// ParseToken parses a JWT token without validation (useful for extracting claims from expired tokens).
func (m *Manager) ParseToken(tokenString string) (*guard.Claims, error) {
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, &jwtClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	jwtClaims, ok := token.Claims.(*jwtClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return jwtClaims.toGuardClaims(), nil
}

// generateToken creates a JWT token with the given claims.
func (m *Manager) generateToken(claims *guard.Claims) (string, error) {
	jwtClaims := newJWTClaims(claims)

	var token *jwt.Token
	switch m.config.Algorithm {
	case HS256:
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
	case RS256:
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims)
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", m.config.Algorithm)
	}

	var signingKey interface{}
	switch m.config.Algorithm {
	case HS256:
		signingKey = []byte(m.config.SecretKey)
	case RS256:
		signingKey = m.privateKey
	}

	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// keyFunc returns the key for token validation.
func (m *Manager) keyFunc(token *jwt.Token) (interface{}, error) {
	switch m.config.Algorithm {
	case HS256:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(m.config.SecretKey), nil
	case RS256:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return m.publicKey, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", m.config.Algorithm)
	}
}
