package jwt

import (
	"core/chrono"
	"errors"
	"time"
)

// Algorithm represents the signing algorithm for JWT tokens.
type Algorithm string

const (
	// HS256 uses HMAC with SHA-256
	HS256 Algorithm = "HS256"
	// RS256 uses RSA signature with SHA-256
	RS256 Algorithm = "RS256"
)

// Config holds the configuration for JWT token management.
type Config struct {
	// SecretKey is the secret key for HS256
	SecretKey string `validate:"required_if=Algorithm HS256"`

	// PrivateKey is the RSA private key for RS256 (PEM format)
	PrivateKey string `validate:"required_if=Algorithm RS256"`

	// PublicKey is the RSA public key for RS256 (PEM format, optional)
	PublicKey string

	// Algorithm to use for signing (HS256 or RS256)
	Algorithm Algorithm `validate:"required,oneof=HS256 RS256"`

	// Issuer identifies the issuer of the token
	Issuer string `validate:"max:100"`

	// Audience identifies the recipients of the token
	Audience string `validate:"max:100"`

	// AccessTokenExpiry sets the expiration time for access tokens
	AccessTokenExpiry time.Duration `validate:"required"`

	// RefreshTokenExpiry sets the expiration time for refresh tokens
	RefreshTokenExpiry time.Duration `validate:"required"`

	// ClockSkew allows for clock drift between servers
	ClockSkew time.Duration
}

// DefaultConfig returns a default JWT configuration.
func DefaultConfig() Config {
	return Config{
		Algorithm:          HS256,
		AccessTokenExpiry:  chrono.FifteenMinutes,
		RefreshTokenExpiry: chrono.Week,
		ClockSkew:          chrono.FiveMinutes,
	}
}

// Validate validates the JWT configuration.
func (c *Config) Validate() error {
	if c.Algorithm == "" {
		return errors.New("algorithm is required")
	}

	if c.Algorithm != HS256 && c.Algorithm != RS256 {
		return errors.New("algorithm must be HS256 or RS256")
	}

	if c.Algorithm == HS256 && c.SecretKey == "" {
		return errors.New("secret key is required for HS256")
	}

	if c.Algorithm == RS256 && c.PrivateKey == "" {
		return errors.New("private key is required for RS256")
	}

	if c.AccessTokenExpiry <= 0 {
		return errors.New("access token expiry must be positive")
	}

	if c.RefreshTokenExpiry <= 0 {
		return errors.New("refresh token expiry must be positive")
	}

	return nil
}
