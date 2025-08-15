package memory

import (
	"core/chrono"
	"errors"
	"guard/jwt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Config holds configuration for the in-memory service.
type Config struct {
	JWTSecretKey       string        `validate:"required"`
	JWTAlgorithm       jwt.Algorithm `validate:"required"`
	AccessTokenExpiry  time.Duration `validate:"required"`
	RefreshTokenExpiry time.Duration `validate:"required"`
	JWTIssuer          string
	JWTAudience        string
	BCryptCost         int
	TokenCacheTTL      time.Duration
}

// DefaultConfig returns a default configuration for development.
func DefaultConfig() Config {
	return Config{
		JWTSecretKey:       "dev-secret-key-change-in-production",
		JWTAlgorithm:       jwt.HS256,
		AccessTokenExpiry:  chrono.FifteenMinutes,
		RefreshTokenExpiry: chrono.Week,
		JWTIssuer:          "guard-memory",
		JWTAudience:        "guard-users",
		BCryptCost:         bcrypt.DefaultCost,
		TokenCacheTTL:      chrono.Day,
	}
}

// Validate validates the service configuration.
func (c *Config) Validate() error {
	if c.JWTSecretKey == "" {
		return errors.New("JWT secret key is required")
	}

	if c.AccessTokenExpiry <= 0 {
		return errors.New("access token expiry must be positive")
	}

	if c.RefreshTokenExpiry <= 0 {
		return errors.New("refresh token expiry must be positive")
	}

	if c.BCryptCost < bcrypt.MinCost || c.BCryptCost > bcrypt.MaxCost {
		return errors.New("bcrypt cost must be between 4 and 31")
	}

	return nil
}
