package jwt

import "errors"

// JWT-specific errors
var (
	// ErrInvalidToken indicates the token is invalid
	ErrInvalidToken = errors.New("invalid token")
	// ErrTokenExpired indicates the token has expired
	ErrTokenExpired = errors.New("token expired")
	// ErrTokenNotYetValid indicates the token is not yet valid
	ErrTokenNotYetValid = errors.New("token not yet valid")
	// ErrInvalidSigningMethod indicates an unsupported signing method
	ErrInvalidSigningMethod = errors.New("invalid signing method")
)
