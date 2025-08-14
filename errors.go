package guard

import "errors"

// Common Guard errors
var (
	// ErrUserNotFound indicates the user was not found
	ErrUserNotFound = errors.New("user not found")

	// ErrUserExists indicates a user with the same username/email already exists
	ErrUserExists = errors.New("user already exists")

	// ErrInvalidCredentials indicates invalid login credentials
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrRoleNotFound indicates the role was not found
	ErrRoleNotFound = errors.New("role not found")

	// ErrPermissionDenied indicates the user lacks required permissions
	ErrPermissionDenied = errors.New("permission denied")

	// ErrTokenExpired indicates the token has expired
	ErrTokenExpired = errors.New("token expired")

	// ErrTokenInvalid indicates the token is invalid
	ErrTokenInvalid = errors.New("token invalid")

	// ErrTokenRevoked indicates the token has been revoked
	ErrTokenRevoked = errors.New("token revoked")
)
