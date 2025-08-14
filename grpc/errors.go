package grpc

import "errors"

// gRPC interceptor-specific errors
var (
	// ErrMissingMetadata indicates no metadata was found in the context
	ErrMissingMetadata = errors.New("missing metadata")

	// ErrMissingToken indicates no authentication token was provided
	ErrMissingToken = errors.New("missing authentication token")

	// ErrInvalidTokenFormat indicates the token format is invalid
	ErrInvalidTokenFormat = errors.New("invalid token format")
)
