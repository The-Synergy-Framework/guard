package http

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Middleware-specific errors
var (
	// ErrMissingToken indicates no authentication token was provided
	ErrMissingToken = errors.New("missing authentication token")

	// ErrInvalidTokenFormat indicates the token format is invalid
	ErrInvalidTokenFormat = errors.New("invalid token format")
)

// ErrorResponse represents a JSON error response.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
	Code    int    `json:"code"`
}

// defaultErrorHandler handles authentication/authorization errors.
func defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	var status int
	var message string

	// Determine appropriate status code
	switch {
	case errors.Is(err, ErrMissingToken), errors.Is(err, ErrInvalidTokenFormat):
		status = http.StatusUnauthorized
		message = "Invalid or missing authentication token"
	default:
		status = http.StatusUnauthorized
		message = "Authentication failed"
	}

	writeJSONError(w, status, "authentication_failed", message)
}

// defaultUnauthorizedHandler handles missing authentication.
func defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	writeJSONError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
}

// defaultForbiddenHandler handles authorization failures.
func defaultForbiddenHandler(w http.ResponseWriter, r *http.Request) {
	writeJSONError(w, http.StatusForbidden, "forbidden", "Insufficient permissions")
}

// writeJSONError writes a JSON error response.
func writeJSONError(w http.ResponseWriter, status int, errorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	response := ErrorResponse{
		Error:   errorCode,
		Message: message,
		Code:    status,
	}

	json.NewEncoder(w).Encode(response)
}
