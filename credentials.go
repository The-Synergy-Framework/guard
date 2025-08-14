package guard

// Credentials represents authentication credentials.
type Credentials interface {
	// Type returns the credential type (e.g., "password", "token", "api_key")
	Type() string
}

// PasswordCredentials represents username/password authentication.
type PasswordCredentials struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

func (p PasswordCredentials) Type() string {
	return "password"
}

// TokenCredentials represents token-based authentication.
type TokenCredentials struct {
	Token string `json:"token" validate:"required"`
}

func (t TokenCredentials) Type() string {
	return "token"
}

// APIKeyCredentials represents API key authentication.
type APIKeyCredentials struct {
	APIKey string `json:"api_key" validate:"required"`
}

func (a APIKeyCredentials) Type() string {
	return "api_key"
}
