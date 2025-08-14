package guard

type CredentialType string

const (
	PasswordCredentialType CredentialType = "password"
	TokenCredentialType    CredentialType = "token"
	APIKeyCredentialType   CredentialType = "api_key"
)

// Credentials represents authentication credentials.
type Credentials interface {
	Type() CredentialType
}

// PasswordCredentials represents username/password authentication.
type PasswordCredentials struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

func (p PasswordCredentials) Type() CredentialType {
	return PasswordCredentialType
}

// TokenCredentials represents token-based authentication.
type TokenCredentials struct {
	Token string `json:"token" validate:"required"`
}

func (t TokenCredentials) Type() CredentialType {
	return TokenCredentialType
}

// APIKeyCredentials represents API key authentication.
type APIKeyCredentials struct {
	APIKey string `json:"api_key" validate:"required"`
}

func (a APIKeyCredentials) Type() CredentialType {
	return APIKeyCredentialType
}
