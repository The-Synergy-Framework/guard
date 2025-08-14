package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

// A minimal PKCS1 RSA private key for tests (generated for testing only)
const dummyRSAPrivate = `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKkq3j0UQb6qU3q8zk8eFhGYEJ0Yb+U3O1mX7j0HMQqY0pQ8s7iZ
qVQK9d8x8m7y6b7S2vH+2l4b4mV6H1K0oXECAwEAAQJATCwEo7XJb7XWZt7m9C0l
8i1m4s8+3k6t1x5Qq3CwYQz1gW7k3v9bkYv0Qd6zBqz2q4N8pZf4lJ2XlDq9kQuk
4QIhAPJq3d0+oM8CwNgG4C8KQK9m8o2Yt4a7dYkX8m0b6FZNAiEAu1eQy0m2+0iA
Qy9Tz2mK8H6u3vQe5b+GmZ+qVql8gPMCIQC1uKkzVxv8kSg7mE6mO5mV4p5a9t4P
Ih6E1nXG1+g8oQIhALl0y8m+1H3S4mDZa5uQx8hX1Yx7wQ2YwJmF3nH8e7sRAiEA
o8s0y3mH9yH7l9C3r2Y5c3Yd2q2v6x2p4R9qXcWj1z8=
-----END RSA PRIVATE KEY-----`

func TestManager_HS256(t *testing.T) {
	m, err := NewManager(Config{
		SecretKey:          "test-secret",
		Algorithm:          HS256,
		AccessTokenExpiry:  time.Minute,
		RefreshTokenExpiry: time.Hour,
		Issuer:             "test-issuer",
		Audience:           "test-aud",
	})
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}

	tests := []struct {
		name    string
		userID  string
		roles   []string
		perms   []string
		invalid bool
	}{
		{name: "admin all", userID: "u1", roles: []string{"admin"}, perms: []string{"*"}},
		{name: "user basic", userID: "u2", roles: []string{"user"}, perms: []string{"profile:read"}},
		{name: "invalid token string", invalid: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.invalid {
				if _, err := m.ValidateToken("not-a-jwt"); err == nil {
					t.Fatalf("expected error for invalid token")
				}
				return
			}

			pair, err := m.GenerateTokens(tt.userID, tt.roles, tt.perms)
			if err != nil {
				t.Fatalf("GenerateTokens error: %v", err)
			}
			if pair.AccessToken == "" || pair.RefreshToken == "" {
				t.Fatalf("expected non-empty tokens")
			}

			claims, err := m.ValidateToken(pair.AccessToken)
			if err != nil {
				t.Fatalf("ValidateToken error: %v", err)
			}
			if claims.UserID != tt.userID || !claims.IsAccessToken() {
				t.Fatalf("unexpected claims: %+v", claims)
			}

			parsed, err := m.ParseToken(pair.AccessToken)
			if err != nil || parsed.TokenID == "" {
				t.Fatalf("ParseToken failed: %v, claims=%+v", err, parsed)
			}
		})
	}
}

func TestManager_RS256_GenerateAndValidate(t *testing.T) {
	// Generate RSA key for test
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pkcs1 := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs1})

	m, err := NewManager(Config{
		PrivateKey:         string(pemBytes),
		Algorithm:          RS256,
		AccessTokenExpiry:  time.Minute,
		RefreshTokenExpiry: time.Hour,
		Issuer:             "iss",
		Audience:           "aud",
	})
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}

	pair, err := m.GenerateTokens("rs-user", nil, nil)
	if err != nil {
		t.Fatalf("GenerateTokens error: %v", err)
	}

	claims, err := m.ValidateToken(pair.AccessToken)
	if err != nil || claims.UserID != "rs-user" || !claims.IsAccessToken() {
		t.Fatalf("validate failed: %v %+v", err, claims)
	}
}

func TestManager_RS256_WithDummyKey(t *testing.T) {
	m, err := NewManager(Config{
		PrivateKey:         dummyRSAPrivate,
		Algorithm:          RS256,
		AccessTokenExpiry:  time.Minute,
		RefreshTokenExpiry: time.Hour,
		Issuer:             "test-issuer",
		Audience:           "test-aud",
	})
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}

	pair, err := m.GenerateTokens("dummy-user", []string{"user"}, []string{"read"})
	if err != nil {
		t.Fatalf("GenerateTokens error: %v", err)
	}

	claims, err := m.ValidateToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken error: %v", err)
	}
	if claims.UserID != "dummy-user" || !claims.IsAccessToken() {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestManager_InvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "missing algorithm",
			cfg: Config{
				SecretKey:          "test-secret",
				AccessTokenExpiry:  time.Minute,
				RefreshTokenExpiry: time.Hour,
			},
		},
		{
			name: "HS256 missing secret key",
			cfg: Config{
				Algorithm:          HS256,
				AccessTokenExpiry:  time.Minute,
				RefreshTokenExpiry: time.Hour,
			},
		},
		{
			name: "RS256 missing private key",
			cfg: Config{
				Algorithm:          RS256,
				AccessTokenExpiry:  time.Minute,
				RefreshTokenExpiry: time.Hour,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewManager(tt.cfg)
			if err == nil {
				t.Fatalf("expected error for invalid config")
			}
		})
	}
}

func TestManager_TokenExpiry(t *testing.T) {
	m, err := NewManager(Config{
		SecretKey:          "test-secret",
		Algorithm:          HS256,
		AccessTokenExpiry:  time.Millisecond * 10, // Very short expiry
		RefreshTokenExpiry: time.Millisecond * 20,
		Issuer:             "test-issuer",
		Audience:           "test-aud",
	})
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}

	pair, err := m.GenerateTokens("expiry-user", nil, nil)
	if err != nil {
		t.Fatalf("GenerateTokens error: %v", err)
	}

	// Token should be valid immediately
	_, err = m.ValidateToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("Token should be valid immediately: %v", err)
	}

	// Wait for token to expire
	time.Sleep(time.Millisecond * 15)

	// Token should now be expired
	_, err = m.ValidateToken(pair.AccessToken)
	if err == nil {
		t.Fatalf("Token should be expired")
	}
}
