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
MIICXAIBAAKBgQDAqx4hMzdzia3ZUb2hgfZb8KX4dJzvHpCPS9YS4+OYwD+U6vdT
k5JUrHrkCcHvfQENLCp8w/S7zY+t/x28JytJisNEmX0rcbcTkwzLS1fdbRsNAXPu
0aYTMKbKuKYumdcu10NQA1eyxgb6L/lhDj7VRhtSrKUCvSNYUqik2koLUwIDAQAB
AoGAL3a4UHN+mJ71ThE+BxiuKU4qhP+tXZcJA9Qp47NycUIDJ9uOnG9BYEyxZZYl
yarg5G7Z9KyNkOp+F94+ZAi+N8ytCfSWGZxEAjcR9NsfGVptsdQ8bWZGh9SAdpjJ
eTRYyue5L/ah4HnIAHSLCdtlIagx2UDR2mSXBBmdxWI5Z5ECQQD49AvV7enUfxQR
dZ8oPAeeqEEbLcVvB9Oywmwxnl+EHwAp4PFO4OdaHe9v55FF+zI+vTg5qtUsu1Vn
Qx7oT09bAkEAxh84/ejvufTWyTXxVzqm/YJY8UIn4jL2bOfCzHrg1LVrWeY8ZQ7n
BFRSbY+4Xxr6/o8v9J3gBQ379uT55wataQJAR6tiWOUUIwOukFQvTJLzkp5Xl+52
Xz9+l4DXSvWQA+Y00tmaPp4KnGvvyWR98wqc7Wjl7dwbYLRRote05yYl7wJAMW+f
B/R0xQDsC18TboGrI3y/9stcKlwvEzOtbtqGeW0fcVo63bifOnxT6RTAm7KeyKAw
BijSulAn/A5csSIAaQJBAMX8JsG6HqkTPu3V+Z6mMR238bbTFrNkA6xQXpfaFFJf
5jMgVR08ctfOs2b+cShoAauG9jMDE6f7l3lCN4HRKTA=
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
		AccessTokenExpiry:  time.Second * 1, // 1 second expiry
		RefreshTokenExpiry: time.Second * 2,
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
	time.Sleep(time.Second + time.Millisecond*100)

	// Token should now be expired
	_, err = m.ValidateToken(pair.AccessToken)
	if err == nil {
		t.Fatalf("Token should be expired")
	}
}
