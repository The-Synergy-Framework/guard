package jwt

import (
	"testing"
	"time"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{name: "ok hs256", cfg: Config{SecretKey: "k", Algorithm: HS256, AccessTokenExpiry: time.Minute, RefreshTokenExpiry: time.Hour}},
		{name: "ok rs256 missing public", cfg: Config{PrivateKey: dummyRSAPrivate, Algorithm: RS256, AccessTokenExpiry: time.Minute, RefreshTokenExpiry: time.Hour}},
		{name: "missing algo", cfg: Config{SecretKey: "k", AccessTokenExpiry: time.Minute, RefreshTokenExpiry: time.Hour}, wantErr: true},
		{name: "bad algo", cfg: Config{SecretKey: "k", Algorithm: Algorithm("BAD"), AccessTokenExpiry: time.Minute, RefreshTokenExpiry: time.Hour}, wantErr: true},
		{name: "hs256 missing secret", cfg: Config{Algorithm: HS256, AccessTokenExpiry: time.Minute, RefreshTokenExpiry: time.Hour}, wantErr: true},
		{name: "rs256 missing private", cfg: Config{Algorithm: RS256, AccessTokenExpiry: time.Minute, RefreshTokenExpiry: time.Hour}, wantErr: true},
		{name: "nonpositive access", cfg: Config{SecretKey: "k", Algorithm: HS256, AccessTokenExpiry: 0, RefreshTokenExpiry: time.Hour}, wantErr: true},
		{name: "nonpositive refresh", cfg: Config{SecretKey: "k", Algorithm: HS256, AccessTokenExpiry: time.Minute, RefreshTokenExpiry: 0}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
		})
	}
}
