// Package oidc provides a generic OpenID Connect provider adapter.
package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"core/cache"
	"core/metrics"
	"guard"
	"guard/adapter"

	"github.com/golang-jwt/jwt/v5"
)

// Config holds OIDC configuration.
type Config struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string // optional
	Audience     string // optional; if empty, defaults to ClientID

	AllowedAlgs      []string // e.g., ["RS256"]. If empty, defaults to ["RS256"].
	RoleClaim        string   // e.g., "roles", "realm_access.roles". Default tries common claims.
	PermissionsClaim string   // e.g., "permissions" or space-delimited "scope". Default tries both.

	HTTPTimeout       time.Duration // default 10s
	DiscoveryCacheTTL time.Duration // default 1h
	JWKSCacheTTL      time.Duration // default 30m
	ClaimsCacheTTL    time.Duration // default 15m
	ClockSkewLeeway   time.Duration // default 2s
}

// Provider implements adapter.Provider using OIDC.
type Provider struct {
	*adapter.BaseAdapter
	config Config
	client *http.Client

	discoveryCache cache.Cache // issuer -> discovery
	jwksCache      cache.Cache // issuer -> jwks
	claimsCache    cache.Cache // key: iss|userID -> *guard.Claims
}

// New creates a new OIDC provider.
func New(registry metrics.Registry, cfg Config, opts ...adapter.Option) (*Provider, error) {
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("issuer URL is required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("client ID is required")
	}
	if cfg.AllowedAlgs == nil || len(cfg.AllowedAlgs) == 0 {
		cfg.AllowedAlgs = []string{"RS256"}
	}
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 10 * time.Second
	}
	if cfg.DiscoveryCacheTTL == 0 {
		cfg.DiscoveryCacheTTL = time.Hour
	}
	if cfg.JWKSCacheTTL == 0 {
		cfg.JWKSCacheTTL = 30 * time.Minute
	}
	if cfg.ClaimsCacheTTL == 0 {
		cfg.ClaimsCacheTTL = 15 * time.Minute
	}
	if cfg.Audience == "" {
		cfg.Audience = cfg.ClientID
	}
	if cfg.ClockSkewLeeway == 0 {
		cfg.ClockSkewLeeway = 2 * time.Second
	}

	base, err := adapter.NewBaseAdapter("oidc", registry, opts...)
	if err != nil {
		return nil, err
	}

	p := &Provider{
		BaseAdapter:    base,
		config:         cfg,
		client:         &http.Client{Timeout: cfg.HTTPTimeout},
		discoveryCache: cache.NewMemory(cache.WithDefaultTTL(cfg.DiscoveryCacheTTL), cache.WithStats()),
		jwksCache:      cache.NewMemory(cache.WithDefaultTTL(cfg.JWKSCacheTTL), cache.WithStats()),
		claimsCache:    cache.NewMemory(cache.WithDefaultTTL(cfg.ClaimsCacheTTL), cache.WithStats()),
	}
	return p, nil
}

// Name returns provider name.
func (p *Provider) Name() string { return "oidc" }

// ValidateToken validates a JWT and returns claims.
func (p *Provider) ValidateToken(ctx context.Context, token string) (*guard.Claims, error) {
	return p.BaseAdapter.ValidateTokenWithCache(ctx, token, func(ctx context.Context, t string) (*guard.Claims, error) {
		return p.validateJWT(ctx, t)
	})
}

// GenerateTokens is not implemented for generic OIDC.
func (p *Provider) GenerateTokens(ctx context.Context, userID string) (*guard.TokenPair, error) {
	return nil, adapter.NewProviderError(p.Name(), "generate_tokens", adapter.ErrProviderMisconfigured)
}

// RefreshTokens is not implemented for generic OIDC.
func (p *Provider) RefreshTokens(ctx context.Context, refreshToken string) (*guard.TokenPair, error) {
	return nil, adapter.NewProviderError(p.Name(), "refresh_tokens", adapter.ErrProviderMisconfigured)
}

// RevokeTokens is not implemented for generic OIDC.
func (p *Provider) RevokeTokens(ctx context.Context, accessToken, refreshToken string) error {
	return adapter.NewProviderError(p.Name(), "revoke_tokens", adapter.ErrProviderMisconfigured)
}

// GetUser returns a user from cached claims if available, otherwise minimal user.
func (p *Provider) GetUser(ctx context.Context, userID string) (*guard.User, error) {
	if v, ok := p.claimsCache.Get(p.claimsCacheKeyFromContext(ctx, userID)); ok {
		cl := v.(*guard.Claims)
		return claimsToUser(cl), nil
	}
	// Minimal user fallback
	return &guard.User{ID: userID, Username: userID, CreatedAt: time.Now(), UpdatedAt: time.Now()}, nil
}

// HasRole checks if cached claims include the role.
func (p *Provider) HasRole(ctx context.Context, userID, role string) (bool, error) {
	if v, ok := p.claimsCache.Get(p.claimsCacheKeyFromContext(ctx, userID)); ok {
		cl := v.(*guard.Claims)
		for _, r := range cl.Roles {
			if r == role {
				return true, nil
			}
		}
	}
	return false, nil
}

// Authorize checks permission against cached claims (roles/permissions/scopes).
func (p *Provider) Authorize(ctx context.Context, userID, resource, action string) error {
	if v, ok := p.claimsCache.Get(p.claimsCacheKeyFromContext(ctx, userID)); ok {
		cl := v.(*guard.Claims)
		// Check permissions list first
		perm := resource + ":" + action
		for _, pstr := range cl.Permissions {
			if pstr == perm || pstr == "*:*" || (strings.HasPrefix(pstr, resource+":") && action == "*") {
				return nil
			}
		}
		// Check roles as fallback (e.g., admin)
		for _, r := range cl.Roles {
			if r == "admin" {
				return nil
			}
		}
	}
	return adapter.NewProviderError(p.Name(), "authorize", adapter.ErrProviderInvalidResponse)
}

// internal: validate JWT using discovery and JWKS.
func (p *Provider) validateJWT(ctx context.Context, tokenString string) (*guard.Claims, error) {
	discovery, err := p.getDiscovery(ctx)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		// Algorithm check
		alg := t.Method.Alg()
		if !contains(p.config.AllowedAlgs, alg) {
			return nil, fmt.Errorf("unsupported alg: %s", alg)
		}
		kid, _ := t.Header["kid"].(string)
		pubKey, err := p.getPublicKey(ctx, discovery.JWKSURI, kid, alg)
		if err != nil {
			return nil, err
		}
		return pubKey, nil
	})
	if err != nil || !token.Valid {
		return nil, adapter.NewProviderError(p.Name(), "validate_token", adapter.ErrProviderInvalidResponse)
	}

	claimsMap, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, adapter.NewProviderError(p.Name(), "claims_parse", adapter.ErrProviderInvalidResponse)
	}

	// Validate iss and aud
	if iss, _ := claimsMap["iss"].(string); iss != p.config.IssuerURL {
		return nil, adapter.NewProviderError(p.Name(), "iss_mismatch", adapter.ErrProviderInvalidResponse)
	}
	if !audContains(claimsMap["aud"], p.config.Audience) {
		return nil, adapter.NewProviderError(p.Name(), "aud_mismatch", adapter.ErrProviderInvalidResponse)
	}

	// Validate exp/nbf/iat with leeway
	now := time.Now().UTC()
	leeway := p.config.ClockSkewLeeway
	if exp, ok := numToTime(claimsMap["exp"]); ok {
		if now.After(exp.Add(leeway)) {
			return nil, adapter.NewProviderError(p.Name(), "token_expired", adapter.ErrProviderInvalidResponse)
		}
	}
	if nbf, ok := numToTime(claimsMap["nbf"]); ok {
		if now.Add(leeway).Before(nbf) {
			return nil, adapter.NewProviderError(p.Name(), "token_not_yet_valid", adapter.ErrProviderInvalidResponse)
		}
	}
	if iat, ok := numToTime(claimsMap["iat"]); ok {
		if iat.After(now.Add(leeway)) {
			return nil, adapter.NewProviderError(p.Name(), "token_issued_in_future", adapter.ErrProviderInvalidResponse)
		}
	}

	// Map to guard.Claims
	claims := mapClaimsToGuardClaims(claimsMap)
	// Extract roles/permissions
	claims.Roles = extractRoles(claimsMap, p.config.RoleClaim)
	claims.Permissions = extractPermissions(claimsMap, p.config.PermissionsClaim)

	// Cache claims by issuer+userID for role/permission checks
	if claims.UserID != "" {
		p.claimsCache.Set(p.claimsCacheKey(claims.Issuer, claims.UserID), claims, p.config.ClaimsCacheTTL)
	}
	return claims, nil
}

// Discovery document
type discoveryDoc struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

func (p *Provider) getDiscovery(ctx context.Context) (*discoveryDoc, error) {
	if v, ok := p.discoveryCache.Get(p.config.IssuerURL); ok {
		return v.(*discoveryDoc), nil
	}
	url := strings.TrimRight(p.config.IssuerURL, "/") + "/.well-known/openid-configuration"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, adapter.NewProviderError(p.Name(), "discovery", adapter.ErrProviderNotAvailable)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, adapter.NewProviderError(p.Name(), "discovery_status", adapter.ErrProviderInvalidResponse)
	}
	var doc discoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, adapter.NewProviderError(p.Name(), "discovery_decode", adapter.ErrProviderInvalidResponse)
	}
	if doc.JWKSURI == "" {
		return nil, adapter.NewProviderError(p.Name(), "discovery_missing_jwks", adapter.ErrProviderInvalidResponse)
	}
	p.discoveryCache.Set(p.config.IssuerURL, &doc, p.config.DiscoveryCacheTTL)
	return &doc, nil
}

// JWKS
type jwks struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (p *Provider) getPublicKey(ctx context.Context, jwksURI, kid, alg string) (any, error) {
	var keys *jwks
	if v, ok := p.jwksCache.Get(jwksURI); ok {
		keys = v.(*jwks)
	} else {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
		resp, err := p.client.Do(req)
		if err != nil {
			return nil, adapter.NewProviderError(p.Name(), "jwks_fetch", adapter.ErrProviderNotAvailable)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, adapter.NewProviderError(p.Name(), "jwks_status", adapter.ErrProviderInvalidResponse)
		}
		var k jwks
		if err := json.NewDecoder(resp.Body).Decode(&k); err != nil {
			return nil, adapter.NewProviderError(p.Name(), "jwks_decode", adapter.ErrProviderInvalidResponse)
		}
		keys = &k
		p.jwksCache.Set(jwksURI, keys, p.config.JWKSCacheTTL)
	}

	for _, key := range keys.Keys {
		if key.Kid != kid {
			continue
		}
		switch key.Kty {
		case "RSA":
			pub, err := rsaFromJWK(key)
			if err != nil {
				return nil, adapter.NewProviderError(p.Name(), "jwks_parse", adapter.ErrProviderInvalidResponse)
			}
			return pub, nil
		case "EC":
			pub, err := ecdsaFromJWK(key)
			if err != nil {
				return nil, adapter.NewProviderError(p.Name(), "jwks_parse", adapter.ErrProviderInvalidResponse)
			}
			return pub, nil
		}
	}
	return nil, adapter.NewProviderError(p.Name(), "jwks_kid_not_found", adapter.ErrProviderInvalidResponse)
}

func rsaFromJWK(k jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func ecdsaFromJWK(k jwkKey) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, err
	}
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", k.Crv)
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// helpers
func contains(arr []string, v string) bool {
	for _, s := range arr {
		if s == v {
			return true
		}
	}
	return false
}

func audContains(aud any, required string) bool {
	switch v := aud.(type) {
	case string:
		return v == required
	case []any:
		for _, x := range v {
			if xs, ok := x.(string); ok && xs == required {
				return true
			}
		}
	}
	return false
}

func mapClaimsToGuardClaims(m jwt.MapClaims) *guard.Claims {
	claims := &guard.Claims{}
	if sub, _ := m["sub"].(string); sub != "" {
		claims.UserID = sub
		claims.Subject = sub
	}
	if usr, _ := m["preferred_username"].(string); usr != "" {
		claims.Username = usr
	}
	if email, _ := m["email"].(string); email != "" {
		claims.Email = email
	}
	if iss, _ := m["iss"].(string); iss != "" {
		claims.Issuer = iss
	}
	if aud, ok := m["aud"]; ok {
		switch v := aud.(type) {
		case string:
			claims.Audience = v
		case []any:
			if len(v) > 0 {
				if s, ok := v[0].(string); ok {
					claims.Audience = s
				}
			}
		}
	}
	if exp, ok := numToTime(m["exp"]); ok {
		claims.ExpiresAt = exp
	}
	if iat, ok := numToTime(m["iat"]); ok {
		claims.IssuedAt = iat
	}
	if nbf, ok := numToTime(m["nbf"]); ok {
		claims.NotBefore = nbf
	}
	claims.TokenType = "access"
	return claims
}

func numToTime(v any) (time.Time, bool) {
	switch x := v.(type) {
	case float64:
		return time.Unix(int64(x), 0).UTC(), true
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return time.Unix(i, 0).UTC(), true
		}
	}
	return time.Time{}, false
}

func extractRoles(m jwt.MapClaims, roleClaim string) []string {
	if roleClaim != "" {
		if roles := getStringSlice(m, roleClaim); len(roles) > 0 {
			return roles
		}
	}
	// common places
	if roles := getStringSlice(m, "roles"); len(roles) > 0 {
		return roles
	}
	if realm, ok := m["realm_access"].(map[string]any); ok {
		if rs, ok := realm["roles"].([]any); ok {
			return toStringSlice(rs)
		}
	}
	if groups := getStringSlice(m, "groups"); len(groups) > 0 {
		return groups
	}
	return nil
}

func extractPermissions(m jwt.MapClaims, permClaim string) []string {
	if permClaim != "" {
		if perms := getStringSlice(m, permClaim); len(perms) > 0 {
			return perms
		}
	}
	// try scope
	if scope, _ := m["scope"].(string); scope != "" {
		return strings.Fields(scope)
	}
	return nil
}

func getStringSlice(m jwt.MapClaims, path string) []string {
	// support simple and one dot level e.g., "realm_access.roles"
	if !strings.Contains(path, ".") {
		if v, ok := m[path]; ok {
			return toStringSliceAny(v)
		}
		return nil
	}
	parts := strings.Split(path, ".")
	cur := any(m)
	for _, p := range parts {
		sw, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = sw[p]
		if !ok {
			return nil
		}
	}
	return toStringSliceAny(cur)
}

func toStringSliceAny(v any) []string {
	switch vv := v.(type) {
	case []any:
		return toStringSlice(vv)
	case []string:
		return vv
	}
	return nil
}

func toStringSlice(v []any) []string {
	out := make([]string, 0, len(v))
	for _, x := range v {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func claimsToUser(c *guard.Claims) *guard.User {
	return &guard.User{
		ID:          c.UserID,
		Username:    c.Username,
		Email:       c.Email,
		Roles:       c.Roles,
		Permissions: c.Permissions,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

func (p *Provider) claimsCacheKey(issuer, userID string) string {
	return issuer + "|" + userID
}

func (p *Provider) claimsCacheKeyFromContext(ctx context.Context, userID string) string {
	if cl, ok := guard.ClaimsFromContext(ctx); ok {
		iss := cl.Issuer
		if iss == "" {
			iss = p.config.IssuerURL
		}
		return p.claimsCacheKey(iss, userID)
	}
	return p.claimsCacheKey(p.config.IssuerURL, userID)
}
