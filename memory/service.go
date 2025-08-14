package memory

import (
	"fmt"
	"sync"
	"time"

	"core/cache"
	"guard"
	"guard/jwt"
)

// Service implements all Guard interfaces using in-memory storage.
type Service struct {
	config Config

	// JWT manager
	jwtManager *jwt.Manager

	// Token blacklist (using Synergy cache)
	tokenBlacklist cache.Cache

	// In-memory storage
	mu           sync.RWMutex
	users        map[string]*guard.User // userID -> User
	usersByName  map[string]string      // username -> userID
	usersByEmail map[string]string      // email -> userID
	roles        map[string]*guard.Role // roleName -> Role
	userRoles    map[string][]string    // userID -> []roleName
	rolePerms    map[string][]string    // roleName -> []permission
}

// NewService creates a new in-memory service with the given configuration.
func NewService(config Config) (*Service, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Create JWT manager
	jwtConfig := jwt.Config{
		SecretKey:          config.JWTSecretKey,
		Algorithm:          config.JWTAlgorithm,
		AccessTokenExpiry:  config.AccessTokenExpiry,
		RefreshTokenExpiry: config.RefreshTokenExpiry,
		Issuer:             config.JWTIssuer,
		Audience:           config.JWTAudience,
	}

	jwtManager, err := jwt.NewManager(jwtConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT manager: %w", err)
	}

	// Create token blacklist cache
	tokenBlacklist := cache.NewMemory(
		cache.WithDefaultTTL(config.TokenCacheTTL),
		cache.WithStats(),
	)

	service := &Service{
		config:         config,
		jwtManager:     jwtManager,
		tokenBlacklist: tokenBlacklist,
		users:          make(map[string]*guard.User),
		usersByName:    make(map[string]string),
		usersByEmail:   make(map[string]string),
		roles:          make(map[string]*guard.Role),
		userRoles:      make(map[string][]string),
		rolePerms:      make(map[string][]string),
	}

	// Create default roles
	service.createDefaultRoles()

	return service, nil
}

// createDefaultRoles creates default system roles.
func (s *Service) createDefaultRoles() {
	defaultRoles := []struct {
		name        string
		description string
		permissions []string
	}{
		{
			name:        "admin",
			description: "System administrator with full access",
			permissions: []string{"*"},
		},
		{
			name:        "user",
			description: "Regular user with basic permissions",
			permissions: []string{"profile:read", "profile:write"},
		},
	}

	for _, role := range defaultRoles {
		s.roles[role.name] = &guard.Role{
			Name:        role.name,
			Description: role.description,
			Permissions: role.permissions,
			IsActive:    true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		s.rolePerms[role.name] = role.permissions
	}
}
