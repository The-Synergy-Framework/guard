package rbac

import (
	"context"
	"fmt"
	"strings"
	"time"

	"core/cache"
	"core/metrics"
	"guard"
)

type TenantResolver func(ctx context.Context) string

// Authorizer implements guard.Authorizer using an RBAC store.
type Authorizer struct {
	store         Store
	metrics       metrics.Registry
	resolveTenant TenantResolver

	// caches
	userRolesCache cache.Cache // key: t:{tenant}:u:{user} -> []string
	rolePermsCache cache.Cache // key: t:{tenant}:r:{role} -> []Permission
	userPermsCache cache.Cache // key: t:{tenant}:u:{user}:perm -> []Permission
}

// Options defines authorizer configuration.
type Options struct {
	Registry       metrics.Registry
	CacheTTL       time.Duration // default: 30s
	SlidingTTL     bool          // default: true
	TenantResolver TenantResolver
}

// NewAuthorizer creates a new RBAC authorizer.
func NewAuthorizer(store Store, opts ...Options) *Authorizer {
	var cfg Options
	if len(opts) > 0 {
		cfg = opts[0]
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 30 * time.Second
	}
	if cfg.TenantResolver == nil {
		cfg.TenantResolver = func(ctx context.Context) string {
			if cl, ok := guard.ClaimsFromContext(ctx); ok {
				return cl.TenantID
			}
			return ""
		}
	}

	newCache := func() cache.Cache {
		if cfg.SlidingTTL {
			return cache.NewMemory(cache.WithDefaultTTL(cfg.CacheTTL), cache.WithStats(), cache.WithSlidingTTL())
		}
		return cache.NewMemory(cache.WithDefaultTTL(cfg.CacheTTL), cache.WithStats())
	}

	return &Authorizer{
		store:          store,
		metrics:        cfg.Registry,
		resolveTenant:  cfg.TenantResolver,
		userRolesCache: newCache(),
		rolePermsCache: newCache(),
		userPermsCache: newCache(),
	}
}

func (a *Authorizer) getTenantID(ctx context.Context) string {
	return a.resolveTenant(ctx)
}

// Invalidate caches for specific entities.
func (a *Authorizer) InvalidateUser(ctx context.Context, userID string) {
	t := a.getTenantID(ctx)
	a.userRolesCache.Delete(fmt.Sprintf("t:%s:u:%s", t, userID))
	a.userPermsCache.Delete(fmt.Sprintf("t:%s:u:%s:perm", t, userID))
}

func (a *Authorizer) InvalidateRole(ctx context.Context, roleName string) {
	t := a.getTenantID(ctx)
	a.rolePermsCache.Delete(fmt.Sprintf("t:%s:r:%s", t, roleName))
}

// Authorize checks if user has permission resource:action via roles or direct grants.
func (a *Authorizer) Authorize(ctx context.Context, userID string, resource, action string) error {
	if userID == "" {
		return fmt.Errorf("missing userID")
	}
	tenant := a.getTenantID(ctx)
	// Build permission set
	perms := make(map[string]struct{})
	roles, err := a.GetUserRoles(ctx, userID)
	if err != nil {
		return err
	}
	for _, role := range roles {
		rps, err := a.getRolePermissions(ctx, tenant, role)
		if err != nil {
			return err
		}
		for _, p := range rps {
			perms[key(p.Resource, p.Action)] = struct{}{}
		}
	}
	dps, err := a.getUserPermissions(ctx, tenant, userID)
	if err != nil {
		return err
	}
	for _, p := range dps {
		perms[key(p.Resource, p.Action)] = struct{}{}
	}
	if match(perms, resource, action) {
		return nil
	}
	return fmt.Errorf("permission denied: %s:%s", resource, action)
}

// HasRole checks if user has the given role.
func (a *Authorizer) HasRole(ctx context.Context, userID string, role string) (bool, error) {
	roles, err := a.GetUserRoles(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, r := range roles {
		if r == role {
			return true, nil
		}
	}
	return false, nil
}

// HasPermission is derived from Authorize.
func (a *Authorizer) HasPermission(ctx context.Context, userID string, permission string) (bool, error) {
	s := strings.SplitN(permission, ":", 2)
	if len(s) != 2 {
		return false, fmt.Errorf("invalid permission format")
	}
	return a.Authorize(ctx, userID, s[0], s[1]) == nil, nil
}

// GetUserRoles returns roles for a user (cached).
func (a *Authorizer) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	tenant := a.getTenantID(ctx)
	ck := fmt.Sprintf("t:%s:u:%s", tenant, userID)
	if v, ok := a.userRolesCache.Get(ck); ok {
		return v.([]string), nil
	}
	roles, err := a.store.GetUserRoles(ctx, tenant, userID)
	if err != nil {
		return nil, err
	}
	a.userRolesCache.Set(ck, roles, 0)
	return roles, nil
}

// GetUserPermissions returns direct user permissions (cached).
func (a *Authorizer) GetUserPermissions(ctx context.Context, userID string) ([]string, error) {
	tenant := a.getTenantID(ctx)
	ck := fmt.Sprintf("t:%s:u:%s:perm", tenant, userID)
	if v, ok := a.userPermsCache.Get(ck); ok {
		return permsToStrings(v.([]Permission)), nil
	}
	perms, err := a.store.GetUserPermissions(ctx, tenant, userID)
	if err != nil {
		return nil, err
	}
	a.userPermsCache.Set(ck, perms, 0)
	return permsToStrings(perms), nil
}

func (a *Authorizer) getUserPermissions(ctx context.Context, tenant, userID string) ([]Permission, error) {
	ck := fmt.Sprintf("t:%s:u:%s:perm", tenant, userID)
	if v, ok := a.userPermsCache.Get(ck); ok {
		return v.([]Permission), nil
	}
	perms, err := a.store.GetUserPermissions(ctx, tenant, userID)
	if err != nil {
		return nil, err
	}
	a.userPermsCache.Set(ck, perms, 0)
	return perms, nil
}

func (a *Authorizer) getRolePermissions(ctx context.Context, tenant, role string) ([]Permission, error) {
	ck := fmt.Sprintf("t:%s:r:%s", tenant, role)
	if v, ok := a.rolePermsCache.Get(ck); ok {
		return v.([]Permission), nil
	}
	perms, err := a.store.GetRolePermissions(ctx, tenant, role)
	if err != nil {
		return nil, err
	}
	a.rolePermsCache.Set(ck, perms, 0)
	return perms, nil
}

func key(resource, action string) string { return resource + ":" + action }

func match(perms map[string]struct{}, resource, action string) bool {
	// Exact
	if _, ok := perms[key(resource, action)]; ok {
		return true
	}
	// Wildcards
	if _, ok := perms["*:*"]; ok {
		return true
	}
	if _, ok := perms[key(resource, "*")]; ok {
		return true
	}
	if _, ok := perms[key("*", action)]; ok {
		return true
	}
	return false
}

func permsToStrings(perms []Permission) []string {
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, key(p.Resource, p.Action))
	}
	return out
}
