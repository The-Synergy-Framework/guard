package rbac

import (
	"context"
	"sync"
)

type memoryStore struct {
	mu sync.RWMutex

	userRoles       map[string]map[string]struct{} // key: tenant|user -> role -> {}
	rolePermissions map[string]map[string]struct{} // key: tenant|role -> "res:act" -> {}
	userPermissions map[string]map[string]struct{} // key: tenant|user -> "res:act" -> {}
	roles           map[string]struct{}            // key: tenant|role -> {}
}

// NewMemoryStore creates an in-memory RBAC store.
func NewMemoryStore() Store {
	return &memoryStore{
		userRoles:       make(map[string]map[string]struct{}),
		rolePermissions: make(map[string]map[string]struct{}),
		userPermissions: make(map[string]map[string]struct{}),
		roles:           make(map[string]struct{}),
	}
}

func key2(a, b string) string { return a + "|" + b }

func (s *memoryStore) AssignRole(ctx context.Context, tenantID, userID, roleName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key2(tenantID, userID)
	if s.userRoles[k] == nil {
		s.userRoles[k] = make(map[string]struct{})
	}
	s.userRoles[k][roleName] = struct{}{}
	return nil
}

func (s *memoryStore) RevokeRole(ctx context.Context, tenantID, userID, roleName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key2(tenantID, userID)
	if s.userRoles[k] != nil {
		delete(s.userRoles[k], roleName)
	}
	return nil
}

func (s *memoryStore) GetUserRoles(ctx context.Context, tenantID, userID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k := key2(tenantID, userID)
	var out []string
	for r := range s.userRoles[k] {
		out = append(out, r)
	}
	return out, nil
}

func (s *memoryStore) UpsertRole(ctx context.Context, tenantID, roleName, description string, isActive bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key2(tenantID, roleName)
	s.roles[k] = struct{}{}
	return nil
}

func (s *memoryStore) DeleteRole(ctx context.Context, tenantID, roleName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key2(tenantID, roleName)
	delete(s.roles, k)
	delete(s.rolePermissions, k)
	return nil
}

func (s *memoryStore) GrantPermissionToRole(ctx context.Context, tenantID, roleName, resource, action string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key2(tenantID, roleName)
	if s.rolePermissions[k] == nil {
		s.rolePermissions[k] = make(map[string]struct{})
	}
	s.rolePermissions[k][resource+":"+action] = struct{}{}
	return nil
}

func (s *memoryStore) RevokePermissionFromRole(ctx context.Context, tenantID, roleName, resource, action string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key2(tenantID, roleName)
	if s.rolePermissions[k] != nil {
		delete(s.rolePermissions[k], resource+":"+action)
	}
	return nil
}

func (s *memoryStore) GetRolePermissions(ctx context.Context, tenantID, roleName string) ([]Permission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k := key2(tenantID, roleName)
	var out []Permission
	for ra := range s.rolePermissions[k] {
		parts := ra
		// split once
		i := -1
		for idx := 0; idx < len(parts); idx++ {
			if parts[idx] == ':' {
				i = idx
				break
			}
		}
		if i > 0 {
			out = append(out, Permission{Resource: parts[:i], Action: parts[i+1:]})
		}
	}
	return out, nil
}

func (s *memoryStore) GrantPermissionToUser(ctx context.Context, tenantID, userID, resource, action string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key2(tenantID, userID)
	if s.userPermissions[k] == nil {
		s.userPermissions[k] = make(map[string]struct{})
	}
	s.userPermissions[k][resource+":"+action] = struct{}{}
	return nil
}

func (s *memoryStore) RevokePermissionFromUser(ctx context.Context, tenantID, userID, resource, action string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key2(tenantID, userID)
	if s.userPermissions[k] != nil {
		delete(s.userPermissions[k], resource+":"+action)
	}
	return nil
}

func (s *memoryStore) GetUserPermissions(ctx context.Context, tenantID, userID string) ([]Permission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k := key2(tenantID, userID)
	var out []Permission
	for ra := range s.userPermissions[k] {
		parts := ra
		i := -1
		for idx := 0; idx < len(parts); idx++ {
			if parts[idx] == ':' {
				i = idx
				break
			}
		}
		if i > 0 {
			out = append(out, Permission{Resource: parts[:i], Action: parts[i+1:]})
		}
	}
	return out, nil
}
