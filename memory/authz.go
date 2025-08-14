package memory

import (
	"context"
	"fmt"

	"guard"
)

// Implement Authorizer interface

// Authorize checks if a user has permission to perform an action on a resource.
func (s *Service) Authorize(ctx context.Context, userID string, resource, action string) error {
	permissions, err := s.GetUserPermissions(ctx, userID)
	if err != nil {
		return err
	}

	requiredPerm := resource + ":" + action
	for _, perm := range permissions {
		if perm == requiredPerm || perm == "*" || perm == resource+":*" {
			return nil
		}
	}

	return fmt.Errorf("%w: %s requires %s", guard.ErrPermissionDenied, userID, requiredPerm)
}

// HasRole checks if a user has a specific role.
func (s *Service) HasRole(ctx context.Context, userID string, role string) (bool, error) {
	s.mu.RLock()
	userRoles, exists := s.userRoles[userID]
	s.mu.RUnlock()

	if !exists {
		return false, guard.ErrUserNotFound
	}

	for _, r := range userRoles {
		if r == role {
			return true, nil
		}
	}

	return false, nil
}

// HasPermission checks if a user has a specific permission.
func (s *Service) HasPermission(ctx context.Context, userID string, permission string) (bool, error) {
	permissions, err := s.GetUserPermissions(ctx, userID)
	if err != nil {
		return false, err
	}

	for _, perm := range permissions {
		if perm == permission || perm == "*" {
			return true, nil
		}
	}

	return false, nil
}

// GetUserRoles returns all roles for a user.
func (s *Service) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	s.mu.RLock()
	roles, exists := s.userRoles[userID]
	s.mu.RUnlock()

	if !exists {
		return nil, guard.ErrUserNotFound
	}

	// Return a copy to prevent external modification
	result := make([]string, len(roles))
	copy(result, roles)
	return result, nil
}

// GetUserPermissions returns all permissions for a user.
func (s *Service) GetUserPermissions(ctx context.Context, userID string) ([]string, error) {
	roles, err := s.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	permSet := make(map[string]bool)
	for _, roleName := range roles {
		if permissions, exists := s.rolePerms[roleName]; exists {
			for _, perm := range permissions {
				permSet[perm] = true
			}
		}
	}

	result := make([]string, 0, len(permSet))
	for perm := range permSet {
		result = append(result, perm)
	}

	return result, nil
}
