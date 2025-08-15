package rbac

import "context"

// Store defines the persistence interface for RBAC data.
type Store interface {
	// Role assignments
	AssignRole(ctx context.Context, tenantID, userID, roleName string) error
	RevokeRole(ctx context.Context, tenantID, userID, roleName string) error
	GetUserRoles(ctx context.Context, tenantID, userID string) ([]string, error)

	// Role permissions
	UpsertRole(ctx context.Context, tenantID, roleName, description string, isActive bool) error
	DeleteRole(ctx context.Context, tenantID, roleName string) error
	GrantPermissionToRole(ctx context.Context, tenantID, roleName, resource, action string) error
	RevokePermissionFromRole(ctx context.Context, tenantID, roleName, resource, action string) error
	GetRolePermissions(ctx context.Context, tenantID, roleName string) ([]Permission, error)

	// Direct user permissions (optional)
	GrantPermissionToUser(ctx context.Context, tenantID, userID, resource, action string) error
	RevokePermissionFromUser(ctx context.Context, tenantID, userID, resource, action string) error
	GetUserPermissions(ctx context.Context, tenantID, userID string) ([]Permission, error)
}

// Permission represents a resource-action pair.
type Permission struct {
	Resource string
	Action   string
}
