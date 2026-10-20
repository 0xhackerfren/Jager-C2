package auth

import (
	"testing"

	"go.uber.org/zap"
)

func allPermissions() []Permission {
	seen := make(map[Permission]bool)
	var perms []Permission
	for _, list := range RolePermissions {
		for _, p := range list {
			if !seen[p] {
				seen[p] = true
				perms = append(perms, p)
			}
		}
	}
	return perms
}

func TestAdminHasAllPerms(t *testing.T) {
	am := NewAuthManager(zap.NewNop())
	admin := am.RegisterOperatorByName("admin", RoleAdmin)

	for _, perm := range allPermissions() {
		if !am.Authorize(admin, perm) {
			t.Fatalf("admin denied permission %q", perm)
		}
	}
}

func TestViewerDeniedMutating(t *testing.T) {
	am := NewAuthManager(zap.NewNop())
	viewer := am.RegisterOperatorByName("viewer", RoleViewer)

	mutating := []Permission{PermTaskCreate, PermSessionKill}
	for _, perm := range mutating {
		if am.Authorize(viewer, perm) {
			t.Fatalf("viewer should be denied %q", perm)
		}
	}
}

func TestNilOperatorDenied(t *testing.T) {
	am := NewAuthManager(zap.NewNop())
	if am.Authorize(nil, PermTaskCreate) {
		t.Fatal("nil operator should be denied")
	}
}
