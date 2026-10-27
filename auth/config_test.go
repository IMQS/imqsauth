package imqsauth

import (
	"strings"
	"testing"

	"github.com/IMQS/authaus"
)

// snapshotPermissionTables captures the current global permission tables so
// a test can mutate them and then restore the originals afterwards. This is
// necessary because PermissionsTable/PermissionModuleMap are shared global
// state that other tests in this package rely on being in their default
// (package-init'd) state.
func snapshotPermissionTables() (authaus.PermissionNameTable, map[string]authaus.PermissionU16) {
	tableCopy := authaus.PermissionNameTable{}
	for k, v := range PermissionsTable {
		tableCopy[k] = v
	}
	moduleCopy := map[string]authaus.PermissionU16{}
	for k, v := range PermissionModuleMap {
		moduleCopy[k] = v
	}
	return tableCopy, moduleCopy
}

func restorePermissionTables(table authaus.PermissionNameTable, moduleMap map[string]authaus.PermissionU16) {
	PermissionsTable = authaus.PermissionNameTable{}
	for k, v := range table {
		PermissionsTable[k] = v
	}
	PermissionModuleMap = map[string]authaus.PermissionU16{}
	for k, v := range moduleMap {
		PermissionModuleMap[k] = v
	}
}

func TestLoadDynamicPermissions_RejectsDuplicateIdAcrossTwoDynamicPermissions(t *testing.T) {
	origTable, origModuleMap := snapshotPermissionTables()
	defer restorePermissionTables(origTable, origModuleMap)

	cfg := &Config{
		Permissions: &ManagePermissions{
			Dynamic: []*Permission{
				{ID: "15016", Name: "PCS2TaskOrderSubModuleAccess", Friendly: "Task Order Sub Module Access", Module: "PCS2"},
				{ID: "15016", Name: "hashserviceUpdateVersion", Friendly: "Update Version", Module: "HashService"},
			},
		},
	}

	err := cfg.loadDynamicPermissions()
	if err == nil {
		t.Fatalf("expected an error due to duplicate permission id 15016, got nil")
	}
	if !strings.Contains(err.Error(), "15016") {
		t.Errorf("expected error to mention the colliding id 15016, got: %v", err)
	}
}

func TestLoadDynamicPermissions_ReportsEveryClashingIdInOnePass(t *testing.T) {
	origTable, origModuleMap := snapshotPermissionTables()
	defer restorePermissionTables(origTable, origModuleMap)

	// Mirrors the real-world scenario found in testconf_local.json, where
	// multiple, unrelated pairs of dynamic permissions each clash on id.
	cfg := &Config{
		Permissions: &ManagePermissions{
			Dynamic: []*Permission{
				{ID: "15016", Name: "PCS2TaskOrderSubModuleAccess", Module: "PCS2"},
				{ID: "15016", Name: "hashserviceUpdateVersion", Module: "HashService"},
				{ID: "15017", Name: "PCS2TaskOrderOverviewAccess", Module: "PCS2"},
				{ID: "15017", Name: "hashserviceAddClient", Module: "HashService"},
				{ID: "15900", Name: "someUniquePermission", Module: "Water"}, // not colliding
				{ID: "15018", Name: "PCS2TaskOrderListAccess", Module: "PCS2"},
				{ID: "15018", Name: "hashserviceDeleteClient", Module: "HashService"},
			},
		},
	}

	err := cfg.loadDynamicPermissions()
	if err == nil {
		t.Fatalf("expected an error due to multiple clashing ids, got nil")
	}
	for _, id := range []string{"15016", "15017", "15018"} {
		if !strings.Contains(err.Error(), id) {
			t.Errorf("expected error to report clashing id %s, got: %v", id, err)
		}
	}
	// The non-colliding id must not be reported as a clash.
	if strings.Contains(err.Error(), "15900") {
		t.Errorf("did not expect non-colliding id 15900 to be reported as a clash, got: %v", err)
	}
	// The non-colliding permission should still have been registered, since
	// we only reject the colliding ones, not the whole config.
	if PermissionsTable[15900] != "someUniquePermission" {
		t.Errorf("expected the non-colliding permission 15900 to still be registered")
	}
}

func TestLoadDynamicPermissions_RejectsDuplicateIdAgainstStaticPermission(t *testing.T) {
	origTable, origModuleMap := snapshotPermissionTables()
	defer restorePermissionTables(origTable, origModuleMap)

	cfg := &Config{
		Permissions: &ManagePermissions{
			Dynamic: []*Permission{
				// id 1 is the hard-coded 'admin' permission (PermAdmin) from perms.go.
				{ID: "1", Name: "someClientPermission", Friendly: "Some Client Permission", Module: "Water"},
			},
		},
	}

	err := cfg.loadDynamicPermissions()
	if err == nil {
		t.Fatalf("expected an error due to id 1 colliding with the static 'admin' permission, got nil")
	}
	if !strings.Contains(err.Error(), "1") {
		t.Errorf("expected error to mention the colliding id 1, got: %v", err)
	}
}

func TestLoadDynamicPermissions_AllowsUniqueIds(t *testing.T) {
	origTable, origModuleMap := snapshotPermissionTables()
	defer restorePermissionTables(origTable, origModuleMap)

	cfg := &Config{
		Permissions: &ManagePermissions{
			Dynamic: []*Permission{
				{ID: "15900", Name: "someClientPermissionA", Friendly: "A", Module: "Water"},
				{ID: "15901", Name: "someClientPermissionB", Friendly: "B", Module: "Sewer"},
			},
		},
	}

	err := cfg.loadDynamicPermissions()
	if err != nil {
		t.Fatalf("expected no error for unique ids, got: %v", err)
	}
	if PermissionsTable[15900] != "someClientPermissionA" {
		t.Errorf("expected PermissionsTable[15900] to be registered")
	}
	if PermissionsTable[15901] != "someClientPermissionB" {
		t.Errorf("expected PermissionsTable[15901] to be registered")
	}
}

func TestLoadDynamicPermissions_IdempotentReloadOfSamePermission(t *testing.T) {
	origTable, origModuleMap := snapshotPermissionTables()
	defer restorePermissionTables(origTable, origModuleMap)

	cfg := &Config{
		Permissions: &ManagePermissions{
			Dynamic: []*Permission{
				{ID: "15902", Name: "someClientPermissionC", Friendly: "C", Module: "Roads"},
			},
		},
	}

	// Loading the same dynamic permission twice (e.g. config reloaded) must
	// not be treated as a collision with itself.
	if err := cfg.loadDynamicPermissions(); err != nil {
		t.Fatalf("expected no error on first load, got: %v", err)
	}
	if err := cfg.loadDynamicPermissions(); err != nil {
		t.Fatalf("expected no error when reloading the identical permission again, got: %v", err)
	}
}



