package imqsauth

import (
	"github.com/IMQS/authaus"
)

// IMQS permission bits (each number in the range 0..65535 means something)
const (
	PermReservedZero authaus.PermissionU16 = 0 // Avoid the danger of having a zero mean something
	PermAdmin        authaus.PermissionU16 = 1 // Super-user who can control all aspects of the auth system
	PermEnabled      authaus.PermissionU16 = 2 // User is allowed to use the system. Without this no request is authorized
)

var PermissionsTable authaus.PermissionNameTable

func init() {
	PermissionsTable = make(authaus.PermissionNameTable, 0)
	PermissionsTable.Append(PermReservedZero, "")
	PermissionsTable.Append(PermAdmin, "admin")
	PermissionsTable.Append(PermEnabled, "enabled")
}
