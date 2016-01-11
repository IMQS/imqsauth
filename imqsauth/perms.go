package imqsauth

import (
	"github.com/IMQS/authaus"
)

// IMQS permission bits (each number in the range 0..65535 means something)
const (
	//General permissions
	PermReservedZero              authaus.PermissionU16 = 0   // Avoid the danger of having a zero mean something
	PermAdmin                     authaus.PermissionU16 = 1   // Super-user who can control all aspects of the auth system
	PermEnabled                   authaus.PermissionU16 = 2   // User is allowed to use the system. Without this no request is authorized
	PermPCS                       authaus.PermissionU16 = 3   // User is allowed to access the PCS module.
	PermPCSSuperUser              authaus.PermissionU16 = 100 // User can perform all actions in PCS
	PermPCSBudgetAddAndDelete     authaus.PermissionU16 = 101 // User is allowed to add and delete a budget to PCS
	PermPCSBudgetUpdate           authaus.PermissionU16 = 102 // User is allowed to update a budget in PCS
	PermPCSBudgetView             authaus.PermissionU16 = 103 // User is allowed to view budgets in PCS.
	PermPCSProjectAddAndDelete    authaus.PermissionU16 = 104 // User is allowed to add and delete a project to PCS
	PermPCSProjectUpdate          authaus.PermissionU16 = 105 // User is allowed to update a project in PCS
	PermPCSProjectView            authaus.PermissionU16 = 106 // User is allowed to view projects in PCS
	PermPCSProgrammeAddAndDelete  authaus.PermissionU16 = 107 // User is allowed to add and delete a programme to PCS
	PermPCSProgrammeUpdate        authaus.PermissionU16 = 108 // User is allowed to update a programme in PCS
	PermPCSProgrammeView          authaus.PermissionU16 = 109 // User is allowed to view programmes in PCS
	PermPCSLookupAddAndDelete     authaus.PermissionU16 = 110 // User is allowed to add a lookup/employee/legal entity to PCS
	PermPCSLookupUpdate           authaus.PermissionU16 = 111 // User is allowed to update a lookup/employee/legal entity in PCS
	PermPCSLookupView             authaus.PermissionU16 = 112 // User is allowed to view lookup/employee/legal entity in PCS
	PermPCSBudgetItemList         authaus.PermissionU16 = 113 // User is allowed to view budget items in PCS
	PermPCSDynamicContent         authaus.PermissionU16 = 114 // User is allowed to get dynamic configuration
	PermPCSProjectsUnassignedView authaus.PermissionU16 = 115 // User is allowed to view all the projects that are not assigned to programmes
	PermPCSBudgetItemsAvailable   authaus.PermissionU16 = 116 // User is allowed to view the allocatable budget items
	PermReportCreator             authaus.PermissionU16 = 200 // Can create reports
	PermReportViewer              authaus.PermissionU16 = 201 // Can view reports
	PermImporter                  authaus.PermissionU16 = 500 // User is allowed to handle data imports
)

// Mapping from 16-bit permission integer to string-based name
var PermissionsTable authaus.PermissionNameTable

func init() {
	PermissionsTable = authaus.PermissionNameTable{}

	// It is better not to include the 'zero' permission in here, otherwise it leaks
	// out into things like an inverted map from permission name to permission number.

	PermissionsTable[PermAdmin] = "admin"
	PermissionsTable[PermEnabled] = "enabled"
	PermissionsTable[PermPCS] = "pcs"

	PermissionsTable[PermPCSSuperUser] = "pcssuperuser"
	PermissionsTable[PermPCSBudgetAddAndDelete] = "pcsbudgetaddanddelete"
	PermissionsTable[PermPCSBudgetUpdate] = "pcsbudgetupdate"
	PermissionsTable[PermPCSBudgetView] = "pcsbudgetview"
	PermissionsTable[PermPCSProjectAddAndDelete] = "pcsprojectaddanddelete"
	PermissionsTable[PermPCSProjectUpdate] = "pcsprojectupdate"
	PermissionsTable[PermPCSProjectView] = "pcsprojectview"
	PermissionsTable[PermPCSProgrammeAddAndDelete] = "pcsprogrammeaddanddelete"
	PermissionsTable[PermPCSProgrammeUpdate] = "pcsprogrammeupdate"
	PermissionsTable[PermPCSProgrammeView] = "pcsprogrammeview"
	PermissionsTable[PermPCSLookupAddAndDelete] = "pcslookupaddanddelete"
	PermissionsTable[PermPCSLookupUpdate] = "pcslookupupdate"
	PermissionsTable[PermPCSLookupView] = "pcslookupview"
	PermissionsTable[PermPCSBudgetItemList] = "pcsbudgetitemlist"
	PermissionsTable[PermPCSDynamicContent] = "pcsdynamiccontent"
	PermissionsTable[PermPCSProjectsUnassignedView] = "pcsprojectsunassignedview"
	PermissionsTable[PermPCSBudgetItemsAvailable] = "pcsbudgetitemsavailable"

	PermissionsTable[PermReportCreator] = "reportcreator"
	PermissionsTable[PermReportViewer] = "reportviewer"

	PermissionsTable[PermImporter] = "importer"
}
