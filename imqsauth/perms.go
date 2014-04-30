package imqsauth

import (
	"github.com/IMQS/authaus"
)

// IMQS permission bits (each number in the range 0..65535 means something)
const (
	PermReservedZero authaus.PermissionU16 = 0 // Avoid the danger of having a zero mean something
	PermAdmin        authaus.PermissionU16 = 1 // Super-user who can control all aspects of the auth system
	PermEnabled      authaus.PermissionU16 = 2 // User is allowed to use the system. Without this no request is authorized
	PermPCS          authaus.PermissionU16 = 3 // User is allowed to access the PCS module.
	// PermPCSSuperUser              authaus.PermissionU16 = 100 // User can perform all actions in PCS
	// PermPCSBudgetView             authaus.PermissionU16 = 101 // User is allowed to view budgets in PCS.
	// PermPCSBudgetAdd              authaus.PermissionU16 = 102 // User is allowed to add a budget to PCS
	// PermPCSSingleBudgetView       authaus.PermissionU16 = 103 // User is allowed to view a single budget in PCS
	// PermPCSBudgetUpdate           authaus.PermissionU16 = 104 // User is allowed to update a budget in PCS
	// PermPCSBudgetDelete           authaus.PermissionU16 = 105 // User is allowed to delete a budget in PCS
	// PermPCSBudgetItemList         authaus.PermissionU16 = 106 // User is allowed to view budget items in PCS
	// PermPCSDynamicContent         authaus.PermissionU16 = 107 // User is allowed to get dynamic configuration
	// PermPCSEmployeeView           authaus.PermissionU16 = 108 // User is allowed to view employees in PCS
	// PermPCSEmployeeAdd            authaus.PermissionU16 = 109 // User is allowed to add employees to PCS
	// PermPCSEmployeeUpdate         authaus.PermissionU16 = 110 // User is allowed to update an employee in PCS
	// PermPCSSingleEmployeeView     authaus.PermissionU16 = 111 // User is allowed to view a single employee in PCS
	// PermPCSEmployeeDelete         authaus.PermissionU16 = 112 // User is allowed to delete employees in PCS
	// PermPCSLegalEntityView        authaus.PermissionU16 = 113 // User is allowed to view legal entities in PCS
	// PermPCSLegalEntityAdd         authaus.PermissionU16 = 114 // User is allowed to add legal entities to PCS
	// PermPCSLegalEntityUpdate      authaus.PermissionU16 = 115 // User is allowed to update a legal entity in PCS
	// PermPCSSingleLegalEntityView  authaus.PermissionU16 = 116 // User is allowed to view a single legal entity in PCS
	// PermPCSLegalEntityDelete      authaus.PermissionU16 = 117 // User is allowed to delete legal entities in PCS
	// PermPCSProjectView            authaus.PermissionU16 = 118 // User is allowed to view projects in PCS
	// PermPCSProjectAdd             authaus.PermissionU16 = 119 // User is allowed to add projects to PCS
	// PermPCSProjectUpdate          authaus.PermissionU16 = 120 // User is allowed to update a project in PCS
	// PermPCSSingleProjectView      authaus.PermissionU16 = 121 // User is allowed to view a single project in PCS
	// PermPCSProjectDelete          authaus.PermissionU16 = 122 // User is allowed to delete projects in PCS
	// PermPCSProgrammeView          authaus.PermissionU16 = 123 // User is allowed to view programmes in PCS
	// PermPCSProgrammeAdd           authaus.PermissionU16 = 124 // User is allowed to add programmes to PCS
	// PermPCSProgrammeUpdate        authaus.PermissionU16 = 125 // User is allowed to update a programme in PCS
	// PermPCSSingleProgrammeView    authaus.PermissionU16 = 126 // User is allowed to view a single programme in PCS
	// PermPCSProgrammeDelete        authaus.PermissionU16 = 127 // User is allowed to delete programmes in PCS
	// PermPCSLookupUpdate           authaus.PermissionU16 = 128 // User is allowed to update a lookup in PCS
	// PermPCSLookupDelete           authaus.PermissionU16 = 129 // User is allowed to delete a lookup in PCS
	// PermPCsLookupView             authaus.PermissionU16 = 130 // User is allowed to view all lookups in PCS
	// PermPCSLookupChildren         authaus.PermissionU16 = 131 // User is allowed to view the children of a parent lookup in PCS
	// PermPCSLookupSpecificTypeView authaus.PermissionU16 = 132 // User is allowed to view all lookups of a specific type in PCS
	// PermPCSLookupAdd              authaus.PermissionU16 = 133 // User is allowed to add a lookup to PCS
	// PermPCSLookupTypesView        authaus.PermissionU16 = 134 // User is allowed to view all lookup types in PCS
	// PermPCSSingleLookupView       authaus.PermissionU16 = 135 // User is allowed to view a single lookup in PCS
	// PermPCSProjectsUnassignedView authaus.PermissionU16 = 136 // User is allowed to view all the projects that are not assigned to programmes
	// PermPCSBudgetItemsAvailable   authaus.PermissionU16 = 137 // User is allowed to view the aloocatable budget items
)

// This is not yet used, but I expect to use it when building the REST API that will be used by
// the administrator web app.
var PermissionsTable authaus.PermissionNameTable

func init() {
	PermissionsTable = make(authaus.PermissionNameTable, 0)
	PermissionsTable.Append(PermReservedZero, "")
	PermissionsTable.Append(PermAdmin, "admin")
	PermissionsTable.Append(PermEnabled, "enabled")
	PermissionsTable.Append(PermPCS, "pcs")
	// PermissionsTable.Append(PermPCSSuperUser, "pcssuperuser")
	// PermissionsTable.Append(PermPCSBudgetView, "pcsbudgetview")
	// PermissionsTable.Append(PermPCSBudgetAdd, "pcsbudgetadd")
	// PermissionsTable.Append(PermPCSSingleBudgetView, "pcssinglebudgetview")
	// PermissionsTable.Append(PermPCSBudgetUpdate, "pcsbudgetupdate")
	// PermissionsTable.Append(PermPCSBudgetDelete, "pcsbudgetdelete")
	// PermissionsTable.Append(PermPCSBudgetItemList, "pcsbudgetitemlist")
	// PermissionsTable.Append(PermPCSDynamicContent, "pcsdynamiccontent")
	// PermissionsTable.Append(PermPCSEmployeeUpdate, "pcsemployeeupdate")
	// PermissionsTable.Append(PermPCSEmployeeAdd, "pcsemployeeadd")
	// PermissionsTable.Append(PermPCSEmployeeView, "pcsemployeeview")
	// PermissionsTable.Append(PermPCSSingleEmployeeView, "pcssingleemployeeview")
	// PermissionsTable.Append(PermPCSEmployeeDelete, "pcsemployeedelete")
	// PermissionsTable.Append(PermPCSLegalEntityUpdate, "pcslegalentityupdate")
	// PermissionsTable.Append(PermPCSLegalEntityAdd, "pcslegalentityadd")
	// PermissionsTable.Append(PermPCSLegalEntityView, "pcslegalentityview")
	// PermissionsTable.Append(PermPCSSingleLegalEntityView, "pcssinglelegalentityview")
	// PermissionsTable.Append(PermPCSLegalEntityDelete, "pcslegalentitydelete")
	// PermissionsTable.Append(PermPCSProjectUpdate, "pcsprojectupdate")
	// PermissionsTable.Append(PermPCSProjectAdd, "pcsprojectadd")
	// PermissionsTable.Append(PermPCSProjectView, "pcsprojectview")
	// PermissionsTable.Append(PermPCSSingleProjectView, "pcssingleprojectview")
	// PermissionsTable.Append(PermPCSProjectDelete, "pcsprojectdelete")
	// PermissionsTable.Append(PermPCSProgrammeUpdate, "pcsprogrammeupdate")
	// PermissionsTable.Append(PermPCSProgrammeAdd, "pcsprogrammeadd")
	// PermissionsTable.Append(PermPCSProgrammeView, "pcsprogrammeview")
	// PermissionsTable.Append(PermPCSSingleProgrammeView, "pcssingleprogrammeview")
	// PermissionsTable.Append(PermPCSProgrammeDelete, "pcsprogrammedelete")
	// PermissionsTable.Append(PermPCSLookupUpdate, "pcslookupupdate")
	// PermissionsTable.Append(PermPCSLookupDelete, "pcslookupdelete")
	// PermissionsTable.Append(PermPCSLookupView, "pcslookupview")
	// PermissionsTable.Append(PermPCSLookupChildren, "pcslookupchildren")
	// PermissionsTable.Append(PermPCSLookupSpecificTypeView, "pcslookupspecifictypeview")
	// PermissionsTable.Append(PermPCSLookupAdd, "pcslookupadd")
	// PermissionsTable.Append(PermPCSLookupTypesView, "pcslookuptypesview")
	// PermissionsTable.Append(PermPCSSingleLookupView, "pcssinglelookupview")
	// PermissionsTable.Append(PermPCSProjectsUnassignedView, "pcsprojectsunassignedview")
	// PermissionsTable.Append(PermPCSBudgetItemsAvailable, "pcsbudgetitemsavailable")
}
