package imqsauth

import (
	"github.com/IMQS/authaus"
)

// ======================
// DO NOT EDIT THIS FILE!
// ======================
//
// This code was generated by the permissions_generator.rb script.
// Should you wish to add a new IMQS V8 permission, follow the instructions
// to regenerate this class at:
//
// https://imqssoftware.atlassian.net/wiki/display/ASC/Generating+Permissions
//
// IMQS permission bits (each number in the range 0..65535 means something)

const (
	PermReservedZero authaus.PermissionU16 = 0 //Avoid the danger of having a zero mean something
	PermAdmin authaus.PermissionU16 = 1 //Super-user who can control all aspects of the auth system
	PermEnabled authaus.PermissionU16 = 2 //User is allowed to use the system. Without this no request is authorized
	PermPcs authaus.PermissionU16 = 3 //User is allowed to access the PCS module.
	PermPcsSuperUser authaus.PermissionU16 = 100 //User can perform all actions in PCS}
	PermPcsBudgetAddAndDelete authaus.PermissionU16 = 101 //User is allowed to add and delete a budget to PCS
	PermPcsBudgetUpdate authaus.PermissionU16 = 102 //User is allowed to update a budget in PCS
	PermPcsBudgetView authaus.PermissionU16 = 103 //User is allowed to view budgets in PCS.
	PermPcsProjectAddAndDelete authaus.PermissionU16 = 104 //User is allowed to add and delete a project to PCS
	PermPcsProjectUpdate authaus.PermissionU16 = 105 //User is allowed to update a project in PCS
	PermPcsProjectView authaus.PermissionU16 = 106 //User is allowed to view projects in PCS
	PermPcsProgrammeAddAndDelete authaus.PermissionU16 = 107 //User is allowed to add and delete a programme to PCS
	PermPcsProgrammeUpdate authaus.PermissionU16 = 108 //User is allowed to update a programme in PCS
	PermPcsProgrammeView authaus.PermissionU16 = 109 //User is allowed to view programmes in PCS
	PermPcsLookupAddAndDelete authaus.PermissionU16 = 110 //User is allowed to add a lookup/employee/legal entity to PCS
	PermPcsLookupUpdate authaus.PermissionU16 = 111 //User is allowed to update a lookup/employee/legal entity in PCS
	PermPcsLookupView authaus.PermissionU16 = 112 //User is allowed to view lookup/employee/legal entity in PCS
	PermPcsBudgetItemList authaus.PermissionU16 = 113 //User is allowed to view budget items in PCS
	PermPcsDynamicContent authaus.PermissionU16 = 114 //User is allowed to get dynamic configuration
	PermPcsProjectsUnassignedView authaus.PermissionU16 = 115 //User is allowed to view all the projects that are not assigned to programmes
	PermPcsBudgetItemsAvailable authaus.PermissionU16 = 116 //User is allowed to view the allocatable budget items
	PermReportCreator authaus.PermissionU16 = 200 //Can create reports
	PermReportViewer authaus.PermissionU16 = 201 //Can view reports
	PermImporter authaus.PermissionU16 = 300 //User is allowed to handle data imports
	PermFileDrop authaus.PermissionU16 = 301 //User is allowed to drop files onto IMQS Web
	PermMm authaus.PermissionU16 = 400 //MM
	PermMmWorkRequestView authaus.PermissionU16 = 401 //Work Request View
	PermMmWorkRequestAddAndDelete authaus.PermissionU16 = 402 //Work Request Add/Delete
	PermMmWorkRequestUpdate authaus.PermissionU16 = 403 //Work Request Update
	PermMmPmWorkRequestAddAndDelete authaus.PermissionU16 = 404 //MM Work Request Add/Delete
	PermMmPmWorkRequestUpdate authaus.PermissionU16 = 405 //MM Work Request Update
	PermMmPmWorkRequestView authaus.PermissionU16 = 406 //MM Work Request View
	PermMmPmRegionalManagerAddAndDelete authaus.PermissionU16 = 407 //MM Work Request Regional Manager Add/Delete
	PermMmPmRegionalManagerUpdate authaus.PermissionU16 = 408 //MM Work Request Regional Manager Update
	PermMmPmRegionalManagerView authaus.PermissionU16 = 409 //MM Work Request Regional Manager View
	PermMmPmDivisionalManagerAddAndDelete authaus.PermissionU16 = 410 //MM Work Request Divisional Manager Add/Delete
	PermMmPmDivisionalManagerUpdate authaus.PermissionU16 = 411 //MM Work Request Divisional Manager Update
	PermMmPmDivisionalManagerView authaus.PermissionU16 = 412 //MM Work Request Divisional Manager View
	PermMmPmGeneralManagerAddAndDelete authaus.PermissionU16 = 413 //MM Work Request General Manager Add/Delete
	PermMmPmGeneralManagerUpdate authaus.PermissionU16 = 414 //MM Work Request General Manager Update
	PermMmPmGeneralManagerView authaus.PermissionU16 = 415 //MM Work Request General Manager View
	PermMmPmRoutingDepartmentAddAndDelete authaus.PermissionU16 = 416 //MM Work Request Routing Department Add/Delete
	PermMmPmRoutingDepartmentUpdate authaus.PermissionU16 = 417 //MM Work Request Routing Department Update
	PermMmPmRoutingDepartmentView authaus.PermissionU16 = 418 //MM Work Request Routing Department View
	PermMmFormBuilder authaus.PermissionU16 = 419 //MM Form Builder
	PermMmLookup authaus.PermissionU16 = 420 //MM Lookup
	PermMmServiceRequest authaus.PermissionU16 = 421 //MM Service Request
	PermMmSetup authaus.PermissionU16 = 422 //MM Setup
	PermMmSuperUser authaus.PermissionU16 = 423 //MM Super User
	PermMmSetupWorkFlow authaus.PermissionU16 = 424 //MM Setup Workflow
	PermMmSetupPM authaus.PermissionU16 = 425 //MM Setup Preventative Maintenance
	PermMmSetupPMSchedule authaus.PermissionU16 = 426 //MM Setup Preventative Maintenance Schedule
	PermWipProjectView authaus.PermissionU16 = 500 //User is allowed to access the WIP module
	PermWipProjectAdd authaus.PermissionU16 = 501 //User is allowed to add a WIP project
	PermWipProjectEdit authaus.PermissionU16 = 502 //User is allowed to edit a WIP project
	PermWipProjectSuspend authaus.PermissionU16 = 503 //User is allowed to suspend a workflow
	PermWipProjectDiscard authaus.PermissionU16 = 504 //User is allowed to discard a workflow
	PermEnergySiteConfigAddAndDelete authaus.PermissionU16 = 600 //User is allowed to add and delete an energy site configuration
	PermEnergySiteConfigUpdate authaus.PermissionU16 = 601 //User is allowed to update an energy site configuration
	PermEnergySiteConfigView authaus.PermissionU16 = 602 //User is allowed to view an energy site configuration
	PermImqsDeveloper authaus.PermissionU16 = 999 //IMQS Developer

)

// Mapping from 16-bit permission integer to string-based name
var PermissionsTable authaus.PermissionNameTable

func init() {
	PermissionsTable = authaus.PermissionNameTable{}

	// It is better not to include the 'zero' permission in here, otherwise it leaks
	// out into things like an inverted map from permission name to permission number.

	PermissionsTable[PermAdmin] = "admin" //Super-user who can control all aspects of the auth system
	PermissionsTable[PermEnabled] = "enabled" //User is allowed to use the system. Without this no request is authorized
	PermissionsTable[PermPcs] = "pcs" //User is allowed to access the PCS module.
	PermissionsTable[PermPcsSuperUser] = "pcssuperuser" //User can perform all actions in PCS}
	PermissionsTable[PermPcsBudgetAddAndDelete] = "pcsbudgetaddanddelete" //User is allowed to add and delete a budget to PCS
	PermissionsTable[PermPcsBudgetUpdate] = "pcsbudgetupdate" //User is allowed to update a budget in PCS
	PermissionsTable[PermPcsBudgetView] = "pcsbudgetview" //User is allowed to view budgets in PCS.
	PermissionsTable[PermPcsProjectAddAndDelete] = "pcsprojectaddanddelete" //User is allowed to add and delete a project to PCS
	PermissionsTable[PermPcsProjectUpdate] = "pcsprojectupdate" //User is allowed to update a project in PCS
	PermissionsTable[PermPcsProjectView] = "pcsprojectview" //User is allowed to view projects in PCS
	PermissionsTable[PermPcsProgrammeAddAndDelete] = "pcsprogrammeaddanddelete" //User is allowed to add and delete a programme to PCS
	PermissionsTable[PermPcsProgrammeUpdate] = "pcsprogrammeupdate" //User is allowed to update a programme in PCS
	PermissionsTable[PermPcsProgrammeView] = "pcsprogrammeview" //User is allowed to view programmes in PCS
	PermissionsTable[PermPcsLookupAddAndDelete] = "pcslookupaddanddelete" //User is allowed to add a lookup/employee/legal entity to PCS
	PermissionsTable[PermPcsLookupUpdate] = "pcslookupupdate" //User is allowed to update a lookup/employee/legal entity in PCS
	PermissionsTable[PermPcsLookupView] = "pcslookupview" //User is allowed to view lookup/employee/legal entity in PCS
	PermissionsTable[PermPcsBudgetItemList] = "pcsbudgetitemlist" //User is allowed to view budget items in PCS
	PermissionsTable[PermPcsDynamicContent] = "pcsdynamiccontent" //User is allowed to get dynamic configuration
	PermissionsTable[PermPcsProjectsUnassignedView] = "pcsprojectsunassignedview" //User is allowed to view all the projects that are not assigned to programmes
	PermissionsTable[PermPcsBudgetItemsAvailable] = "pcsbudgetitemsavailable" //User is allowed to view the allocatable budget items
	PermissionsTable[PermReportCreator] = "reportcreator" //Can create reports
	PermissionsTable[PermReportViewer] = "reportviewer" //Can view reports
	PermissionsTable[PermImporter] = "importer" //User is allowed to handle data imports
	PermissionsTable[PermFileDrop] = "filedrop" //User is allowed to drop files onto IMQS Web
	PermissionsTable[PermMm] = "mm" //MM
	PermissionsTable[PermMmWorkRequestView] = "mmworkrequestview" //Work Request View
	PermissionsTable[PermMmWorkRequestAddAndDelete] = "mmworkrequestaddanddelete" //Work Request Add/Delete
	PermissionsTable[PermMmWorkRequestUpdate] = "mmworkrequestupdate" //Work Request Update
	PermissionsTable[PermMmPmWorkRequestAddAndDelete] = "mmpmworkrequestaddanddelete" //MM Work Request Add/Delete
	PermissionsTable[PermMmPmWorkRequestUpdate] = "mmpmworkrequestupdate" //MM Work Request Update
	PermissionsTable[PermMmPmWorkRequestView] = "mmpmworkrequestview" //MM Work Request View
	PermissionsTable[PermMmPmRegionalManagerAddAndDelete] = "mmpmregionalmanageraddanddelete" //MM Work Request Regional Manager Add/Delete
	PermissionsTable[PermMmPmRegionalManagerUpdate] = "mmpmregionalmanagerupdate" //MM Work Request Regional Manager Update
	PermissionsTable[PermMmPmRegionalManagerView] = "mmpmregionalmanagerview" //MM Work Request Regional Manager View
	PermissionsTable[PermMmPmDivisionalManagerAddAndDelete] = "mmpmdivisionalmanageraddanddelete" //MM Work Request Divisional Manager Add/Delete
	PermissionsTable[PermMmPmDivisionalManagerUpdate] = "mmpmdivisionalmanagerupdate" //MM Work Request Divisional Manager Update
	PermissionsTable[PermMmPmDivisionalManagerView] = "mmpmdivisionalmanagerview" //MM Work Request Divisional Manager View
	PermissionsTable[PermMmPmGeneralManagerAddAndDelete] = "mmpmgeneralmanageraddanddelete" //MM Work Request General Manager Add/Delete
	PermissionsTable[PermMmPmGeneralManagerUpdate] = "mmpmgeneralmanagerupdate" //MM Work Request General Manager Update
	PermissionsTable[PermMmPmGeneralManagerView] = "mmpmgeneralmanagerview" //MM Work Request General Manager View
	PermissionsTable[PermMmPmRoutingDepartmentAddAndDelete] = "mmpmroutingdepartmentaddanddelete" //MM Work Request Routing Department Add/Delete
	PermissionsTable[PermMmPmRoutingDepartmentUpdate] = "mmpmroutingdepartmentupdate" //MM Work Request Routing Department Update
	PermissionsTable[PermMmPmRoutingDepartmentView] = "mmpmroutingdepartmentview" //MM Work Request Routing Department View
	PermissionsTable[PermMmFormBuilder] = "mmformbuilder" //MM Form Builder
	PermissionsTable[PermMmLookup] = "mmlookup" //MM Lookup
	PermissionsTable[PermMmServiceRequest] = "mmservicerequest" //MM Service Request
	PermissionsTable[PermMmSetup] = "mmsetup" //MM Setup
	PermissionsTable[PermMmSuperUser] = "mmsuperuser" //MM Super User
	PermissionsTable[PermMmSetupWorkFlow] = "mmsetupworkflow" //MM Setup Workflow
	PermissionsTable[PermMmSetupPM] = "mmsetuppm" //MM Setup Preventative Maintenance
	PermissionsTable[PermMmSetupPMSchedule] = "mmsetuppmschedule" //MM Setup Preventative Maintenance Schedule
	PermissionsTable[PermWipProjectView] = "wipprojectview" //User is allowed to access the WIP module
	PermissionsTable[PermWipProjectAdd] = "wipprojectadd" //User is allowed to add a WIP project
	PermissionsTable[PermWipProjectEdit] = "wipprojectedit" //User is allowed to edit a WIP project
	PermissionsTable[PermWipProjectSuspend] = "wipprojectsuspend" //User is allowed to suspend a workflow
	PermissionsTable[PermWipProjectDiscard] = "wipprojectdiscard" //User is allowed to discard a workflow
	PermissionsTable[PermEnergySiteConfigAddAndDelete] = "energysiteconfigaddanddelete" //User is allowed to add and delete an energy site configuration
	PermissionsTable[PermEnergySiteConfigUpdate] = "energysiteconfigupdate" //User is allowed to update an energy site configuration
	PermissionsTable[PermEnergySiteConfigView] = "energysiteconfigview" //User is allowed to view an energy site configuration
	PermissionsTable[PermImqsDeveloper] = "imqsdeveloper" //IMQS Developer

}