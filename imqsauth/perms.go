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
	PermReservedZero authaus.PermissionU16 = 0 // Avoid the danger of having a zero mean something
	PermAdmin authaus.PermissionU16 = 1 // Super-user who can control all aspects of the auth system
	PermEnabled authaus.PermissionU16 = 2 // User is allowed to use the system. Without this no request is authorized
	PermPcs authaus.PermissionU16 = 3 // User is allowed to access the PCS module.
	PermBulkSms authaus.PermissionU16 = 4 // User is allowed to send SMS messages.
	PermPcsSuperUser authaus.PermissionU16 = 100 // User can perform all actions in PCS}
	PermPcsBudgetAddAndDelete authaus.PermissionU16 = 101 // User is allowed to add and delete a budget to PCS
	PermPcsBudgetUpdate authaus.PermissionU16 = 102 // User is allowed to update a budget in PCS
	PermPcsBudgetView authaus.PermissionU16 = 103 // User is allowed to view budgets in PCS.
	PermPcsProjectAddAndDelete authaus.PermissionU16 = 104 // User is allowed to add and delete a project to PCS
	PermPcsProjectUpdate authaus.PermissionU16 = 105 // User is allowed to update a project in PCS
	PermPcsProjectView authaus.PermissionU16 = 106 // User is allowed to view projects in PCS
	PermPcsProgrammeAddAndDelete authaus.PermissionU16 = 107 // User is allowed to add and delete a programme to PCS
	PermPcsProgrammeUpdate authaus.PermissionU16 = 108 // User is allowed to update a programme in PCS
	PermPcsProgrammeView authaus.PermissionU16 = 109 // User is allowed to view programmes in PCS
	PermPcsLookupAddAndDelete authaus.PermissionU16 = 110 // User is allowed to add a lookup/employee/legal entity to PCS
	PermPcsLookupUpdate authaus.PermissionU16 = 111 // User is allowed to update a lookup/employee/legal entity in PCS
	PermPcsLookupView authaus.PermissionU16 = 112 // User is allowed to view lookup/employee/legal entity in PCS
	PermPcsBudgetItemList authaus.PermissionU16 = 113 // User is allowed to view budget items in PCS
	PermPcsDynamicContent authaus.PermissionU16 = 114 // User is allowed to get dynamic configuration
	PermPcsProjectsUnassignedView authaus.PermissionU16 = 115 // User is allowed to view all the projects that are not assigned to programmes
	PermPcsBudgetItemsAvailable authaus.PermissionU16 = 116 // User is allowed to view the allocatable budget items
	PermReportCreator authaus.PermissionU16 = 200 // Can create reports
	PermReportViewer authaus.PermissionU16 = 201 // Can view reports
	PermImporter authaus.PermissionU16 = 300 // User is allowed to handle data imports
	PermFileDrop authaus.PermissionU16 = 301 // User is allowed to drop files onto IMQS Web
	PermHydroWorkOrderCreation authaus.PermissionU16 = 302 // User is allowed to view and use the hydrojet work order creation tool
	PermMm authaus.PermissionU16 = 400 // MM
	PermMmWorkRequestView authaus.PermissionU16 = 401 // Work Request View
	PermMmWorkRequestAddAndDelete authaus.PermissionU16 = 402 // Work Request Add/Delete
	PermMmWorkRequestUpdate authaus.PermissionU16 = 403 // Work Request Update
	PermMmPmWorkRequestAddAndDelete authaus.PermissionU16 = 404 // MM Work Request Add/Delete
	PermMmPmWorkRequestUpdate authaus.PermissionU16 = 405 // MM Work Request Update
	PermMmPmWorkRequestView authaus.PermissionU16 = 406 // MM Work Request View
	PermMmPmRegionalManagerAddAndDelete authaus.PermissionU16 = 407 // MM Work Request Regional Manager Add/Delete
	PermMmPmRegionalManagerUpdate authaus.PermissionU16 = 408 // MM Work Request Regional Manager Update
	PermMmPmRegionalManagerView authaus.PermissionU16 = 409 // MM Work Request Regional Manager View
	PermMmPmDivisionalManagerAddAndDelete authaus.PermissionU16 = 410 // MM Work Request Divisional Manager Add/Delete
	PermMmPmDivisionalManagerUpdate authaus.PermissionU16 = 411 // MM Work Request Divisional Manager Update
	PermMmPmDivisionalManagerView authaus.PermissionU16 = 412 // MM Work Request Divisional Manager View
	PermMmPmGeneralManagerAddAndDelete authaus.PermissionU16 = 413 // MM Work Request General Manager Add/Delete
	PermMmPmGeneralManagerUpdate authaus.PermissionU16 = 414 // MM Work Request General Manager Update
	PermMmPmGeneralManagerView authaus.PermissionU16 = 415 // MM Work Request General Manager View
	PermMmPmRoutingDepartmentAddAndDelete authaus.PermissionU16 = 416 // MM Work Request Routing Department Add/Delete
	PermMmPmRoutingDepartmentUpdate authaus.PermissionU16 = 417 // MM Work Request Routing Department Update
	PermMmPmRoutingDepartmentView authaus.PermissionU16 = 418 // MM Work Request Routing Department View
	PermMmFormBuilder authaus.PermissionU16 = 419 // MM Form Builder
	PermMmLookup authaus.PermissionU16 = 420 // MM Lookup
	PermMmServiceRequest authaus.PermissionU16 = 421 // MM Service Request
	PermMmSetup authaus.PermissionU16 = 422 // MM Setup
	PermMmSuperUser authaus.PermissionU16 = 423 // MM Super User
	PermMmSetupWorkFlow authaus.PermissionU16 = 424 // MM Setup Workflow
	PermMmSetupPM authaus.PermissionU16 = 425 // MM Setup Preventative Maintenance
	PermMmSetupPMSchedule authaus.PermissionU16 = 426 // MM Setup Preventative Maintenance Schedule
	PermMmIncidentLogger authaus.PermissionU16 = 427 // MM Incident Logger
	PermMmResourceManagerView authaus.PermissionU16 = 428 // MM Resource Manager View
	PermMmResourceManagerAddAndDelete authaus.PermissionU16 = 429 // MM Resource Manager Add/Delete
	PermMmResourceManagerUpdate authaus.PermissionU16 = 430 // MM Resource Manager Update
	PermMmTimeAndCostView authaus.PermissionU16 = 431 // MM Time and Cost View
	PermMmTimeAndCostAddAndDelete authaus.PermissionU16 = 432 // MM Time and Cost Add/Delete
	PermMmTimeAndCostUpdate authaus.PermissionU16 = 433 // MM Time and Cost Update
	PermMmDocuments authaus.PermissionU16 = 434 // MM Documents
	PermMmMeterMaintenance authaus.PermissionU16 = 435 // MM Meter Maintenance Map
	PermMmReAssignEditOfDisabledControl authaus.PermissionU16 = 436 // Disabled controls become active for a user with this permission
	PermMmEmployeeView authaus.PermissionU16 = 437 // MM Employee View
	PermMmEmployeeAddAndDelete authaus.PermissionU16 = 438 // MM Employee Add/Delete
	PermMmEmployeeUpdate authaus.PermissionU16 = 439 // MM Employee Update
	PermMmFleetView authaus.PermissionU16 = 440 // MM Fleet View
	PermMmFleetAddAndDelete authaus.PermissionU16 = 441 // MM Fleet Add/Delete
	PermMmFleetUpdate authaus.PermissionU16 = 442 // MM Fleet Update
	PermMmMaterialView authaus.PermissionU16 = 443 // MM Material View
	PermMmMaterialAddAndDelete authaus.PermissionU16 = 444 // MM Material Add/Delete
	PermMmMaterialUpdate authaus.PermissionU16 = 445 // MM Material Update
	PermMmContractorView authaus.PermissionU16 = 446 // MM Contractor View
	PermMmContractorAddAndDelete authaus.PermissionU16 = 447 // MM Contractor Add/Delete
	PermMmContractorUpdate authaus.PermissionU16 = 448 // MM Contractor Update
	PermMmContractorDocsView authaus.PermissionU16 = 449 // MM Contractor Documents View
	PermMmContractorDocsAddAndDelete authaus.PermissionU16 = 450 // MM Contractor Documents Add/Delete
	PermMmContractorDocsUpdate authaus.PermissionU16 = 451 // MM Contractor Documents Update
	PermMmStandardTimesView authaus.PermissionU16 = 452 // MM Standard Times View
	PermMmStandardTimesAddAndDelete authaus.PermissionU16 = 453 // MM Standard Times Add/Delete
	PermMmStandardTimesUpdate authaus.PermissionU16 = 454 // MM Standard Times Update
	PermMmTariffsView authaus.PermissionU16 = 455 // MM Tariffs View
	PermMmTariffsAddAndDelete authaus.PermissionU16 = 456 // MM Tariffs Add/Delete
	PermMmTariffsUpdate authaus.PermissionU16 = 457 // MM Tariffs Update
	PermMmIncidentLoggerView authaus.PermissionU16 = 458 // MM Incident Logger View
	PermMmIncidentLoggerAddAndDelete authaus.PermissionU16 = 459 // MM Incident Logger Add/Delete
	PermMmIncidentLoggerUpdate authaus.PermissionU16 = 460 // MM Incident Logger Update
	PermMmLeaveManagementView authaus.PermissionU16 = 461 // MM Leave Management View
	PermMmLeaveManagementAddAndDelete authaus.PermissionU16 = 462 // MM Leave Management Add/Delete
	PermMmLeaveManagementUpdate authaus.PermissionU16 = 463 // MM Leave Management Update
	PermMmProjectCodeManagementView authaus.PermissionU16 = 464 // MM Project Code Management View
	PermMmProjectCodeManagementAddAndDelete authaus.PermissionU16 = 465 // MM Project Code Management Add/Delete
	PermMmProjectCodeManagementUpdate authaus.PermissionU16 = 466 // MM Project Code Management Update
	PermMmProjectSapManagementView authaus.PermissionU16 = 467 // MM Project Sap Management View
	PermMmProjectSapManagementAddAndDelete authaus.PermissionU16 = 468 // MM Project Sap Management Add/Delete
	PermMmProjectSapManagementUpdate authaus.PermissionU16 = 469 // MM Project Sap Management Update
	PermWipEnabled authaus.PermissionU16 = 500 // User is allowed to use the WIP module
	PermWipWorkflowStart authaus.PermissionU16 = 501 // User is allowed to start a workflow
	PermWipWorkflowSuspend authaus.PermissionU16 = 502 // User is allowed to suspend a workflow
	PermWipWorkflowDiscard authaus.PermissionU16 = 503 // User is allowed to discard a workflow
	PermWipProjectView authaus.PermissionU16 = 510 // User is allowed to view a WIP project
	PermWipProjectAdd authaus.PermissionU16 = 511 // User is allowed to add a WIP project
	PermWipProjectEdit authaus.PermissionU16 = 512 // User is allowed to edit a WIP project
	PermWipProjectDelete authaus.PermissionU16 = 513 // User is allowed to delete a WIP project
	PermWipComponentView authaus.PermissionU16 = 514 // User is allowed to view a WIP component
	PermWipComponentAdd authaus.PermissionU16 = 515 // User is allowed to add a WIP component
	PermWipComponentEdit authaus.PermissionU16 = 516 // User is allowed to edit a WIP component
	PermWipComponentDelete authaus.PermissionU16 = 517 // User is allowed to delete a WIP component
	PermWipActualView authaus.PermissionU16 = 518 // User is allowed to view a WIP actual
	PermWipActualAdd authaus.PermissionU16 = 519 // User is allowed to add a WIP actual
	PermWipActualEdit authaus.PermissionU16 = 520 // User is allowed to edit a WIP actual
	PermWipActualDelete authaus.PermissionU16 = 521 // User is allowed to delete a WIP actual
	PermWipBudgetView authaus.PermissionU16 = 522 // User is allowed to view a WIP budget
	PermWipBudgetAdd authaus.PermissionU16 = 523 // User is allowed to add a WIP budget
	PermWipBudgetEdit authaus.PermissionU16 = 524 // User is allowed to edit a WIP budget
	PermWipBudgetDelete authaus.PermissionU16 = 525 // User is allowed to delete a WIP budget
	PermWipCapitalize authaus.PermissionU16 = 526 // User is allowed to perform capitalization tasks
	PermEnergyConfigAddAndDelete authaus.PermissionU16 = 600 // User is allowed to add and delete an energy site configuration
	PermEnergyConfigUpdate authaus.PermissionU16 = 601 // User is allowed to update an energy site configuration
	PermEnergyConfigView authaus.PermissionU16 = 602 // User is allowed to view an energy site configuration
	PermEnergyConfigLockUnlock authaus.PermissionU16 = 603 // User is allowed to lock/unlock site configuration
	PermEnergyGeneratorsStartStop authaus.PermissionU16 = 604 // User is allowed to start/stop generators
	PermEnergyGateUnlock authaus.PermissionU16 = 605 // User is allowed to unlock gate
	PermEnergySimSwitch authaus.PermissionU16 = 606 // User is allowed to switch site controller SIM
	PermEnergyAlarmsMute authaus.PermissionU16 = 607 // User is allowed to mute site alarms
	PermEnergyAnalogDataRefresh authaus.PermissionU16 = 608 // User is allowed to refresh analog data
	PermEnergyControllerFirmwareVersionRefresh authaus.PermissionU16 = 609 // User is allowed to refresh controller firmware version
	PermEnergyTimeSync authaus.PermissionU16 = 610 // User is allowed to synchronise controller clock with server
	PermEnergyAlarmsAcknowledge authaus.PermissionU16 = 611 // User is allowed to acknowledge alarms
	PermEnergyGateAccessFirmwareVersionRefresh authaus.PermissionU16 = 612 // User is allowed to refresh gate access firmware version
	PermEnergySiteInfoEdit authaus.PermissionU16 = 613 // User is allowed to edit site info
	PermEnergySitePACEdit authaus.PermissionU16 = 614 // User is allowed to edit site PAC
	PermDevconProjectEdit authaus.PermissionU16 = 700 // User is allowed to edit projects
	PermDevconProjectCreate authaus.PermissionU16 = 701 // User is allowed to create new projects
	PermDevconProjectDelete authaus.PermissionU16 = 702 // User is allowed to delete projects
	PermDevconProjectMerge authaus.PermissionU16 = 703 // User is allowed to merge projects
	PermDevconApplicationEdit authaus.PermissionU16 = 704 // User is allowed to edit applications
	PermDevconApplicationCreate authaus.PermissionU16 = 705 // User is allowed to create new applications
	PermDevconApplicationDelete authaus.PermissionU16 = 706 // User is allowed to delete applications
	PermDevconLookupEdit authaus.PermissionU16 = 707 // User is allowed to edit lookups, such as applicant and organisation
	PermDevconLookupCreate authaus.PermissionU16 = 708 // User is allowed to create new lookups
	PermDevconLookupDelete authaus.PermissionU16 = 709 // User is allowed to delete lookups
	PermDevconLookupManagement authaus.PermissionU16 = 710 // User is allowed to access the lookup management page and manage lookups
	PermDevconTemplateManagement authaus.PermissionU16 = 711 // User is allowed to access the feedback template management page and update templates
	PermDevconReportViewing authaus.PermissionU16 = 712 // User is allowed to view reports
	PermImqsDeveloper authaus.PermissionU16 = 999 // IMQS Developer
	PermAssetsModuleAccess authaus.PermissionU16 = 1100 // User is allowed to access the Assets module
	PermCogtaModuleAccess authaus.PermissionU16 = 1101 // User is allowed to access the COGTA module
	PermConditionAssessmentModuleAccess authaus.PermissionU16 = 1102 // User is allowed to access the Condition Assessment module
	PermDocumentExplorerModuleAccess authaus.PermissionU16 = 1103 // User is allowed to access the Document Explorer module
	PermElectricityModuleAccess authaus.PermissionU16 = 1104 // User is allowed to access the Electricity module
	PermElectricityDemandModuleAccess authaus.PermissionU16 = 1105 // User is allowed to access the Electricity Demand module
	PermElectricityDemoModuleAccess authaus.PermissionU16 = 1106 // User is allowed to access the Electricity Demo module
	PermEnergyModuleAccess authaus.PermissionU16 = 1107 // User is allowed to access the Energy module
	PermIndigentModuleAccess authaus.PermissionU16 = 1108 // User is allowed to access the Indigent module
	PermLandUseModuleAccess authaus.PermissionU16 = 1109 // User is allowed to access the Land Use module
	PermMaintenanceManagementModuleAccess authaus.PermissionU16 = 1110 // User is allowed to access the Maintenance Management module
	PermMeterMaintenanceModuleAccess authaus.PermissionU16 = 1111 // User is allowed to access the Meter Maintenance module
	PermPcsModuleAccess authaus.PermissionU16 = 1112 // User is allowed to access the PCS module
	PermPropertiesandBuildingsModuleAccess authaus.PermissionU16 = 1113 // User is allowed to access the Properties and Buildings module
	PermRevenueEnhancementModuleAccess authaus.PermissionU16 = 1114 // User is allowed to access the Revenue Enhancement module
	PermRoadsModuleAccess authaus.PermissionU16 = 1115 // User is allowed to access the Roads module
	PermSewerModuleAccess authaus.PermissionU16 = 1116 // User is allowed to access the Sewer module
	PermSewerPRPModuleAccess authaus.PermissionU16 = 1117 // User is allowed to access the Sewer PRP module
	PermStormwaterModuleAccess authaus.PermissionU16 = 1118 // User is allowed to access the Stormwater module
	PermTelcosModuleAccess authaus.PermissionU16 = 1119 // User is allowed to access the Telcos module
	PermWaterModuleAccess authaus.PermissionU16 = 1120 // User is allowed to access the Water module
	PermWaterDemandModuleAccess authaus.PermissionU16 = 1121 // User is allowed to access the Water Demand module
	PermWaterPRPModuleAccess authaus.PermissionU16 = 1122 // User is allowed to access the Water PRP module
	PermWipModuleAccess authaus.PermissionU16 = 1123 // User is allowed to access the WIP module
	PermDevelopmentControlModuleAccess authaus.PermissionU16 = 1124 // User is allowed to access the Development Control module

)

// Mapping from 16-bit permission integer to string-based name
var PermissionsTable authaus.PermissionNameTable

func init() {
	PermissionsTable = authaus.PermissionNameTable{}

	// It is better not to include the 'zero' permission in here, otherwise it leaks
	// out into things like an inverted map from permission name to permission number.


	PermissionsTable[PermAdmin] = "admin" // Super-user who can control all aspects of the auth system
	PermissionsTable[PermEnabled] = "enabled" // User is allowed to use the system. Without this no request is authorized
	PermissionsTable[PermPcs] = "pcs" // User is allowed to access the PCS module.
	PermissionsTable[PermBulkSms] = "bulksms" // User is allowed to send SMS messages.
	PermissionsTable[PermPcsSuperUser] = "pcssuperuser" // User can perform all actions in PCS}
	PermissionsTable[PermPcsBudgetAddAndDelete] = "pcsbudgetaddanddelete" // User is allowed to add and delete a budget to PCS
	PermissionsTable[PermPcsBudgetUpdate] = "pcsbudgetupdate" // User is allowed to update a budget in PCS
	PermissionsTable[PermPcsBudgetView] = "pcsbudgetview" // User is allowed to view budgets in PCS.
	PermissionsTable[PermPcsProjectAddAndDelete] = "pcsprojectaddanddelete" // User is allowed to add and delete a project to PCS
	PermissionsTable[PermPcsProjectUpdate] = "pcsprojectupdate" // User is allowed to update a project in PCS
	PermissionsTable[PermPcsProjectView] = "pcsprojectview" // User is allowed to view projects in PCS
	PermissionsTable[PermPcsProgrammeAddAndDelete] = "pcsprogrammeaddanddelete" // User is allowed to add and delete a programme to PCS
	PermissionsTable[PermPcsProgrammeUpdate] = "pcsprogrammeupdate" // User is allowed to update a programme in PCS
	PermissionsTable[PermPcsProgrammeView] = "pcsprogrammeview" // User is allowed to view programmes in PCS
	PermissionsTable[PermPcsLookupAddAndDelete] = "pcslookupaddanddelete" // User is allowed to add a lookup/employee/legal entity to PCS
	PermissionsTable[PermPcsLookupUpdate] = "pcslookupupdate" // User is allowed to update a lookup/employee/legal entity in PCS
	PermissionsTable[PermPcsLookupView] = "pcslookupview" // User is allowed to view lookup/employee/legal entity in PCS
	PermissionsTable[PermPcsBudgetItemList] = "pcsbudgetitemlist" // User is allowed to view budget items in PCS
	PermissionsTable[PermPcsDynamicContent] = "pcsdynamiccontent" // User is allowed to get dynamic configuration
	PermissionsTable[PermPcsProjectsUnassignedView] = "pcsprojectsunassignedview" // User is allowed to view all the projects that are not assigned to programmes
	PermissionsTable[PermPcsBudgetItemsAvailable] = "pcsbudgetitemsavailable" // User is allowed to view the allocatable budget items
	PermissionsTable[PermReportCreator] = "reportcreator" // Can create reports
	PermissionsTable[PermReportViewer] = "reportviewer" // Can view reports
	PermissionsTable[PermImporter] = "importer" // User is allowed to handle data imports
	PermissionsTable[PermFileDrop] = "filedrop" // User is allowed to drop files onto IMQS Web
	PermissionsTable[PermHydroWorkOrderCreation] = "hydroworkordercreation" // User is allowed to view and use the hydrojet work order creation tool
	PermissionsTable[PermMm] = "mm" // MM
	PermissionsTable[PermMmWorkRequestView] = "mmworkrequestview" // Work Request View
	PermissionsTable[PermMmWorkRequestAddAndDelete] = "mmworkrequestaddanddelete" // Work Request Add/Delete
	PermissionsTable[PermMmWorkRequestUpdate] = "mmworkrequestupdate" // Work Request Update
	PermissionsTable[PermMmPmWorkRequestAddAndDelete] = "mmpmworkrequestaddanddelete" // MM Work Request Add/Delete
	PermissionsTable[PermMmPmWorkRequestUpdate] = "mmpmworkrequestupdate" // MM Work Request Update
	PermissionsTable[PermMmPmWorkRequestView] = "mmpmworkrequestview" // MM Work Request View
	PermissionsTable[PermMmPmRegionalManagerAddAndDelete] = "mmpmregionalmanageraddanddelete" // MM Work Request Regional Manager Add/Delete
	PermissionsTable[PermMmPmRegionalManagerUpdate] = "mmpmregionalmanagerupdate" // MM Work Request Regional Manager Update
	PermissionsTable[PermMmPmRegionalManagerView] = "mmpmregionalmanagerview" // MM Work Request Regional Manager View
	PermissionsTable[PermMmPmDivisionalManagerAddAndDelete] = "mmpmdivisionalmanageraddanddelete" // MM Work Request Divisional Manager Add/Delete
	PermissionsTable[PermMmPmDivisionalManagerUpdate] = "mmpmdivisionalmanagerupdate" // MM Work Request Divisional Manager Update
	PermissionsTable[PermMmPmDivisionalManagerView] = "mmpmdivisionalmanagerview" // MM Work Request Divisional Manager View
	PermissionsTable[PermMmPmGeneralManagerAddAndDelete] = "mmpmgeneralmanageraddanddelete" // MM Work Request General Manager Add/Delete
	PermissionsTable[PermMmPmGeneralManagerUpdate] = "mmpmgeneralmanagerupdate" // MM Work Request General Manager Update
	PermissionsTable[PermMmPmGeneralManagerView] = "mmpmgeneralmanagerview" // MM Work Request General Manager View
	PermissionsTable[PermMmPmRoutingDepartmentAddAndDelete] = "mmpmroutingdepartmentaddanddelete" // MM Work Request Routing Department Add/Delete
	PermissionsTable[PermMmPmRoutingDepartmentUpdate] = "mmpmroutingdepartmentupdate" // MM Work Request Routing Department Update
	PermissionsTable[PermMmPmRoutingDepartmentView] = "mmpmroutingdepartmentview" // MM Work Request Routing Department View
	PermissionsTable[PermMmFormBuilder] = "mmformbuilder" // MM Form Builder
	PermissionsTable[PermMmLookup] = "mmlookup" // MM Lookup
	PermissionsTable[PermMmServiceRequest] = "mmservicerequest" // MM Service Request
	PermissionsTable[PermMmSetup] = "mmsetup" // MM Setup
	PermissionsTable[PermMmSuperUser] = "mmsuperuser" // MM Super User
	PermissionsTable[PermMmSetupWorkFlow] = "mmsetupworkflow" // MM Setup Workflow
	PermissionsTable[PermMmSetupPM] = "mmsetuppm" // MM Setup Preventative Maintenance
	PermissionsTable[PermMmSetupPMSchedule] = "mmsetuppmschedule" // MM Setup Preventative Maintenance Schedule
	PermissionsTable[PermMmIncidentLogger] = "mmincidentlogger" // MM Incident Logger
	PermissionsTable[PermMmResourceManagerView] = "mmresourcemanagerview" // MM Resource Manager View
	PermissionsTable[PermMmResourceManagerAddAndDelete] = "mmresourcemanageraddanddelete" // MM Resource Manager Add/Delete
	PermissionsTable[PermMmResourceManagerUpdate] = "mmresourcemanagerupdate" // MM Resource Manager Update
	PermissionsTable[PermMmTimeAndCostView] = "mmtimeandcostview" // MM Time and Cost View
	PermissionsTable[PermMmTimeAndCostAddAndDelete] = "mmtimeandcostaddanddelete" // MM Time and Cost Add/Delete
	PermissionsTable[PermMmTimeAndCostUpdate] = "mmtimeandcostupdate" // MM Time and Cost Update
	PermissionsTable[PermMmDocuments] = "mmdocuments" // MM Documents
	PermissionsTable[PermMmMeterMaintenance] = "mmmetermaintenance" // MM Meter Maintenance Map
	PermissionsTable[PermMmReAssignEditOfDisabledControl] = "mmreassigneditofdisabledcontrol" // Disabled controls become active for a user with this permission
	PermissionsTable[PermMmEmployeeView] = "mmemployeeview" // MM Employee View
	PermissionsTable[PermMmEmployeeAddAndDelete] = "mmemployeeaddanddelete" // MM Employee Add/Delete
	PermissionsTable[PermMmEmployeeUpdate] = "mmemployeeupdate" // MM Employee Update
	PermissionsTable[PermMmFleetView] = "mmfleetview" // MM Fleet View
	PermissionsTable[PermMmFleetAddAndDelete] = "mmfleetaddanddelete" // MM Fleet Add/Delete
	PermissionsTable[PermMmFleetUpdate] = "mmfleetupdate" // MM Fleet Update
	PermissionsTable[PermMmMaterialView] = "mmmaterialview" // MM Material View
	PermissionsTable[PermMmMaterialAddAndDelete] = "mmmaterialaddanddelete" // MM Material Add/Delete
	PermissionsTable[PermMmMaterialUpdate] = "mmmaterialupdate" // MM Material Update
	PermissionsTable[PermMmContractorView] = "mmcontractorview" // MM Contractor View
	PermissionsTable[PermMmContractorAddAndDelete] = "mmcontractoraddanddelete" // MM Contractor Add/Delete
	PermissionsTable[PermMmContractorUpdate] = "mmcontractorupdate" // MM Contractor Update
	PermissionsTable[PermMmContractorDocsView] = "mmcontractordocsview" // MM Contractor Documents View
	PermissionsTable[PermMmContractorDocsAddAndDelete] = "mmcontractordocsaddanddelete" // MM Contractor Documents Add/Delete
	PermissionsTable[PermMmContractorDocsUpdate] = "mmcontractordocsupdate" // MM Contractor Documents Update
	PermissionsTable[PermMmStandardTimesView] = "mmstandardtimesview" // MM Standard Times View
	PermissionsTable[PermMmStandardTimesAddAndDelete] = "mmstandardtimesaddanddelete" // MM Standard Times Add/Delete
	PermissionsTable[PermMmStandardTimesUpdate] = "mmstandardtimesupdate" // MM Standard Times Update
	PermissionsTable[PermMmTariffsView] = "mmtariffsview" // MM Tariffs View
	PermissionsTable[PermMmTariffsAddAndDelete] = "mmtariffsaddanddelete" // MM Tariffs Add/Delete
	PermissionsTable[PermMmTariffsUpdate] = "mmtariffsupdate" // MM Tariffs Update
	PermissionsTable[PermMmIncidentLoggerView] = "mmincidentloggerview" // MM Incident Logger View
	PermissionsTable[PermMmIncidentLoggerAddAndDelete] = "mmincidentloggeraddanddelete" // MM Incident Logger Add/Delete
	PermissionsTable[PermMmIncidentLoggerUpdate] = "mmincidentloggerupdate" // MM Incident Logger Update
	PermissionsTable[PermMmLeaveManagementView] = "mmleavemanagementview" // MM Leave Management View
	PermissionsTable[PermMmLeaveManagementAddAndDelete] = "mmleavemanagementaddanddelete" // MM Leave Management Add/Delete
	PermissionsTable[PermMmLeaveManagementUpdate] = "mmleavemanagementupdate" // MM Leave Management Update
	PermissionsTable[PermMmProjectCodeManagementView] = "mmprojectcodemanagementview" // MM Project Code Management View
	PermissionsTable[PermMmProjectCodeManagementAddAndDelete] = "mmprojectcodemanagementaddanddelete" // MM Project Code Management Add/Delete
	PermissionsTable[PermMmProjectCodeManagementUpdate] = "mmprojectcodemanagementupdate" // MM Project Code Management Update
	PermissionsTable[PermMmProjectSapManagementView] = "mmprojectsapmanagementview" // MM Project Sap Management View
	PermissionsTable[PermMmProjectSapManagementAddAndDelete] = "mmprojectsapmanagementaddanddelete" // MM Project Sap Management Add/Delete
	PermissionsTable[PermMmProjectSapManagementUpdate] = "mmprojectsapmanagementupdate" // MM Project Sap Management Update
	PermissionsTable[PermWipEnabled] = "wipenabled" // User is allowed to use the WIP module
	PermissionsTable[PermWipWorkflowStart] = "wipworkflowstart" // User is allowed to start a workflow
	PermissionsTable[PermWipWorkflowSuspend] = "wipworkflowsuspend" // User is allowed to suspend a workflow
	PermissionsTable[PermWipWorkflowDiscard] = "wipworkflowdiscard" // User is allowed to discard a workflow
	PermissionsTable[PermWipProjectView] = "wipprojectview" // User is allowed to view a WIP project
	PermissionsTable[PermWipProjectAdd] = "wipprojectadd" // User is allowed to add a WIP project
	PermissionsTable[PermWipProjectEdit] = "wipprojectedit" // User is allowed to edit a WIP project
	PermissionsTable[PermWipProjectDelete] = "wipprojectdelete" // User is allowed to delete a WIP project
	PermissionsTable[PermWipComponentView] = "wipcomponentview" // User is allowed to view a WIP component
	PermissionsTable[PermWipComponentAdd] = "wipcomponentadd" // User is allowed to add a WIP component
	PermissionsTable[PermWipComponentEdit] = "wipcomponentedit" // User is allowed to edit a WIP component
	PermissionsTable[PermWipComponentDelete] = "wipcomponentdelete" // User is allowed to delete a WIP component
	PermissionsTable[PermWipActualView] = "wipactualview" // User is allowed to view a WIP actual
	PermissionsTable[PermWipActualAdd] = "wipactualadd" // User is allowed to add a WIP actual
	PermissionsTable[PermWipActualEdit] = "wipactualedit" // User is allowed to edit a WIP actual
	PermissionsTable[PermWipActualDelete] = "wipactualdelete" // User is allowed to delete a WIP actual
	PermissionsTable[PermWipBudgetView] = "wipbudgetview" // User is allowed to view a WIP budget
	PermissionsTable[PermWipBudgetAdd] = "wipbudgetadd" // User is allowed to add a WIP budget
	PermissionsTable[PermWipBudgetEdit] = "wipbudgetedit" // User is allowed to edit a WIP budget
	PermissionsTable[PermWipBudgetDelete] = "wipbudgetdelete" // User is allowed to delete a WIP budget
	PermissionsTable[PermWipCapitalize] = "wipcapitalize" // User is allowed to perform capitalization tasks
	PermissionsTable[PermEnergyConfigAddAndDelete] = "energyconfigaddanddelete" // User is allowed to add and delete an energy site configuration
	PermissionsTable[PermEnergyConfigUpdate] = "energyconfigupdate" // User is allowed to update an energy site configuration
	PermissionsTable[PermEnergyConfigView] = "energyconfigview" // User is allowed to view an energy site configuration
	PermissionsTable[PermEnergyConfigLockUnlock] = "energyconfiglockunlock" // User is allowed to lock/unlock site configuration
	PermissionsTable[PermEnergyGeneratorsStartStop] = "energygeneratorsstartstop" // User is allowed to start/stop generators
	PermissionsTable[PermEnergyGateUnlock] = "energygateunlock" // User is allowed to unlock gate
	PermissionsTable[PermEnergySimSwitch] = "energysimswitch" // User is allowed to switch site controller SIM
	PermissionsTable[PermEnergyAlarmsMute] = "energyalarmsmute" // User is allowed to mute site alarms
	PermissionsTable[PermEnergyAnalogDataRefresh] = "energyanalogdatarefresh" // User is allowed to refresh analog data
	PermissionsTable[PermEnergyControllerFirmwareVersionRefresh] = "energycontrollerfirmwareversionrefresh" // User is allowed to refresh controller firmware version
	PermissionsTable[PermEnergyTimeSync] = "energytimesync" // User is allowed to synchronise controller clock with server
	PermissionsTable[PermEnergyAlarmsAcknowledge] = "energyalarmsacknowledge" // User is allowed to acknowledge alarms
	PermissionsTable[PermEnergyGateAccessFirmwareVersionRefresh] = "energygateaccessfirmwareversionrefresh" // User is allowed to refresh gate access firmware version
	PermissionsTable[PermEnergySiteInfoEdit] = "energysiteinfoedit" // User is allowed to edit site info
	PermissionsTable[PermEnergySitePACEdit] = "energysitepacedit" // User is allowed to edit site PAC
	PermissionsTable[PermDevconProjectEdit] = "devconprojectedit" // User is allowed to edit projects
	PermissionsTable[PermDevconProjectCreate] = "devconprojectcreate" // User is allowed to create new projects
	PermissionsTable[PermDevconProjectDelete] = "devconprojectdelete" // User is allowed to delete projects
	PermissionsTable[PermDevconProjectMerge] = "devconprojectmerge" // User is allowed to merge projects
	PermissionsTable[PermDevconApplicationEdit] = "devconapplicationedit" // User is allowed to edit applications
	PermissionsTable[PermDevconApplicationCreate] = "devconapplicationcreate" // User is allowed to create new applications
	PermissionsTable[PermDevconApplicationDelete] = "devconapplicationdelete" // User is allowed to delete applications
	PermissionsTable[PermDevconLookupEdit] = "devconlookupedit" // User is allowed to edit lookups, such as applicant and organisation
	PermissionsTable[PermDevconLookupCreate] = "devconlookupcreate" // User is allowed to create new lookups
	PermissionsTable[PermDevconLookupDelete] = "devconlookupdelete" // User is allowed to delete lookups
	PermissionsTable[PermDevconLookupManagement] = "devconlookupmanagement" // User is allowed to access the lookup management page and manage lookups
	PermissionsTable[PermDevconTemplateManagement] = "devcontemplatemanagement" // User is allowed to access the feedback template management page and update templates
	PermissionsTable[PermDevconReportViewing] = "devconreportviewing" // User is allowed to view reports
	PermissionsTable[PermImqsDeveloper] = "imqsdeveloper" // IMQS Developer
	PermissionsTable[PermAssetsModuleAccess] = "assetsmoduleaccess" // User is allowed to access the Assets module
	PermissionsTable[PermCogtaModuleAccess] = "cogtamoduleaccess" // User is allowed to access the COGTA module
	PermissionsTable[PermConditionAssessmentModuleAccess] = "conditionassessmentmoduleaccess" // User is allowed to access the Condition Assessment module
	PermissionsTable[PermDocumentExplorerModuleAccess] = "documentexplorermoduleaccess" // User is allowed to access the Document Explorer module
	PermissionsTable[PermElectricityModuleAccess] = "electricitymoduleaccess" // User is allowed to access the Electricity module
	PermissionsTable[PermElectricityDemandModuleAccess] = "electricitydemandmoduleaccess" // User is allowed to access the Electricity Demand module
	PermissionsTable[PermElectricityDemoModuleAccess] = "electricitydemomoduleaccess" // User is allowed to access the Electricity Demo module
	PermissionsTable[PermEnergyModuleAccess] = "energymoduleaccess" // User is allowed to access the Energy module
	PermissionsTable[PermIndigentModuleAccess] = "indigentmoduleaccess" // User is allowed to access the Indigent module
	PermissionsTable[PermLandUseModuleAccess] = "landusemoduleaccess" // User is allowed to access the Land Use module
	PermissionsTable[PermMaintenanceManagementModuleAccess] = "maintenancemanagementmoduleaccess" // User is allowed to access the Maintenance Management module
	PermissionsTable[PermMeterMaintenanceModuleAccess] = "metermaintenancemoduleaccess" // User is allowed to access the Meter Maintenance module
	PermissionsTable[PermPcsModuleAccess] = "pcsmoduleaccess" // User is allowed to access the PCS module
	PermissionsTable[PermPropertiesandBuildingsModuleAccess] = "propertiesandbuildingsmoduleaccess" // User is allowed to access the Properties and Buildings module
	PermissionsTable[PermRevenueEnhancementModuleAccess] = "revenueenhancementmoduleaccess" // User is allowed to access the Revenue Enhancement module
	PermissionsTable[PermRoadsModuleAccess] = "roadsmoduleaccess" // User is allowed to access the Roads module
	PermissionsTable[PermSewerModuleAccess] = "sewermoduleaccess" // User is allowed to access the Sewer module
	PermissionsTable[PermSewerPRPModuleAccess] = "sewerprpmoduleaccess" // User is allowed to access the Sewer PRP module
	PermissionsTable[PermStormwaterModuleAccess] = "stormwatermoduleaccess" // User is allowed to access the Stormwater module
	PermissionsTable[PermTelcosModuleAccess] = "telcosmoduleaccess" // User is allowed to access the Telcos module
	PermissionsTable[PermWaterModuleAccess] = "watermoduleaccess" // User is allowed to access the Water module
	PermissionsTable[PermWaterDemandModuleAccess] = "waterdemandmoduleaccess" // User is allowed to access the Water Demand module
	PermissionsTable[PermWaterPRPModuleAccess] = "waterprpmoduleaccess" // User is allowed to access the Water PRP module
	PermissionsTable[PermWipModuleAccess] = "wipmoduleaccess" // User is allowed to access the WIP module
	PermissionsTable[PermDevelopmentControlModuleAccess] = "developmentcontrolmoduleaccess" // User is allowed to access the Development Control module

}
