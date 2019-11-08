package imqsauth

import (
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"time"

	"github.com/IMQS/authaus"
)

const (
	// Hard-coded group names, which a lot of the system depends on
	RoleGroupAdmin   = "admin"
	RoleGroupEnabled = "enabled"
	// Hard-coded group names, which used to be created by our Windows ruby installer scripts.
	// Since moving to docker, we've moved these elements into ResetAuthGroups
	RoleGroupFileDrop      = "filedrop"
	RoleGroupReportCreator = "reportcreator"
	RoleGroupReportViewer  = "reportviewer"
	RoleGroupPCS           = "PCS"
)

type predefinedGroup struct {
	groupName   string
	permissions authaus.PermissionList
}

// Reset auth groups to a sane state. After running this, you should be able to use
// the web interface to do everything else. That's the idea at least.
func ResetAuthGroups(icentral *ImqsCentral) error {

	// mandatory groups, used by a lot of things across the entire IMQS ecosystem
	mandatory := []predefinedGroup{
		{RoleGroupAdmin, authaus.PermissionList{PermAdmin}},
		{RoleGroupEnabled, authaus.PermissionList{PermEnabled}},
	}

	// not-so-mandatory groups, used by a few specific things
	// This list was ported from https://github.com/IMQS/InfrastructureBin/blob/dd525a2d4ab7ec7b81aa8111b264bc72eb827dbd/ops/installers/03_deploy_win.rb
	others := []predefinedGroup{
		{RoleGroupFileDrop, authaus.PermissionList{PermFileDrop}},
		// Commented out - See RollbackUnwantedgroups
		// {RoleGroupReportCreator, authaus.PermissionList{PermReportCreator}},
		// {RoleGroupReportViewer, authaus.PermissionList{PermReportViewer}},
		// // [2019-09-03] PCS access used to be a permission in the "Global" module, but today we moved to be the same as other modules.
		// // HOWEVER, we retained the permission number (3). So basically, we renamed the PCS permission, and we moved it from
		// // "Global" into the "PCS" module. As part of this exercise, we also got rid of the old "PCS" permission, which was 1112.
		// //{RoleGroupPCS, authaus.PermissionList{PermPcs}},
		// {"DevelopmentControl", authaus.PermissionList{PermDevelopmentControlModuleAccess}},
		// {"DevelopmentControl - Admin", authaus.PermissionList{PermDevelopmentControlModuleAccess, PermDevconProjectEdit, PermDevconProjectCreate, PermDevconProjectDelete, PermDevconProjectMerge, PermDevconApplicationEdit, PermDevconApplicationCreate, PermDevconApplicationDelete, PermDevconLookupEdit, PermDevconLookupCreate, PermDevconLookupDelete, PermDevconLookupManagement, PermDevconTemplateManagement, PermDevconReportViewing}},
		// {"DevelopmentControl - Operator", authaus.PermissionList{PermDevelopmentControlModuleAccess, PermDevconProjectEdit, PermDevconProjectCreate, PermDevconProjectDelete, PermDevconProjectMerge, PermDevconApplicationEdit, PermDevconApplicationCreate, PermDevconApplicationDelete, PermDevconLookupEdit, PermDevconLookupCreate, PermDevconLookupDelete, PermDevconReportViewing}},
		// {"DevelopmentControl - Service Desk User", authaus.PermissionList{PermDevelopmentControlModuleAccess, PermDevconProjectEdit, PermDevconProjectCreate, PermDevconProjectDelete, PermDevconApplicationEdit, PermDevconApplicationCreate, PermDevconApplicationDelete, PermDevconLookupEdit, PermDevconLookupCreate, PermDevconLookupDelete}},
	}

	// Create a group for every module. If you belong to one of these groups, then you are allowed
	// to access that module.
	// Commented out - See RollbackUnwantedgroups
	// for name, perm := range PermissionModuleMap {
	// 	others = append(others, predefinedGroup{name, authaus.PermissionList{perm}})
	// }

	// Commented out - See RollbackUnwantedgroups
	// Create the "AllModuleAccess" group, which can access any module
	// allModuleAccess := authaus.PermissionList{}
	// for _, perm := range PermissionModuleMap {
	// 	allModuleAccess = append(allModuleAccess, perm)
	// }
	// others = append(others, predefinedGroup{"AllModuleAccess", allModuleAccess})

	// See comment above, about PCS, from 2019-09-03.
	// Basically, we got rid of 1112, which no part of our system ever respected, and we replaced it
	// with 3, which PCS has respected since many years ago.
	if err := ModifyGroup(icentral, GroupModifyRemove, "PCS", authaus.PermissionList{1112}); err != nil {
		return err
	}

	for _, p := range mandatory {
		if err := ModifyGroup(icentral, GroupModifySet, p.groupName, p.permissions); err != nil {
			return err
		}
	}

	for _, p := range others {
		if err := ModifyGroup(icentral, GroupModifyAdd, p.groupName, p.permissions); err != nil {
			return err
		}
	}

	return nil
}

func RollbackUnwantedGroupsOnce(icentral *ImqsCentral) error {
	if time.Now().Year() > 2019 {
		// If you're in 2020, then you should be able to get rid of all of this rollback code
		return nil
	}
	if runtime.GOOS == "linux" {
		// This fix was only necessary for clients on Windows
		return nil
	}
	onceFile := "c:/imqsvar/cache/auth-groups-rolled-back"
	if _, err := os.Stat(onceFile); err == nil {
		return nil
	}
	err := RollbackUnwantedGroups(icentral)
	if err != nil {
		return err
	}
	ioutil.WriteFile(onceFile, []byte("yes"), 0644)
	return nil
}

// RollbackUnwantedGroups was created on 8 November 2019.
// On 4 September a change was comitted (https://github.com/IMQS/imqsauth/commit/a30698f3432d213a9e4b50789b9482f028c80632) which
// automatically created a bunch of groups. After this was rolled out, we discovered that customers REALLY don't want this.
// So this function reverses those automatic group creations.
// Once it's rolled out to clients, we can delete this function.
func RollbackUnwantedGroups(icentral *ImqsCentral) error {
	icentral.Central.Log.Infof("Rolling back unwanted groups - starting")

	// Step 1: Figure out which groups have zero members
	users, err := icentral.Central.GetAuthenticatorIdentities(authaus.GetIdentitiesFlagNone)
	if err != nil {
		return err
	}

	permits, err := icentral.Central.GetPermits()
	if err != nil {
		return err
	}

	groups, err := icentral.Central.GetRoleGroupDB().GetGroups()
	if err != nil {
		return err
	}

	groupTouched := map[authaus.GroupIDU32]bool{}

	for _, user := range users {
		if permits[user.UserId] == nil {
			// icentral.Central.Log.Infof("Rolling back unwanted groups - user %v (%v) has no permit", user.UserId, user.Username)
			continue
		}
		userGroups, err := authaus.DecodePermit(permits[user.UserId].Roles)
		if err != nil {
			return err
		}
		for _, g := range userGroups {
			groupTouched[g] = true
		}
	}

	emptyGroups := map[string]*authaus.AuthGroup{}
	for _, g := range groups {
		if !groupTouched[g.ID] {
			emptyGroups[g.Name] = g
		}
	}

	others := []string{
		RoleGroupReportCreator,
		RoleGroupReportViewer,
		"DevelopmentControl",
		"DevelopmentControl - Admin",
		"DevelopmentControl - Operator",
		"DevelopmentControl - Service Desk User",
	}
	for name := range PermissionModuleMap {
		others = append(others, name)
	}
	others = append(others, "AllModuleAccess")

	for _, name := range others {
		if g, ok := emptyGroups[name]; ok {
			icentral.Central.Log.Infof("Deleting unwanted and empty group %v", g.Name)
			if err := icentral.Central.GetRoleGroupDB().DeleteGroup(g); err != nil {
				icentral.Central.Log.Errorf("Failed to delete group %v: %v", name, err)
			}
		}
	}

	icentral.Central.Log.Infof("Rolling back unwanted groups - finished")

	return nil
}

func ModifyGroup(icentral *ImqsCentral, mode GroupModifyMode, groupName string, perms authaus.PermissionList) error {
	group, err := loadOrCreateGroup(icentral, groupName, true)
	if err != nil {
		return err
	}

	switch mode {
	case GroupModifyAdd:
		for _, perm := range perms {
			group.AddPerm(perm)
		}
	case GroupModifyRemove:
		for _, perm := range perms {
			group.RemovePerm(perm)
		}
	case GroupModifySet:
		group.PermList = make(authaus.PermissionList, len(perms))
		copy(group.PermList, perms)
	default:
		panic(fmt.Sprintf("Unrecognized permission set mode %v", mode))
	}

	return saveGroup(icentral, group)
}

type GroupModifyMode int

const (
	GroupModifySet GroupModifyMode = iota
	GroupModifyAdd
	GroupModifyRemove
)

func saveGroup(icentral *ImqsCentral, group *authaus.AuthGroup) error {
	if err := icentral.Central.GetRoleGroupDB().UpdateGroup(group); err != nil {
		return fmt.Errorf("Error updating group %v: %v", group.Name, err)
	}
	return nil
}

func loadOrCreateGroup(icentral *ImqsCentral, groupName string, createIfNotExist bool) (*authaus.AuthGroup, error) {
	group, err := authaus.LoadOrCreateGroup(icentral.Central.GetRoleGroupDB(), groupName, createIfNotExist)
	if err != nil {
		return nil, fmt.Errorf("Error loading group %v: %v", groupName, err)
	}
	return group, nil
}
