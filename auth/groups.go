package imqsauth

import (
	"fmt"

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
		{RoleGroupReportCreator, authaus.PermissionList{PermReportCreator}},
		{RoleGroupReportViewer, authaus.PermissionList{PermReportViewer}},
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
