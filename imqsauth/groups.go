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

// Reset auth groups to a sane state. After running this, you should be able to use
// the web interface to do everything else. That's the idea at least.
func ResetAuthGroups(icentral *ImqsCentral) bool {
	ok := true

	// mandatory groups, used by a lot of things across the entire IMQS ecosystem
	ok = ok && ModifyGroup(icentral, GroupModifySet, RoleGroupAdmin, authaus.PermissionList{PermAdmin})
	ok = ok && ModifyGroup(icentral, GroupModifySet, RoleGroupEnabled, authaus.PermissionList{PermEnabled})

	// not-so-mandatory groups, used by a few specific things
	// This list was ported from https://github.com/IMQS/InfrastructureBin/blob/dd525a2d4ab7ec7b81aa8111b264bc72eb827dbd/ops/installers/03_deploy_win.rb
	ok = ok && ModifyGroup(icentral, GroupModifyAdd, RoleGroupFileDrop, authaus.PermissionList{PermFileDrop})
	ok = ok && ModifyGroup(icentral, GroupModifyAdd, RoleGroupReportCreator, authaus.PermissionList{PermReportCreator})
	ok = ok && ModifyGroup(icentral, GroupModifyAdd, RoleGroupReportViewer, authaus.PermissionList{PermReportViewer})

	if !ok {
		return false
	}
	return true
}

func ModifyGroup(icentral *ImqsCentral, mode GroupModifyMode, groupName string, perms authaus.PermissionList) bool {
	if group, e := loadOrCreateGroup(icentral, groupName, true); e == nil {
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
		if saveGroup(icentral, group) {
			return true
		} else {
			return false
		}
	} else {
		fmt.Printf("Error retrieving group '%v': %v\n", groupName, e)
		return false
	}
}

type GroupModifyMode int

const (
	GroupModifySet GroupModifyMode = iota
	GroupModifyAdd
	GroupModifyRemove
)

func saveGroup(icentral *ImqsCentral, group *authaus.AuthGroup) bool {
	if err := icentral.Central.GetRoleGroupDB().UpdateGroup(group); err == nil {
		fmt.Printf("Group %v updated\n", group.Name)
		return true
	} else {
		fmt.Printf("Error updating group of %v: %v\n", group.Name, err)
		return false
	}
}

func loadOrCreateGroup(icentral *ImqsCentral, groupName string, createIfNotExist bool) (*authaus.AuthGroup, error) {
	if group, error := authaus.LoadOrCreateGroup(icentral.Central.GetRoleGroupDB(), groupName, createIfNotExist); error == nil {
		fmt.Printf("Group %v created\n", groupName)
		return group, nil
	} else {
		fmt.Printf("Error creating group %v, %v ", groupName, error)
		return nil, error
	}
}
