package imqsauth

import (
	"fmt"
	"github.com/IMQS/authaus"
)

const (
	// Hard-coded group names
	RoleGroupAdmin   = "admin"
	RoleGroupEnabled = "enabled"
)

// Reset auth groups to a sane state. After running this, you should be able to use
// the web interface to do everything else. That's the idea at least (the web interface has yet to be built).
func ResetAuthGroups(icentral *ImqsCentral) bool {
	ok := true
	ok = ok && ModifyGroup(icentral, GroupModifySet, RoleGroupAdmin, authaus.PermissionList{PermAdmin})
	ok = ok && ModifyGroup(icentral, GroupModifySet, RoleGroupEnabled, authaus.PermissionList{PermEnabled})
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
