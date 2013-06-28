package main

import (
	"fmt"
	"github.com/IMQS/authaus"
	"github.com/IMQS/imqsauth/imqsauth"
	"os"
	"strings"
)

func showhelp() {
	help := `
imqsauth -c configfile command [options]

  commands
    createdb          Create the postgres database
    resetauthgroups   Reset the 'imqsadmin' and 'user' groups
    createuser        Create a user in the authentication system
    setpassword       Set a user's password
    permgroupadd      Add a group to a permit
    permgroupdel      Remove a group from a permit
    permshow          Show the groups of a permit
    run               Run the service

  mandatory options
    -c configfile     Specify the authaus config file
`
	fmt.Print(help)
}

func main() {
	os.Exit(realMain())
}

func realMain() (result int) {
	result = 0
	args := os.Args[1:]
	defer func() {
		if err := recover(); err != nil {
			result = 1
			fmt.Printf("%v\n", err)
		}
	}()
	if len(args) == 0 {
		showhelp()
		return 0
	}
	command := ""
	configFile := ""
	lastRecognizedArgument := 0
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg[0:1] == "-" && i < len(args)-1 {
			// options followed by a single value
			switch arg {
			case "-c":
				configFile = args[i+1]
				lastRecognizedArgument = i + 1
			case "help":
				fallthrough
			case "-help":
				fallthrough
			case "--help":
				fallthrough
			case "?":
				fallthrough
			case "-?":
				fallthrough
			case "--?":
				showhelp()
				return 0
			default:
				panic("Unrecognized option " + arg)
			}
			i += 1
		} else if command == "" && arg[0:1] != "-" {
			command = arg
			lastRecognizedArgument = i
		}
	}
	cmdargs := args[lastRecognizedArgument+1:]

	ic := &imqsauth.ImqsCentral{}
	ic.Config = &authaus.Config{}

	if configFile == "" {
		showhelp()
		return 1
	}

	if err := ic.Config.LoadFile(configFile); err != nil {
		fmt.Printf("Error loading config file '%v': %v\n", configFile, err)
		return 1
	}

	handler := func() {
		ic.RunHttp()
	}

	success := true

	switch command {
	case "createdb":
		success = createDB(ic.Config)
	case "run":
		if !authaus.RunAsService(handler) {
			success = false
			fmt.Print(ic.RunHttp())
		}
	default:
		success = genericFunc(ic, command, cmdargs)
	}

	if ic.Central != nil {
		ic.Central.Close()
	}

	if success {
		return 0
	} else {
		return 1
	}
}

func createDB(config *authaus.Config) (success bool) {
	success = true
	if err := authaus.SqlCreateSchema_User(&config.PermitDB.DB); err != nil {
		success = false
		fmt.Printf("Error creating User database: %v\n", err)
	} else {
		fmt.Print("User database schema is up to date\n")
	}

	if err := authaus.SqlCreateSchema_Session(&config.SessionDB.DB); err != nil {
		success = false
		fmt.Printf("Error creating Session database: %v\n", err)
	} else {
		fmt.Print("Session database schema is up to date\n")
	}

	if err := authaus.SqlCreateSchema_RoleGroupDB(&config.RoleGroupDB.DB); err != nil {
		success = false
		fmt.Printf("Error creating Role Group database: %v\n", err)
	} else {
		fmt.Print("Role Group database schema is up to date\n")
	}

	return success
}

func loadOrCreateGroup(icentral *imqsauth.ImqsCentral, groupName string, createIfNotExist bool) (*authaus.AuthGroup, error) {
	if existing, eget := icentral.Central.GetRoleGroupDB().GetByName(groupName); eget == nil {
		return existing, nil
	} else if strings.Index(eget.Error(), authaus.ErrGroupNotExist.Error()) == 0 {
		if createIfNotExist {
			group := &authaus.AuthGroup{}
			group.Name = groupName
			if ecreate := icentral.Central.GetRoleGroupDB().InsertGroup(group); ecreate == nil {
				fmt.Printf("Group %v created\n", groupName)
				return group, nil
			} else {
				fmt.Printf("Error inserting group %v: %v\n", groupName, ecreate)
				return nil, ecreate
			}
		} else {
			return nil, eget
		}
	} else {
		return nil, eget
	}
}

func saveGroup(icentral *imqsauth.ImqsCentral, group *authaus.AuthGroup) bool {
	if eupdate := icentral.Central.GetRoleGroupDB().UpdateGroup(group); eupdate == nil {
		fmt.Printf("Group %v updated\n", group.Name)
		return true
	} else {
		fmt.Printf("Error updating group of %v: %v\n", group.Name, eupdate)
		return false
	}
}

func resetGroup(icentral *imqsauth.ImqsCentral, group *authaus.AuthGroup) bool {
	if existing, eget := icentral.Central.GetRoleGroupDB().GetByName(group.Name); eget == nil {
		group.ID = existing.ID
		existing.PermList = group.PermList
		if eupdate := icentral.Central.GetRoleGroupDB().UpdateGroup(existing); eupdate == nil {
			fmt.Printf("Group %v updated\n", group.Name)
			return true
		} else {
			fmt.Printf("Error updating group of %v: %v\n", group.Name, eupdate)
		}
	} else if strings.Index(eget.Error(), authaus.ErrGroupNotExist.Error()) == 0 {
		if ecreate := icentral.Central.GetRoleGroupDB().InsertGroup(group); ecreate == nil {
			fmt.Printf("Group %v created\n", group.Name)
			return true
		} else {
			fmt.Printf("Error inserting group %v: %v\n", group.Name, ecreate)
		}
	} else {
		fmt.Printf("Error updating (retrieving) group %v: %v\n", group.Name, eget)
	}
	return false
}

func permGroupAddOrDel(icentral *imqsauth.ImqsCentral, identity string, groupname string, isAdd bool) (success bool) {
	perm, eGetPermit := icentral.Central.GetPermit(identity)
	if eGetPermit != nil && strings.Index(eGetPermit.Error(), authaus.ErrIdentityPermitNotFound.Error()) == 0 {
		perm = &authaus.Permit{}
	} else if eGetPermit != nil {
		fmt.Printf("Error retrieving permit: %v\n", eGetPermit)
		return false
	}

	if group, eGetGroup := icentral.Central.GetRoleGroupDB().GetByName(groupname); eGetGroup == nil {
		if groups, eDecode := authaus.DecodePermit(perm.Roles); eDecode == nil {
			haveGroup := false
			for i, gid := range groups {
				if gid == group.ID && !isAdd {
					groups = append(groups[0:i], groups[i+1:]...)
				} else if gid == group.ID && isAdd {
					haveGroup = true
				}
			}
			if !haveGroup && isAdd {
				groups = append(groups, group.ID)
			}
			perm.Roles = authaus.EncodePermit(groups)
			if eSet := icentral.Central.SetPermit(identity, perm); eSet == nil {
				fmt.Printf("Set permit for %v\n", identity)
				return true
			} else {
				fmt.Printf("Error setting permit: %v\n", eSet)
			}
		} else {
			fmt.Printf("Error decoding permit: %v\n", eDecode)
		}
	} else {
		fmt.Printf("Error retrieving group '%v': %v\n", groupname, eGetGroup)
	}

	return false
}

func permShow(icentral *imqsauth.ImqsCentral, identity string) (success bool) {
	if perm, e := icentral.Central.GetPermit(identity); e == nil {
		if groups, eDecode := authaus.DecodePermit(perm.Roles); eDecode == nil {
			if groupNames, eGetNames := authaus.GroupIDsToNames(groups, icentral.Central.GetRoleGroupDB()); eGetNames == nil {
				fmt.Printf("%v: ", identity)
				for _, gname := range groupNames {
					fmt.Printf("%v ", gname)
				}
				fmt.Printf("\n")
				return true
			} else {
				fmt.Printf("Error converting group IDs to names: %v\n", eGetNames)
			}
		} else {
			fmt.Printf("Error decoding permit: %v\n", eDecode)
		}
	} else {
		fmt.Printf("Error retrieving permit: %v\n", e)
	}
	return false
}

func genericFunc(icentral *imqsauth.ImqsCentral, function string, args []string) (success bool) {
	var err error
	icentral.Central, err = authaus.NewCentralFromConfig(icentral.Config)
	if err == nil {
		defer icentral.Central.Close()
		defer func() {
			if e := recover(); e != nil {
				fmt.Printf("Error: %v\n", e)
				success = false
			}
		}()
		switch function {
		case "resetauthgroups":
			return resetAuthGroups(icentral)
		case "createuser":
			if len(args) != 2 {
				panic("createuser identity password")
			}
			return createUser(icentral, args[0], args[1])
		case "setpassword":
			if len(args) != 2 {
				panic("setpassword identity password")
			}
			return setPassword(icentral, args[0], args[1])
		case "permgroupadd":
			if len(args) != 2 {
				panic("permgroupadd identity groupname")
			}
			return permGroupAddOrDel(icentral, args[0], args[1], true)
		case "permgroupdel":
			if len(args) != 2 {
				panic("permgroupdel identity groupname")
			}
			return permGroupAddOrDel(icentral, args[0], args[1], false)
		case "permshow":
			if len(args) != 1 {
				panic("permshow identity")
			}
			return permShow(icentral, args[0])
		default:
			fmt.Printf("Unrecognized command '%v'\n", function)
			return false
		}
	} else {
		fmt.Printf("Error: %v\n", err)
		return false
	}
}

func createUser(icentral *imqsauth.ImqsCentral, identity string, password string) bool {
	if e := icentral.Central.CreateAuthenticatorIdentity(identity, password); e == nil {
		fmt.Printf("Created user %v\n", identity)
		return true
	} else {
		fmt.Printf("Error creating %v: %v\n", identity, e)
		return false
	}
}

func setPassword(icentral *imqsauth.ImqsCentral, identity string, password string) bool {
	if e := icentral.Central.SetPassword(identity, password); e == nil {
		fmt.Printf("Reset password of %v\n", identity)
		return true
	} else {
		fmt.Printf("Error resetting password: %v\n", e)
		return false
	}
}

func ensureGroupHasBits(icentral *imqsauth.ImqsCentral, groupName string, perms []authaus.PermissionU16) bool {
	if group, e := loadOrCreateGroup(icentral, groupName, true); e == nil {
		for _, perm := range perms {
			group.AddPermBit(perm)
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

// Reset auth groups to a sane state. After running this, you should be able to use
// the web interface to do everything else. That's the idea at least (the web interface has yet to be built).
func resetAuthGroups(icentral *imqsauth.ImqsCentral) bool {
	ok := true
	ok = ok && ensureGroupHasBits(icentral, "imqsadmin", []authaus.PermissionU16{imqsauth.PermAdmin, imqsauth.PermEnabled})
	ok = ok && ensureGroupHasBits(icentral, "user", []authaus.PermissionU16{imqsauth.PermEnabled})
	if !ok {
		return false
	}

	// Reset the perm bits of the imqsadmin user
	if group_imqsadmin, eLoad := loadOrCreateGroup(icentral, "imqsadmin", false); eLoad != nil {
		fmt.Printf("Error loading imqsadmin group: %v\n", eLoad)
		return false
	} else {
		pgroups := make([]authaus.GroupIDU32, 1, 1)
		pgroups[0] = group_imqsadmin.ID
		permit := &authaus.Permit{}
		permit.Roles = authaus.EncodePermit(pgroups)
		if eSetPermit := icentral.Central.SetPermit("imqsadmin", permit); eSetPermit != nil {
			fmt.Printf("Error setting permit: %v\n", eSetPermit)
			return false
		}
	}

	return true
}
