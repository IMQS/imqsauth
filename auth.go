package main

import (
	"fmt"
	"github.com/IMQS/authaus"
	"github.com/IMQS/imqsauth/imqsauth"
	"log"
	"os"
	"strings"
)

const TestConfig1 = "!TESTCONFIG1"
const TestPort = 3377

const (
	RoleGroupAdmin   = "admin"
	RoleGroupEnabled = "enabled"
)

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
	// Add one to the end, so that we don't have to worry about reading past the end of the arguments list
	args = append(args, "")
	command := ""
	configFile := ""
	yfconfigFile := ""
	lastRecognizedArgument := 0
	helpCmd := false
	for i := 0; i < len(args)-1; i++ {
		arg := args[i]
		if arg[0:1] == "-" {
			switch arg {
			case "-c":
				configFile = args[i+1]
				lastRecognizedArgument = i + 1
			case "-y":
				yfconfigFile = args[i+1]
				lastRecognizedArgument = i + 1
			case "-help":
				fallthrough
			case "--help":
				fallthrough
			case "-?":
				fallthrough
			case "--?":
				helpCmd = true
			}
			i += 1
		} else if command == "" {
			command = arg
			lastRecognizedArgument = i
		}
	}
	cmdargsRaw := args[lastRecognizedArgument+1 : len(args)-1]

	if helpCmd || command == "help" || command == "?" {
		showhelp_cmd(command)
		return 0
	}

	cmdOptions := make(map[string]string)
	cmdArgs := []string{}
	for _, v := range cmdargsRaw {
		if v[0:1] == "-" {
			cmdOptions[v[1:]] = ""
		} else {
			cmdArgs = append(cmdArgs, v)
		}
	}

	ic := &imqsauth.ImqsCentral{}
	ic.Config = &authaus.Config{}
	ic.Yellowfin = &imqsauth.Yellowfin{Enabled: false}

	if configFile == "" {
		showhelp()
		return 1
	}

	isTestConfig := loadTestConfig(ic, configFile)

	if !isTestConfig {
		if err := ic.Config.LoadFile(configFile); err != nil {
			fmt.Printf("Error loading config file '%v': %v\n", configFile, err)
			return 1
		}
		if yfconfigFile != "" {
			if err := ic.Yellowfin.LoadConfig(yfconfigFile); err != nil {
				fmt.Printf("Error loading config file '%v': %v\n", yfconfigFile, err)
				return 1
			}
		}
	}

	handler := func() error {
		if isTestConfig {
			return ic.RunHttp()
		} else {
			return ic.LoadConfigAndRunHttp()
		}
	}
	handlerNoRetVal := func() {
		handler()
	}

	success := true

	switch command {
	case "createdb":
		success = createDB(ic.Config)
	case "run":
		if !authaus.RunAsService(handlerNoRetVal) {
			success = false
			fmt.Print(handler())
		}
	case "":
		showhelp()
		success = false
	default:
		success = genericFunc(ic, command, cmdOptions, cmdArgs)
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

func loadTestConfig(ic *imqsauth.ImqsCentral, testConfigName string) bool {
	if testConfigName == TestConfig1 {
		ic.Config.HTTP.Bind = "127.0.0.1"
		ic.Config.HTTP.Port = TestPort
		ic.Central = authaus.NewCentralDummy(log.New(os.Stdout, "", 0))
		resetAuthGroups(ic)
		ic.Central.CreateAuthenticatorIdentity("joe", "JOE")
		ic.Central.CreateAuthenticatorIdentity("admin", "ADMIN")
		ic.Central.CreateAuthenticatorIdentity("admin_disabled", "ADMIN_DISABLED")
		groupAdmin, _ := ic.Central.GetRoleGroupDB().GetByName(RoleGroupAdmin)
		groupEnabled, _ := ic.Central.GetRoleGroupDB().GetByName(RoleGroupEnabled)
		permitEnabled := &authaus.Permit{}
		permitEnabled.Roles = authaus.EncodePermit([]authaus.GroupIDU32{groupEnabled.ID})
		permitAdminEnabled := &authaus.Permit{}
		permitAdminEnabled.Roles = authaus.EncodePermit([]authaus.GroupIDU32{groupAdmin.ID, groupEnabled.ID})
		permitAdminDisabled := &authaus.Permit{}
		permitAdminDisabled.Roles = authaus.EncodePermit([]authaus.GroupIDU32{groupAdmin.ID})
		ic.Central.SetPermit("joe", permitEnabled)
		ic.Central.SetPermit("admin", permitAdminEnabled)
		ic.Central.SetPermit("admin_disabled", permitAdminDisabled)
		ic.Yellowfin.Enabled = false
		return true
	}
	return false
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
		// Tolerate a non-existing identity. We are going to create the permit for this identity.
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

func dumpOptions(options map[string]string) string {
	r := ""
	for k, _ := range options {
		r += k + ", "
	}
	return r[0 : len(r)-2]
}

func genericFunc(icentral *imqsauth.ImqsCentral, function string, options map[string]string, args []string) (success bool) {
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
		// NOTE: We should move all of this arbitrary option checking out of here and into some centralized error handling thing
		switch function {
		case "resetauthgroups":
			if len(options) != 0 {
				panic("Unrecognized option " + dumpOptions(options))
			}
			return resetAuthGroups(icentral)
		case "createuser":
			if len(args) != 2 {
				panic("Must have identity and password")
			}
			return createUser(icentral, options, args[0], args[1])
		case "setpassword":
			if len(args) != 2 {
				panic("setpassword identity password")
			}
			if len(options) != 0 {
				panic("Unrecognized option " + dumpOptions(options))
			}
			return setPassword(icentral, args[0], args[1])
		case "permgroupadd":
			if len(args) != 2 {
				panic("permgroupadd identity groupname")
			}
			if len(options) != 0 {
				panic("Unrecognized option " + dumpOptions(options))
			}
			return permGroupAddOrDel(icentral, args[0], args[1], true)
		case "permgroupdel":
			if len(args) != 2 {
				panic("permgroupdel identity groupname")
			}
			if len(options) != 0 {
				panic("Unrecognized option " + dumpOptions(options))
			}
			return permGroupAddOrDel(icentral, args[0], args[1], false)
		case "addgroup":
			if len(args) < 1 {
				//at least one argument is required, the groupname. If no other parameters are provided,
				//the group is created with no roles
				panic("addgroup groupname role1 role2 role3...")
			}
			if len(options) != 0 {
				panic("Unrecognized option " + dumpOptions(options))
			}
			return addGroup(icentral, args)
		case "permshow":
			if len(args) != 1 {
				panic("permshow identity")
			}
			if len(options) != 0 {
				panic("Unrecognized option " + dumpOptions(options))
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

func addGroup(icentral *imqsauth.ImqsCentral, args []string) bool {
	//print out permission names from cmd line
	for i, k := range args {
		fmt.Printf("arg %v value %s\n", i, k)
	}

	//convert imqsauth.PermissionsTable to map
	var permMap map[string]int
	permMap = make(map[string]int)

	for permNr, permName := range imqsauth.PermissionsTable {
		permMap[permName] = permNr
	}

	//extract all args[1]..[n-1] as PermissionU16
	// loadOrCreateGroup()
	// roles = make(authaus.PermissionList, len(args))

	ps := make([]authaus.PermissionU16, 0, len(args))
	var result int
	for l, cmdPerm := range args {
		if l > 0 {
			result = permMap[cmdPerm]
			if result > 0 {
				ps = append(ps, authaus.PermissionU16(result))
				fmt.Printf("New permission added for %s : %v\n", cmdPerm, result)
			} else {
				panic("Permission does not exit " + cmdPerm)
			}
		}
	}

	ok := true
	ok = ok && modifyGroup(icentral, groupModifySet, args[0], ps)

	return ok
}

func createUser(icentral *imqsauth.ImqsCentral, options map[string]string, identity string, password string) bool {
	update := false
	for k, _ := range options {
		switch k {
		case "update":
			update = true
		default:
			panic("Unrecognized option '" + k + "'")
		}
	}

	if update {
		if e := icentral.Central.SetPassword(identity, password); e == nil {
			fmt.Printf("Reset password of %v\n", identity)
			return true
		} else if strings.Index(e.Error(), authaus.ErrIdentityAuthNotFound.Error()) == -1 {
			fmt.Printf("Error setting password fof %v: %v\n", identity, e)
			return false
		}
	}

	if e := icentral.Central.CreateAuthenticatorIdentity(identity, password); e == nil {
		fmt.Printf("Created user %v\n", identity)
		return true
	} else {
		fmt.Printf("Error creating identity %v: %v\n", identity, e)
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

type groupModifyMode int

const (
	groupModifySet groupModifyMode = iota
	groupModifyAdd
	groupModifyRemove
)

func modifyGroup(icentral *imqsauth.ImqsCentral, mode groupModifyMode, groupName string, perms authaus.PermissionList) bool {
	if group, e := loadOrCreateGroup(icentral, groupName, true); e == nil {
		switch mode {
		case groupModifyAdd:
			for _, perm := range perms {
				group.AddPerm(perm)
			}
		case groupModifyRemove:
			for _, perm := range perms {
				group.RemovePerm(perm)
			}
		case groupModifySet:
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

// Reset auth groups to a sane state. After running this, you should be able to use
// the web interface to do everything else. That's the idea at least (the web interface has yet to be built).
func resetAuthGroups(icentral *imqsauth.ImqsCentral) bool {
	ok := true
	ok = ok && modifyGroup(icentral, groupModifySet, RoleGroupAdmin, authaus.PermissionList{imqsauth.PermAdmin})
	ok = ok && modifyGroup(icentral, groupModifySet, RoleGroupEnabled, authaus.PermissionList{imqsauth.PermEnabled})
	if !ok {
		return false
	}
	return true
}

func showhelp() {
	help := `
imqsauth -c configfile [-y yfconfigfile] command [options]

  commands
    createdb          Create the postgres database
    resetauthgroups   Reset the [admin,enabled] groups
    createuser        Create a user in the authentication system
    setpassword       Set a user's password
    permgroupadd      Add a group to a permit
    permgroupdel      Remove a group from a permit
    permshow          Show the groups of a permit
    run               Run the service

  mandatory options
    -c configfile     Specify the authaus config file. A pseudo file called
                      !TESTCONFIG1 is used by the REST test suite to load a
                      test configuration.
`
	fmt.Print(help)
}

func showhelp_cmd(cmd string) {
	switch cmd {
	case "":
		showhelp()
	case "createuser":
		showhelp_createuser()
	default:
		fmt.Printf("%v has no built-in help\n", cmd)
	}
}

func showhelp_createuser() {
	fmt.Print(`
createuser [-update] identity password
  Create or update a user in the authentication system.
  This affects only the 'authentication' system - the permit
  database is not altered by this command.

  -update If specified, and the user already exists, then
          behave identically to 'setpassword'. If this
          is not specified, and the identity already exists,
          then the function returns with an error.
`)
}
