package main

import (
	"fmt"
	"github.com/IMQS/authaus"
	"github.com/IMQS/cli"
	"github.com/IMQS/imqsauth/imqsauth"
	"log"
	"os"
	"runtime"
	"sort"
	"strings"
)

const TestConfig1 = "!TESTCONFIG1"
const TestPort = 3377

// These files are written by create-keys.rb
const (
	YellowfinAdminPasswordFile = "c:/imqsvar/secrets/yellowfin_admin"
	YellowfinUserPasswordFile  = "c:/imqsvar/secrets/yellowfin_user"
)

const (
	// Hard-coded group names
	RoleGroupAdmin   = "admin"
	RoleGroupEnabled = "enabled"
)

func main() {
	app := cli.App{}

	app.Description = "imqsauth -c=configfile [options] command"
	app.DefaultExec = exec

	app.AddCommand("createdb", "Create the postgres database")
	app.AddCommand("resetauthgroups", "Reset the [admin,enabled] groups")

	createUserDesc := "Create a user in the authentication system\nThis affects only the 'authentication' system - the permit database is not altered by this command. " +
		"This has no effect on Yellowfin. Yellowfin users are created automatically during HTTP login."
	app.AddCommand("createuser", createUserDesc, "identity", "password")

	app.AddCommand("killsessions", "Erase all sessions belonging to a particular user\nWarning! The running server maintains a cache of "+
		"sessions, so you must stop the server, run this command, and then start the server again to kill sessions correctly.", "identity")
	app.AddCommand("setpassword", "Set a user's password in Authaus", "identity", "password")
	app.AddCommand("setpassword-yf", "Set a user's password in Yellowfin", "identity", "password")
	app.AddCommand("setgroup", "Add or modify a group\nThe list of roles specified replaces the existing roles completely.", "groupname", "...role")
	app.AddCommand("permgroupadd", "Add a group to a permit", "identity", "groupname")
	app.AddCommand("permgroupdel", "Remove a group from a permit", "identity", "groupname")
	app.AddCommand("permshow", "Show the groups of a permit", "identity")
	app.AddCommand("showidentities", "Show a list of all identities and the groups that they belong to")
	app.AddCommand("showroles", "Show a list of all roles")
	app.AddCommand("showgroups", "Show a list of all groups")
	app.AddCommand("run", "Run the service\nThis will automatically detect if it's being run from the Windows Service dispatcher, and if so, "+
		"launch as a Windows Service. Otherwise, this runs in the foreground, and returns with an error code of 1. When running in the foreground, "+
		"log messages are still sent to the logfile (not to the console).")

	app.AddValueOption("c", "configfile", "Specify the imqsauth config file. A pseudo file called "+TestConfig1+" is "+
		"used by the REST test suite to load a test configuration. This option is mandatory.")

	app.Run()
}

func exec(cmdName string, args []string, options map[string]string) {

	// panic(string) to show an error message.
	// panic(error) will show a stack trace
	defer func() {
		if ex := recover(); ex != nil {
			switch err := ex.(type) {
			case error:
				fmt.Printf("%v\n", err)
				trace := make([]byte, 1024)
				runtime.Stack(trace, false)
				fmt.Printf("%s\n", trace)
			case string:
				if err != "" {
					fmt.Printf("%v\n", err)
				}
			default:
				fmt.Printf("%v\n", ex)
			}
			os.Exit(1)
		} else {
			os.Exit(0)
		}
	}()

	ic := &imqsauth.ImqsCentral{}
	ic.Config = &imqsauth.Config{}

	configFile := options["c"]
	if configFile == "" {
		panic("config file not specified")
	}

	// Try test config first; otherwise load real config
	isTestConfig := loadTestConfig(ic, configFile)
	if !isTestConfig {
		if err := ic.Config.LoadFile(configFile); err != nil {
			panic(fmt.Sprintf("Error loading config file '%v': %v", configFile, err))
		}
	}

	// Because Yellowfin only allows a single session per user, we need to
	// make our behaviour the same.
	if ic.Config.Yellowfin.Enabled {
		ic.Config.Authaus.SessionDB.MaxActiveSessions = 1
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

	// "createdb" is different to the other command.
	// We cannot initialize an authaus Central object until the DB has been created.
	createCentral := cmdName != "createdb" && !isTestConfig

	if createCentral {
		var err error
		ic.Central, err = authaus.NewCentralFromConfig(&ic.Config.Authaus)
		if err != nil {
			panic(err)
		}
		defer ic.Central.Close()
	}

	// Setup yellowfin
	if ic.Central != nil {
		ic.Yellowfin = imqsauth.NewYellowfin(ic.Central.Log)
		if ic.Config.Yellowfin.Enabled {
			if err := ic.Yellowfin.LoadConfig(ic.Config.Yellowfin, YellowfinAdminPasswordFile, YellowfinUserPasswordFile); err != nil {
				panic(fmt.Sprintf("Error loading yellowfin config: %v", err))
			}
		}
	}

	success := false
	switch cmdName {
	case "createdb":
		success = createDB(&ic.Config.Authaus)
	case "createuser":
		success = createUser(ic, options, args[0], args[1])
	case "killsessions":
		success = killSessions(ic, args[0])
	case "permgroupadd":
		success = permGroupAddOrDel(ic, args[0], args[1], true)
	case "permgroupdel":
		success = permGroupAddOrDel(ic, args[0], args[1], false)
	case "permshow":
		success = permShow(ic, 0, args[0])
	case "resetauthgroups":
		success = resetAuthGroups(ic)
	case "run":
		if !authaus.RunAsService(handlerNoRetVal) {
			success = false
			fmt.Print(handler())
		}
	case "setgroup":
		success = setGroup(ic, args[0], args[1:])
	case "setpassword":
		success = setPassword(ic, args[0], args[1])
	case "setpassword-yf":
		success = setPasswordYellowfin(ic, args[0], args[1])
	case "showgroups":
		success = showAllGroups(ic)
	case "showidentities":
		success = showAllIdentities(ic)
	case "showroles":
		showAllRoles()
		success = true
	}

	if !success {
		panic("")
	}
}

func loadTestConfig(ic *imqsauth.ImqsCentral, testConfigName string) bool {
	if testConfigName == TestConfig1 {
		ic.Config.Authaus.HTTP.Bind = "127.0.0.1"
		ic.Config.Authaus.HTTP.Port = TestPort
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
	if group, error := authaus.LoadOrCreateGroup(icentral.Central.GetRoleGroupDB(), groupName, createIfNotExist); error == nil {
		fmt.Printf("Group %v created\n", groupName)
		return group, nil
	} else {
		fmt.Printf("Error creating group %v, %v ", groupName, error)
		return nil, error
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

//add or remove an identity (e.g. user) to or from a group
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

func permShow(icentral *imqsauth.ImqsCentral, identityColumnWidth int, identity string) (success bool) {
	permStr := ""
	success = false
	if perm, e := icentral.Central.GetPermit(identity); e == nil {
		if groups, eDecode := authaus.DecodePermit(perm.Roles); eDecode == nil {
			if groupNames, eGetNames := authaus.GroupIDsToNames(groups, icentral.Central.GetRoleGroupDB()); eGetNames == nil {
				sort.Strings(groupNames)
				permStr = strings.Join(groupNames, " ")
				success = true
			} else {
				permStr = fmt.Sprintf("Error converting group IDs to names: %v\n", eGetNames)
			}
		} else {
			permStr = fmt.Sprintf("Error decoding permit: %v\n", eDecode)
		}
	} else {
		permStr = fmt.Sprintf("Error retrieving permit: %v\n", e)
	}
	fmtStr := fmt.Sprintf("%%-%vv  %%v\n", identityColumnWidth)
	fmt.Printf(fmtStr, identity, permStr)
	return
}

func showAllGroups(icentral *imqsauth.ImqsCentral) bool {
	groups, err := icentral.Central.GetRoleGroupDB().GetGroups()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return false
	}

	longestName := 0
	for _, group := range groups {
		if len(group.Name) > longestName {
			longestName = len(group.Name)
		}
	}
	formatStr := fmt.Sprintf("%%-%vv  %%v\n", longestName)

	fmt.Printf(formatStr, "group", "roles")
	fmt.Printf(formatStr, "-----", "-----")

	for _, group := range groups {
		roles := []string{}
		for _, perm := range group.PermList {
			roles = append(roles, imqsauth.PermissionsTable[perm])
		}
		sort.Strings(roles)
		fmt.Printf(formatStr, group.Name, strings.Join(roles, " "))
	}
	return true
}

func showAllRoles() {
	roles := []string{}
	for _, name := range imqsauth.PermissionsTable {
		roles = append(roles, name)
	}
	sort.Strings(roles)
	for _, name := range roles {
		fmt.Printf("%v\n", name)
	}
}

func showAllIdentities(icentral *imqsauth.ImqsCentral) bool {
	identities, err := icentral.Central.GetAuthenticatorIdentities()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return false
	}
	sort.Strings(identities)

	longestName := 0
	for _, ident := range identities {
		if len(ident) > longestName {
			longestName = len(ident)
		}
	}

	for _, ident := range identities {
		permShow(icentral, longestName, ident)
	}

	return true
}

func setGroup(icentral *imqsauth.ImqsCentral, groupName string, roles []string) bool {
	perms := []authaus.PermissionU16{}
	nameToPerm := imqsauth.PermissionsTable.Inverted()

	for _, pname := range roles {
		if perm, ok := nameToPerm[pname]; ok {
			perms = append(perms, perm)
			// fmt.Printf("Added permission : %-25v [%v]\n", pname, perm)
		} else {
			panic(fmt.Sprintf("Permission '%v' does not exist", pname))
		}
	}

	return modifyGroup(icentral, groupModifySet, groupName, perms)
}

func createUser(icentral *imqsauth.ImqsCentral, options map[string]string, identity string, password string) bool {
	if e := icentral.Central.CreateAuthenticatorIdentity(identity, password); e == nil {
		fmt.Printf("Created user %v\n", identity)
		return true
	} else {
		fmt.Printf("Error creating identity %v: %v\n", identity, e)
		return false
	}
}

func killSessions(icentral *imqsauth.ImqsCentral, identity string) bool {
	if e := icentral.Central.InvalidateSessionsForIdentity(identity); e == nil {
		fmt.Printf("Destroyed all sessions for %v\n", identity)
		return true
	} else {
		fmt.Printf("Error destroying sessions: %v\n", e)
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

func setPasswordYellowfin(icentral *imqsauth.ImqsCentral, identity string, password string) bool {
	if !icentral.Yellowfin.Enabled {
		fmt.Printf("Yellowfin is disabled\n")
		return false
	}
	if e := icentral.Yellowfin.UpdatePassword(identity, password); e == nil {
		fmt.Printf("Reset yellowfin password of %v\n", identity)
		return true
	} else {
		fmt.Printf("Failed to set yellowfin password of %v: %v\n", identity, e)
		return false
	}
}

type groupModifyMode int

const (
	groupModifySet groupModifyMode = iota
	groupModifyAdd
	groupModifyRemove
)

func saveGroup(icentral *imqsauth.ImqsCentral, group *authaus.AuthGroup) bool {
	if err := icentral.Central.GetRoleGroupDB().UpdateGroup(group); err == nil {
		fmt.Printf("Group %v updated\n", group.Name)
		return true
	} else {
		fmt.Printf("Error updating group of %v: %v\n", group.Name, err)
		return false
	}
}

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
