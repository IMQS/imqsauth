package main

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/IMQS/authaus"
	"github.com/IMQS/cli"
	"github.com/IMQS/imqsauth/cros"
	"github.com/IMQS/imqsauth/imqsauth"
)

// These files are written by create-keys.rb
// They are now in the cros package to allow for cross-platform compilation.
// Windows
//  c:/imqsvar/secrets/yellowfin_admin
//  c:/imqsvar/secrets/yellowfin_user
// Linux
//  /var/imqs/secrets/yellowfin_admin
//  /var/imqs/secrets/yellowfin_user

func main() {
	app := cli.App{}

	app.Description = "imqsauth -c=configfile [options] command"
	app.DefaultExec = exec

	app.AddCommand("createdb", "Create the postgres database")
	app.AddCommand("resetauthgroups", "Reset the [admin,enabled] groups")

	createUserDesc := "Create a user in the authentication system\nThis affects only the 'authentication' system - the permit database is not altered by this command. " +
		"This has no effect on Yellowfin. Yellowfin users are created automatically during HTTP login."
	createUser := app.AddCommand("createuser", createUserDesc, "identity", "password")
	createUser.AddValueOption("mobile", "number", "Mobile number (cell phone)")
	createUser.AddValueOption("firstname", "text", "First name")
	createUser.AddValueOption("lastname", "text", "Last name")
	createUser.AddValueOption("username", "text", "Username")
	createUser.AddValueOption("telephone", "text", "Telephone number")
	createUser.AddValueOption("remarks", "text", "Remarks")

	app.AddCommand("killsessions", "Erase all sessions belonging to a particular user\nWarning! The running server maintains a cache of "+
		"sessions, so you must stop the server, run this command, and then start the server again to kill sessions correctly.", "identity")
	app.AddCommand("setpassword", "Set a user's password in Authaus", "identity", "password")
	app.AddCommand("setpassword-yf", "Set a user's password in Yellowfin", "identity", "password")
	app.AddCommand("resetpassword", "Send a password reset email", "identity")
	app.AddCommand("setgroup", "Add or modify a group\nThe list of roles specified replaces the existing roles completely.", "groupname", "...role")
	app.AddCommand("renameuser", "Rename a user\nThe user will be logged out of any current sessions", "old", "new")
	app.AddCommand("permgroupadd", "Add a group to a permit", "identity", "groupname")
	app.AddCommand("permgroupdel", "Remove a group from a permit", "identity", "groupname")
	app.AddCommand("permshow", "Show the groups of a permit", "identity")
	app.AddCommand("showidentities", "Show a list of all identities and the groups that they belong to")
	app.AddCommand("showroles", "Show a list of all roles")
	app.AddCommand("showgroups", "Show a list of all groups")
	app.AddCommand("run", "Run the service\nThis will automatically detect if it's being run from the Windows Service dispatcher, and if so, "+
		"launch as a Windows Service. Otherwise, this runs in the foreground, and returns with an error code of 1. When running in the foreground, "+
		"log messages are still sent to the logfile (not to the console).")

	app.AddValueOption("c", "configfile", "Specify the imqsauth config file. A pseudo file called "+imqsauth.TestConfig1+" is "+
		"used by the REST test suite to load a test configuration. This option is mandatory.")

	app.AddBoolOption("nosvc", "Do not try to run as a Windows Service. Normally, the 'run' command detects whether this is an "+
		"'interactive session', and if not interactive, runs as a Windows Service. Specifying -nosvc forces us to launch as a regular process.")

	app.AddBoolOption("d", "Indicate that the service will run in container mode.")

	app.Run()
}

func exec(cmdName string, args []string, options cli.OptionSet) {

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

	_, cMode :=  options["d"]

	ic := &imqsauth.ImqsCentral{}
	ic.Config = &imqsauth.Config{}

	configFile := options["c"]

	// Try test config first; otherwise load real config
	isTestConfig := imqsauth.LoadTestConfig(ic, configFile)
	if !isTestConfig {
		if err := ic.Config.LoadFile(configFile, cMode); err != nil {
			panic(fmt.Sprintf("Error loading config file '%v': %v", configFile, err))
		}
	}

	// Because Yellowfin only allows a single session per user, we need to
	// make our behaviour the same. Note that this is only true for the Legacy case.
	// When using our new Router-based "transparent" yellowfin login, this
	// restriction falls away.
	if ic.Config.Yellowfin.Enabled && ic.Config.Yellowfin.UseLegacyAuth {
		ic.Config.Authaus.SessionDB.MaxActiveSessions = 1
	}

	handler := func() error {
		err := ic.RunHttp()
		ic.Central.Close()
		return err
	}

	handlerNoRetVal := func() {
		handler()
	}

	// "createdb" is different to the other command.
	// We cannot initialize an authaus Central object until the DB has been created.
	// The "run" command already creates a new Central object.
	createCentral := cmdName != "createdb" && !isTestConfig

	if createCentral {
		var err error
		ic.Central, err = authaus.NewCentralFromConfig(&ic.Config.Authaus)
		if err != nil {
			panic(err)
		}
		defer ic.Central.Close()
	}

	// Run migrations
	createDB(&ic.Config.Authaus)

	// Setup yellowfin
	if ic.Central != nil {
		ic.Yellowfin = imqsauth.NewYellowfin(ic.Central.Log)
		if ic.Config.Yellowfin.Enabled {
			if err := ic.Yellowfin.LoadConfig(ic.Config.Yellowfin, cros.YellowfinAdminPasswordFile, cros.YellowfinUserPasswordFile); err != nil {
				panic(fmt.Sprintf("Error loading yellowfin config: %v", err))
			}
		}
	}

	// Setup audit service
	if ic.Central != nil {
		ic.Central.Auditor = imqsauth.NewIMQSAuditor(ic.Config.AuditServiceUrl, ic.Central.Log)
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
		success = imqsauth.ResetAuthGroups(ic)
	case "run":
		if options.Has("nosvc") || !authaus.RunAsService(handlerNoRetVal) {
			success = false
			fmt.Print(handler())
		}
	case "setgroup":
		success = setGroup(ic, args[0], args[1:])
	case "setpassword":
		success = setPassword(ic, args[0], args[1])
	case "setpassword-yf":
		success = setPasswordYellowfin(ic, args[0], args[1])
	case "resetpassword":
		success = resetPassword(ic, args[0])
	case "renameuser":
		success = renameUser(ic, args[0], args[1])
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

func createDB(config *authaus.Config) bool {
	if err := authaus.SqlCreateDatabase(&config.UserStore.DB); err != nil {
		fmt.Printf("Error creating database: %v", err)
		return false
	}

	if err := authaus.RunMigrations(&config.UserStore.DB); err != nil {
		fmt.Printf("Error running migrations: %v", err)
		return false
	}
	return true
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
	user, eUserId := icentral.Central.GetUserFromIdentity(identity)
	if eUserId != nil {
		fmt.Printf("Error retrieving userid for identity: %v\n", identity)
		return false
	}
	perm, eGetPermit := icentral.Central.GetPermit(user.UserId)
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
			if eSet := icentral.Central.SetPermit(user.UserId, perm); eSet == nil {
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
	user, eUserId := icentral.Central.GetUserFromIdentity(identity)
	if eUserId != nil {
		fmt.Printf("Error retrieving userid for identity: %v\n", identity)
		return false
	}
	if perm, e := icentral.Central.GetPermit(user.UserId); e == nil {
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
	users, err := icentral.Central.GetAuthenticatorIdentities()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return false
	}

	longestName := 0
	for _, user := range users {
		if len(user.Email) > longestName {
			longestName = len(user.Email)
		}
	}

	for _, user := range users {
		permShow(icentral, longestName, user.Email)
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

	return imqsauth.ModifyGroup(icentral, imqsauth.GroupModifySet, groupName, perms)
}

func createUser(icentral *imqsauth.ImqsCentral, options map[string]string, identity string, password string) bool {

	isEmail, _ := regexp.MatchString("^([\\w-]+(?:\\.[\\w-]+)*)@((?:[\\w-]+\\.)*\\w[\\w-]{0,66})\\.([a-z]{2,6}(?:\\.[a-z]{2})?)$", identity)
	var e error
	nowTime := time.Now().UTC()
	user := authaus.AuthUser{
		Firstname:       options["firstname"],
		Lastname:        options["lastname"],
		Mobilenumber:    options["mobile"],
		Telephonenumber: options["telephone"],
		Remarks:         options["remarks"],
		Created:         nowTime,
		CreatedBy:       0,
		Modified:        nowTime,
		ModifiedBy:      0,
	}
	if isEmail {
		user.Email = identity
		user.Username = options["username"]
	} else {
		user.Email = options["email"]
		user.Username = identity
	}
	_, e = icentral.Central.CreateUserStoreIdentity(&user, password)

	if e == nil {
		var label string
		if isEmail {
			label = "email address"
		} else {
			label = "username"
		}
		fmt.Printf("Created user with %s %v\n", label, identity)
		return true
	} else {
		fmt.Printf("Error creating identity %v: %v\n", identity, e)
		return false
	}
}

func killSessions(icentral *imqsauth.ImqsCentral, identity string) bool {
	user, eUserId := icentral.Central.GetUserFromIdentity(identity)
	if eUserId != nil {
		fmt.Printf("Error retrieving userid for identity: %v\n", identity)
		return false
	}
	if e := icentral.Central.InvalidateSessionsForIdentity(user.UserId); e == nil {
		fmt.Printf("Destroyed all sessions for %v\n", identity)
		return true
	} else {
		fmt.Printf("Error destroying sessions: %v\n", e)
		return false
	}
}

func setPassword(icentral *imqsauth.ImqsCentral, identity string, password string) bool {
	user, eUserId := icentral.Central.GetUserFromIdentity(identity)
	if eUserId != nil {
		fmt.Printf("Error retrieving userid for identity: %v\n", identity)
		return false
	}
	if e := icentral.Central.SetPassword(user.UserId, password); e == nil {
		fmt.Printf("Reset password of %v\n", identity)
		return true
	} else {
		fmt.Printf("Error resetting password: %v\n", e)
		return false
	}
}

func renameUser(icentral *imqsauth.ImqsCentral, oldIdent string, newIdent string) bool {
	if e := icentral.Central.RenameIdentity(oldIdent, newIdent); e == nil {
		fmt.Printf("Renamed %v to %v\n", oldIdent, newIdent)
		return true
	} else {
		fmt.Printf("Error renaming: %v\n", e)
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

func resetPassword(icentral *imqsauth.ImqsCentral, identity string) bool {
	user, eUserId := icentral.Central.GetUserFromIdentity(identity)
	if eUserId != nil {
		fmt.Printf("Error retrieving userid for identity: %v\n", identity)
		return false
	}
	code, msg := icentral.ResetPasswordStart(user.UserId, false)
	if code == 200 {
		fmt.Printf("Message sent\n")
		return true
	} else {
		fmt.Printf("Error %v %v\n", code, msg)
		return false
	}
}