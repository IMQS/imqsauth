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
imqsauth command [options]

  commands
    createdb     Create the postgres database
    resetadmin   Reset the imqsadmin user
    run          Run the service

  options
    -c configfile Specify the authaus config file
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
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg[0:1] == "-" && i < len(args)-1 {
			// options followed by a single value
			switch arg {
			case "-c":
				configFile = args[i+1]
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
		}
	}

	ic := &imqsauth.ImqsCentral{}
	ic.Config = &authaus.Config{}

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
	case "resetadmin":
		success = resetAdmin(ic)
	case "run":
		if !authaus.RunAsService(handler) {
			success = false
			fmt.Print(ic.RunHttp())
		}
	default:
		panic("Unrecognized command '" + command + "'")
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

func resetAdmin(icentral *imqsauth.ImqsCentral) bool {
	var err error
	icentral.Central, err = authaus.NewCentralFromConfig(icentral.Config)
	if err == nil {
		defer icentral.Central.Close()

		password := authaus.RandomString(10, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
		adminOK := false
		setPermOK := false

		// Reset the password, or create the user
		if ecreate := icentral.Central.CreateAuthenticatorIdentity("imqsadmin", password); ecreate == nil {
			adminOK = true
			fmt.Printf("Created user imqsadmin. Password: %v\n", password)
		} else if ecreate == authaus.ErrIdentityExists {
			if eset := icentral.Central.SetPassword("imqsadmin", password); eset == nil {
				adminOK = true
				fmt.Printf("Reset password of imqsadmin. Password: %v\n", password)
			} else {
				fmt.Printf("Error resetting imqsadmin: %v\n", eset)
			}
		} else {
			fmt.Printf("Error creating imqsadmin: %v\n", ecreate)
		}

		// Reset the permission groups
		groupOK := true
		var groupAdmin *authaus.AuthGroup
		if adminOK {

			group := &authaus.AuthGroup{}
			group.Name = "imqsadmin"
			group.AddPermBit(imqsauth.PermAdmin)
			group.AddPermBit(imqsauth.PermEnabled)
			groupOK = groupOK && resetGroup(icentral, group)
			groupAdmin = group

			group = &authaus.AuthGroup{}
			group.Name = "user"
			group.AddPermBit(imqsauth.PermEnabled)
			groupOK = groupOK && resetGroup(icentral, group)
		}

		// Reset the perm bits of the imqsadmin user
		if groupOK && adminOK {
			pgroups := make([]authaus.GroupIDU32, 1, 1)
			pgroups[0] = groupAdmin.ID
			permit := &authaus.Permit{}
			permit.Roles = authaus.EncodePermit(pgroups)
			if eSetPermit := icentral.Central.SetPermit("imqsadmin", permit); eSetPermit != nil {
				fmt.Printf("Error setting permit: %v\n", eSetPermit)
			} else {
				setPermOK = true
			}
		}
		return setPermOK
	} else {
		fmt.Printf("Error: %v\n", err)
		return false
	}
}
