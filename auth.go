package main

import (
	"fmt"
	"github.com/IMQS/auth/imqsauth"
	"github.com/IMQS/authaus"
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
	args := os.Args[1:]
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("%v\n", err)
		}
	}()
	if len(args) == 0 {
		showhelp()
		return
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
			case "-?":
				fallthrough
			case "--?":
				showhelp()
				return
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
		return
	}

	// Use the PermitDB connection for the group DB
	var err error
	if ic.GroupDB, err = imqsauth.NewCachedRoleGroupDB(&ic.Config.PermitDB.DB); err != nil {
		fmt.Printf("Error connecting to GroupDB (using PermitDB connection) %v\n", err)
		return
	}

	handler := func() {
		ic.RunHttp()
	}

	switch command {
	case "createdb":
		createDB(ic.Config)
	case "resetadmin":
		resetAdmin(ic)
	case "run":
		if !authaus.RunAsService(handler) {
			fmt.Print(ic.RunHttp())
		}
	default:
		panic("Unrecognized command '" + command + "'")
	}

	ic.GroupDB.Close()
}

func createDB(config *authaus.Config) {
	if err := authaus.SqlCreateSchema_User(&config.PermitDB.DB); err != nil {
		fmt.Printf("Error creating User database: %v\n", err)
	} else {
		fmt.Print("User database created\n")
	}

	if err := authaus.SqlCreateSchema_Session(&config.SessionDB.DB); err != nil {
		fmt.Printf("Error creating Session database: %v\n", err)
	} else {
		fmt.Print("Session database created\n")
	}

	// Use the PermitDB connection for the group DB
	if err := imqsauth.RoleGroupDB_Create(&config.PermitDB.DB); err != nil {
		fmt.Printf("Error creating Role Group database: %v\n", err)
	} else {
		fmt.Print("Role Group database created\n")
	}
}

func resetGroup(icentral *imqsauth.ImqsCentral, group *imqsauth.AuthGroup) bool {
	if existing, eget := icentral.GroupDB.GetByName(group.Name); eget == nil {
		group.ID = existing.ID
		existing.PermBits = group.PermBits
		if eupdate := icentral.GroupDB.UpdateGroup(existing); eupdate == nil {
			fmt.Printf("Group %v updated\n", group.Name)
			return true
		} else {
			fmt.Printf("Error updating group of %v: %v\n", group.Name, eupdate)
		}
	} else if strings.Index(eget.Error(), imqsauth.ErrGroupNotExist.Error()) == 0 {
		if ecreate := icentral.GroupDB.InsertGroup(group); ecreate == nil {
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

func resetAdmin(icentral *imqsauth.ImqsCentral) {
	var err error
	icentral.Central, err = authaus.NewCentralFromConfig(icentral.Config)
	if err == nil {
		password := authaus.RandomString(10, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
		adminOK := false

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
		var groupAdmin *imqsauth.AuthGroup
		if adminOK {

			group := &imqsauth.AuthGroup{}
			group.Name = "imqsadmin"
			group.AddPermBit(imqsauth.PermAdmin)
			group.AddPermBit(imqsauth.PermEnabled)
			groupOK = groupOK && resetGroup(icentral, group)
			groupAdmin = group

			group = &imqsauth.AuthGroup{}
			group.Name = "user"
			group.AddPermBit(imqsauth.PermEnabled)
			groupOK = groupOK && resetGroup(icentral, group)
		}

		// Reset the perm bits of the imqsadmin user
		if groupOK && adminOK {
			pgroups := make([]imqsauth.GroupIDU32, 1, 1)
			pgroups[0] = groupAdmin.ID
			permit := &authaus.Permit{}
			permit.Roles = imqsauth.EncodePermit(pgroups)
			icentral.Central.SetPermit("imqsadmin", permit)
		}

		icentral.Central.Close()
	} else {
		fmt.Printf("Error: %v\n", err)
	}
}
