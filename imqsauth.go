package main

import (
	"fmt"
	"github.com/IMQS/authaus"
	"os"
)

func main() {
	if authaus.RunAsService() {
		return
	} else {
		runCommandLine()
	}
}

func showhelp() {
	help := `
imqsauth command [options]

  commands
    createdb
    run

  options
    -c configfile Specify the authaus config file
`
	fmt.Print(help)
}

func runCommandLine() {
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
	for i, arg := range args {
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

	config := &authaus.Config{}
	if err := config.LoadFile(configFile); err != nil {
		fmt.Printf("Error loading config file '%v': %v\n", configFile, err)
		return
	}

	switch command {
	case "createdb":
		createDB(config)
	case "run":
		// TODO: Don't run this, but run our own custom HTTP frontend that has other commands
		// such as "SetPermit", etc. These commands UTILIZE authaus to verify that the requestor
		// has the necessary permissions. In other words, the IMQS-specific "auth" package knows
		// how to decode the permission bits.
		fmt.Print(authaus.RunHttpFromConfig(config))
	default:
		panic("Unrecognized command '" + command + "'")
	}
}

func createDB(config *authaus.Config) {
	db := &config.PermitDB.DBConnection
	if err := authaus.SqlCreateSchema("postgres", db.Host, db.Database, db.User, db.Password, db.SSL); err != nil {
		fmt.Printf("Error creating database: %v\n", err)
	} else {
		fmt.Print("Database created\n")
	}
}
