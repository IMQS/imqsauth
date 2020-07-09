package imqsauth

import (
	"fmt"
	"os"
	"strings"

	"github.com/IMQS/authaus"
	"github.com/IMQS/log"
	serviceconfig "github.com/IMQS/serviceconfigsgo"
)

const (
	serviceConfigFileName = "imqsauth.json"
	serviceConfigVersion  = 1
	serviceName           = "ImqsAuth"
)

type ConfigYellowfin struct {
	Enabled bool
	// If this is true, then we store yellowfin cookies in the user's browser.
	// If this is false, then we transparently login to Yellowfin via the Router.
	// We could probably get rid of this old code path, but it adds minimal
	// complexity to the code, and might still prove useful.
	UseLegacyAuth bool
	// Filter YF categories according to current IMQS module, which is passed in from the front-end.
	ContentCategoryFilter bool
	// Map IMQS modules to Yellowfin report categories for cases where it does not match, e.g. Water Demand->Swift.
	ModuleToCategoryMapping map[string]string
	// Pass in the IMQS scenario as a field used to filter reports.
	SourceAccessFilter bool
}

// Permission holds all of the details to create the dynamic permission list.
// These permissions are used for code implementations which are purely driven
// by configuration requiring different permissions per client which the static
// permissions cannot service. The static permissions also contain values which are
// client specific and these additional changes will us to prevent these static
// permissions from being shown in the User Management screen or they can be renamed
// to match specific client requirements.
// Client/dynamic permissions are added to the imqsauth.json file using the following
// as an example:
// {
// 	"Permissions": {
// 		"dynamic": [
// 			{"id": "15000", "name": "MMTest", "friendly": "An MM Test Permission",
//			"description": "MM Test permission", "module": "Maintenance Management"}
// 		],
//		"disable": ["newMmIlCreateAdd"],
//		"relabel": [
//			{"id": "1204", "name": "newMmIlArchive", "friendly": "Archive incident",
//			"description": "MM Acrhive an incident", "module": "Maintenance Management"}
//		]
// 	}
// }
type Permission struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Friendly    string `json:"friendly"`
	Description string `json:"description"`
	Module      string `json:"module"`
}

// ManagePermissions is used to store all of the dynamic, disable and rename/relabel permission details
type ManagePermissions struct {
	Dynamic []*Permission `json:"dynamic,omitempty"` // List of client specific permissions
	Disable []string      `json:"disable,omitempty"` // Disable is to prevent static permissions from being shown in User Management
	Relabel []*Permission `json:"relabel,omitempty"` // Relabel is used to change the labels of static permissions
}

// Note: Be sure to keep doc.go up to date with the Config structure here

type Config struct {
	Authaus                    authaus.Config
	Yellowfin                  ConfigYellowfin
	PasswordResetExpirySeconds float64
	NewAccountExpirySeconds    float64
	SendMailPassword           string // NB: When moving SendMailPassword to a standalone secrets file, change for PCS also. PCS reads imqsauth config file.
	NotificationUrl            string
	hostname                   string // This is read from environment variable the first time GetHostname is called
	lastFileLoaded             string // Used for relative paths (such as HostnameFile)
	enablePcsRename            bool   // Disabled by unit tests
	Permissions                *ManagePermissions
}

func (x *Config) Reset() {
	*x = Config{}
	x.PasswordResetExpirySeconds = 24 * 3600
	x.NewAccountExpirySeconds = 5 * 365 * 24 * 3600
	x.enablePcsRename = true
	x.Authaus.Reset()
}

// Performs setup specific to unit tests
func (x *Config) ResetForUnitTests() {
	x.Reset()
	x.enablePcsRename = false
}

func (x *Config) LoadFile(filename string) error {
	x.Reset()
	err := serviceconfig.GetConfig(filename, serviceName, serviceConfigVersion, serviceConfigFileName, x)
	if err != nil {
		return err
	}
	x.lastFileLoaded = filename
	return nil
}

func (x *Config) IsContainer() bool {
	return serviceconfig.IsContainer()
}

func (x *Config) GetHostname() string {
	if x.hostname == "" {
		hostname_b, ok := os.LookupEnv("IMQS_HOSTNAME_URL")
		if ok {
			x.hostname = strings.TrimSpace(string(hostname_b))
		}
	}
	return x.hostname
}

// MakeOutsideDocker changes all of the hostnames from our common hostnames in
// docker-compose files, to 'localhost'. This is built to allow a developer to
// debug the Auth service, while running everything else in docker.
func (x *Config) MakeOutsideDocker() {
	fmt.Printf("OutsideDocker changes: db => localhost, port => 2003, IMQS_HOSTNAME_URL => http://localhost:2500\n")
	translateDBHost := func(dbHost *string) {
		if *dbHost == "db" {
			*dbHost = "localhost"
		}
	}
	translateDBHost(&x.Authaus.PermitDB.DB.Host)
	translateDBHost(&x.Authaus.RoleGroupDB.DB.Host)
	translateDBHost(&x.Authaus.UserStore.DB.Host)
	translateDBHost(&x.Authaus.SessionDB.DB.Host)
	if x.Authaus.HTTP.Port == "80" {
		x.Authaus.HTTP.Port = "2003"
	}
	x.Authaus.Log.Filename = log.Stdout
	x.hostname = "http://localhost:2500"
}
