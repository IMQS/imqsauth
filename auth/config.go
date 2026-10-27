package imqsauth

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/IMQS/authaus"
	"github.com/IMQS/log"
	serviceconfig "github.com/IMQS/serviceconfigsgo"
)

const (
	serviceConfigFileName = "imqsauth.json"
	serviceConfigVersion  = 1
	serviceName           = "ImqsAuth"
	defaultMailerURL      = "https://imqs-mailer.appspot.com"
)

type MailParameters struct {
	// Name of the template that the mail server should use when generating the
	// email body. Optional.
	TemplateName *string `json:"TemplateName,omitempty"`
	// Custom from variable to be used by mailer service. Optional
	// eg: IMQS Password Reset <noreply@imqs.co.za>
	From *string `json:"From,omitempty"`
	// Custom subject variable to be used by mailer service. Optional
	// eg: IMQS Reset Password
	Subject *string `json:"Subject,omitempty"`
}

type SendMailDetails struct {
	// URL of mail server. Optional.
	URL           *string         `json:"URL,omitempty"`
	PasswordReset *MailParameters `json:"PasswordReset,omitempty"`
	NewAccount    *MailParameters `json:"NewAccount,omitempty"`
	// Currently does not make use of `TemplateName`
	LDAPPasswordReset *MailParameters `json:"LDAPPasswordReset,omitempty"`
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
//
//	{
//		"Permissions": {
//			"dynamic": [
//				{"id": "15000", "name": "MMTest", "friendly": "An MM Test Permission",
//				"description": "MM Test permission", "module": "Maintenance Management"}
//			],
//			"disable": ["newMmIlCreateAdd"],
//			"relabel": [
//				{"id": "1204", "name": "newMmIlArchive", "friendly": "Archive incident",
//				"description": "MM Acrhive an incident", "module": "Maintenance Management"}
//			]
//		}
//	}
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
	ForbiddenPasswords         []string
	PasswordResetExpirySeconds float64
	NewAccountExpirySeconds    float64
	SendMailPassword           string // NB: When moving SendMailPassword to a standalone secrets file, change for PCS also. PCS reads imqsauth config file.
	SendMailDetails            SendMailDetails
	NotificationUrl            string
	hostnameURL                string // This is fetched from configservice
	lastFileLoaded             string // Used for relative paths (such as HostnameFile)
	enablePcsRename            bool   // Disabled by unit tests
	Permissions                *ManagePermissions
}

func (x *SendMailDetails) SetDefaults() {
	if x.URL == nil {
		u := defaultMailerURL
		x.URL = &u
	}
}

func (x *Config) SetDefaults() {
	x.SendMailDetails.SetDefaults()
}

func (x *Config) Reset() {
	*x = Config{}
	x.SetDefaults()
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

func (x *Config) LoadConfig(filename string) error {
	x.Reset()
	err := serviceconfig.GetConfig(filename, serviceName, serviceConfigVersion, serviceConfigFileName, x)
	if err != nil {
		return err
	}

	x.SetDefaults()

	//hostnameURL, err := serviceconfig.GetSystemVariableFromConfigService("IMQS_HOSTNAME_URL")
	//if err != nil {
	//	return err
	//}
	x.hostnameURL = "127.0.0.1"

	x.lastFileLoaded = filename
	return x.loadDynamicPermissions()
}

// loadDynamicPermissions adds the dynamic permissions from config to the
// static/coded list of permissions for transparent usage.
//
// Each permission ID must be unique across the entire permission space (both
// the hard-coded static permissions in perms.go, and the dynamic permissions
// loaded here from config). If two permissions share the same numeric ID,
// whichever one happens to be resolved "wins" unpredictably wherever that ID
// is looked up (e.g. in the auth UI), causing one permission/module's
// checkbox to silently alias to a completely unrelated permission. To avoid
// this class of bug, we scan the *entire* dynamic permission list up front
// and fail loudly at config-load time, reporting every clashing id found in
// a single pass, instead of silently allowing the collision through (or only
// reporting the first one encountered).
func (x *Config) loadDynamicPermissions() error {
	if x.Permissions != nil && x.Permissions.Dynamic != nil {
		// Seed with the names already present in PermissionsTable - this
		// includes all of the hard-coded static permissions from perms.go,
		// plus anything registered by an earlier call to this function.
		idToName := make(map[authaus.PermissionU16]string, len(PermissionsTable))
		for id, name := range PermissionsTable {
			idToName[id] = name
		}

		var collidingIDs []authaus.PermissionU16
		alreadyReported := map[authaus.PermissionU16]bool{}

		for _, perm := range x.Permissions.Dynamic {
			permID, err := strconv.ParseUint(perm.ID, 10, 16)
			if err != nil {
				return fmt.Errorf("Failed to parse dynamic permission ID '%s' to uint16 for permission %s: %v\n", perm.ID, perm.Name, err)
			}
			id := authaus.PermissionU16(permID)

			if existingName, exists := idToName[id]; exists && existingName != perm.Name {
				// Record the clash and keep scanning the rest of the list, so
				// that every clashing id is identified in one pass rather than
				// stopping at the first one found.
				if !alreadyReported[id] {
					collidingIDs = append(collidingIDs, id)
					alreadyReported[id] = true
				}
				continue
			}
			idToName[id] = perm.Name

			PermissionsTable[id] = perm.Name
			if strings.HasSuffix(strings.ToLower(perm.Name), "moduleaccess") {
				PermissionModuleMap[perm.Module] = id
			}
		}

		if len(collidingIDs) > 0 {
			sort.Slice(collidingIDs, func(i, j int) bool { return collidingIDs[i] < collidingIDs[j] })
			ids := make([]string, len(collidingIDs))
			for i, id := range collidingIDs {
				ids[i] = strconv.Itoa(int(id))
			}
			return fmt.Errorf("Found %d dynamic permission id(s) that clash with an existing permission (static or dynamic): %s. "+
				"Each permission id must be unique - please reassign a different, unused id for each of these in the config's Permissions.dynamic list.",
				len(collidingIDs), strings.Join(ids, ", "))
		}
	}
	return nil
}

func (x *Config) IsContainer() bool {
	return serviceconfig.IsContainer()
}

func (x *Config) GetHostnameURL() string {
	return x.hostnameURL
}

// MakeOutsideDocker changes all of the hostnames from our common hostnames in
// docker-compose files, to 'localhost'. This is built to allow a developer to
// debug the Auth service, while running everything else in docker.
func (x *Config) MakeOutsideDocker() {
	fmt.Printf("OutsideDocker changes: db => localhost, port => 2003, IMQS_HOSTNAME_URL => http://localhost:2500\n")
	translateDB := func(db *authaus.DBConnection) {
		if db.Host == "db" {
			db.Host = "localhost"
			// db.Port = 6432 // DO NOT COMMIT (for testing PgBouncer)
		}
	}
	translateDB(&x.Authaus.DB)
	if x.Authaus.HTTP.Port == "80" {
		x.Authaus.HTTP.Port = "2003"
	}
	x.Authaus.Log.Filename = log.Stdout
	x.hostnameURL = "http://localhost:2500"
}
