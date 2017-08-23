package imqsauth

import (
	"github.com/IMQS/authaus"
	"github.com/IMQS/serviceconfigsgo"
	"io/ioutil"
	"path/filepath"
	"strings"
)

const serviceConfigFileName = "imqsauth.json"
const serviceConfigVersion = 1
const serviceName = "ImqsAuth"

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

// Note: Be sure to keep doc.go up to date with the Config structure here

type Config struct {
	Authaus                    authaus.Config
	Yellowfin                  ConfigYellowfin
	PasswordResetExpirySeconds float64
	NewAccountExpirySeconds    float64
	SendMailPassword           string // NB: When moving SendMailPassword to a standalone secrets file, change for PCS also. PCS reads imqsauth config file.
	HostnameFile               string
	hostname                   string // This is read from HostnameFile the first time GetHostname is called
	lastFileLoaded             string // Used for relative paths (such as HostnameFile)
	enablePcsRename            bool   // Disabled by unit tests
	NotificationUrl            string
	AuditServiceUrl            string
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

func (x *Config) GetHostname() string {
	if x.hostname == "" {
		if x.HostnameFile != "" {
			hostname_b, err := ioutil.ReadFile(x.HostnameFile)
			if err != nil {
				hostname_b, _ = ioutil.ReadFile(filepath.Join(filepath.Dir(x.lastFileLoaded), x.HostnameFile))
			}
			x.hostname = strings.TrimSpace(string(hostname_b))
		}
	}
	return x.hostname
}
