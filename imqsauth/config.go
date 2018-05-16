package imqsauth

import (
	"os"
	"strings"

	"github.com/IMQS/authaus"
	"github.com/IMQS/serviceconfigsgo"
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

// Note: Be sure to keep doc.go up to date with the Config structure here

type Config struct {
	Authaus                    authaus.Config
	Yellowfin                  ConfigYellowfin
	PasswordResetExpirySeconds float64
	NewAccountExpirySeconds    float64
	SendMailPassword           string // NB: When moving SendMailPassword to a standalone secrets file, change for PCS also. PCS reads imqsauth config file.
	hostname                   string // This is read from environment variable the first time GetHostname is called
	lastFileLoaded             string // Used for relative paths (such as HostnameFile)
	enablePcsRename            bool   // Disabled by unit tests
	NotificationUrl            string
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
