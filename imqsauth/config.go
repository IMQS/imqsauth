package imqsauth

import (
	"encoding/json"
	"github.com/IMQS/authaus"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type ConfigYellowfin struct {
	Enabled bool
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
}

func (x *Config) Reset() {
	*x = Config{}
	x.PasswordResetExpirySeconds = 24 * 3600
	x.NewAccountExpirySeconds = 5 * 365 * 24 * 3600
	x.Authaus.Reset()
}

func (x *Config) LoadFile(filename string) error {
	x.Reset()
	var file *os.File
	var all []byte
	var err error
	if file, err = os.Open(filename); err != nil {
		return err
	}
	defer file.Close()
	if all, err = ioutil.ReadAll(file); err != nil {
		return err
	}
	if err = json.Unmarshal(all, x); err != nil {
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
