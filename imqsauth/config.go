package imqsauth

import (
	"encoding/json"
	"github.com/IMQS/authaus"
	"io/ioutil"
	"os"
)

type ConfigYellowfin struct {
	Enabled bool
	Url     string
}

type Config struct {
	Authaus   authaus.Config
	Yellowfin ConfigYellowfin
}

func (x *Config) Reset() {
	*x = Config{}
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
	return nil
}
