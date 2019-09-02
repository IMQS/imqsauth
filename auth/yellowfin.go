package imqsauth

import (
	"bytes"
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/IMQS/log"
	"github.com/IMQS/yfws"
)

type YellowfinGroup int

const (
	YellowfinGroupNone YellowfinGroup = iota
	YellowfinGroupAdmin
	YellowfinGroupWriter
	YellowfinGroupConsumer
)

// If you modify this, then also read the comment inside httpLoginYellowfin, and make
// sure you keep in mind the session timeout value in Yellowfin's web.xml
const yellowfinCookieExpiry = 31 * 24 * time.Hour

// The 'admin' user is a yellowfin super-user that we can use as authority in order to
// login on behalf of regular users. This is convenient, because it means we do not
// need to worry about yellowfin's storage of passwords for regular users.
// The password for the 'admin@yellowfin.com.au' user is set by create-keys.rb.
// We use this particular username because it is the default created by the
// yellowfin installer. Note also, that this is the "userid" as well as the "email"
// identity of the user, so despite the fact that yellowfin's authentication mode
// is set to "UserID", we still use the full name.
const AdminUser = "admin@yellowfin.com.au"

// This is the password of admin@yellowfin.com.au, as set by the yellowfin installer
const AdminDefaultPassword = "test"

// We never use a user's actual password. We authorize all requests with the admin user's credentials.
// This just makes life simpler for us, so that we don't have to worry about keeping passwords in sync
// between authaus and yellowfin.
// The one place where we are forced to specify a user's password is when creating a new user. We simply
// force all users to have the same password. This one password is stored in the secrets directory on the
// server, alongside the admin password

type Yellowfin struct {
	Log           *log.Logger
	AdminPassword string
	UserPassword  string // This password is used only when creating users, but thereafter we never use it
	Url           string
	Enabled       bool
	Transport     *http.Transport

	// Should be temporary - remove when we have all reports on scenario filtering.
	ContentCategoryFilterEnabled bool
	SourceAccessFilterEnabled    bool
	// Map IMQS modules to Yellowfin report categories for cases where it does not match, e.g. Water Demand->Swift.
	ModuleToCategoryMapping map[string]string
}

func NewYellowfin(logger *log.Logger) *Yellowfin {
	y := &Yellowfin{
		Log:     logger,
		Enabled: false,
		Url:     "http://127.0.0.1:2005/yellowfin/",
	}
	if y.Log == nil {
		y.Log = log.New(log.Stdout)
	}
	y.Transport = &http.Transport{
		DisableKeepAlives:  true,
		DisableCompression: true,
	}
	return y
}

func (y *Yellowfin) LoadConfig(config ConfigYellowfin, adminPasswordFile, userPasswordFile string) error {
	y.Enabled = config.Enabled

	// Should be temporary - used to test new reports with filters until all reports are ready for migration
	y.ContentCategoryFilterEnabled = config.ContentCategoryFilter
	y.ModuleToCategoryMapping = config.ModuleToCategoryMapping
	y.SourceAccessFilterEnabled = config.SourceAccessFilter

	// Read admin password. If this file is not found, then we assume that the password
	// is "test", because that is the password set by the yellowfin installer.
	// This is not just conservative coding - this code path is actually used
	// by the IMQS server install script when it changes the yellowfin admin password
	// to a random string.
	rawPass, err := ioutil.ReadFile(adminPasswordFile)
	if err == nil {
		y.AdminPassword = string(rawPass)
	} else if os.IsNotExist(err) {
		y.AdminPassword = AdminDefaultPassword
	} else {
		return err
	}

	// Read user password
	rawPass, err = ioutil.ReadFile(userPasswordFile)
	if err == nil {
		y.UserPassword = string(rawPass)
	} else if y.Enabled {
		return err
	}
	return nil
}

func (y *Yellowfin) CreateUser(identity string) error {
	if !y.Enabled {
		return nil
	}
	// See comments higher in file, about why we use a fixed password for all users
	password := y.UserPassword
	var params = map[string]string{
		"%ADMIN%":        AdminUser,
		"%PASSWORD%":     y.AdminPassword,
		"%USERID%":       identity,
		"%EMAIL%":        identity + "@imqs.co.za",
		"%FIRSTNAME%":    identity,
		"%LASTNAME%":     identity,
		"%USERPASSWORD%": password,
	}

	_, err := yfws.SendRequest(y.Url+"services/AdministrationService", "createuser", params)
	if err != nil {
		return err
	}

	return y.UpdatePassword(identity, password)

}

func (y *Yellowfin) UpdatePassword(identity, password string) error {
	if !y.Enabled {
		return nil
	}
	var params = map[string]string{
		"%ADMIN%":        AdminUser,
		"%PASSWORD%":     y.AdminPassword,
		"%USERID%":       identity,
		"%USERPASSWORD%": password,
	}

	_, err := yfws.SendRequest(y.Url+"services/AdministrationService", "changepassword", params)
	if err != nil {
		return err
	}

	return nil
}

func (y *Yellowfin) ChangeGroup(identity string, group YellowfinGroup) error {
	if !y.Enabled {
		return nil
	}
	var params = map[string]string{
		"%ADMIN%":    AdminUser,
		"%PASSWORD%": y.AdminPassword,
		"%USERID%":   identity,
	}
	switch group {
	case YellowfinGroupAdmin:
		params["%ROLE%"] = "YFADMIN"
	case YellowfinGroupWriter:
		params["%ROLE%"] = "YFREPORTWRITER"
	case YellowfinGroupConsumer:
		params["%ROLE%"] = "YFREPORTCONSUMER"
	default:
		return yfws.ErrYFInvalidGroup
	}

	_, err := yfws.SendRequest(y.Url+"services/AdministrationService", "updateuser", params)
	if err != nil {
		return err
	}
	return nil
}

func (y *Yellowfin) LoginAndUpdateGroup(identity string, group YellowfinGroup, loginParams yellowfinLoginParameters) ([]*http.Cookie, error) {
	// We must change the group before logging in, otherwise the user's UI will not reflect his new status
	err := y.ChangeGroup(identity, group)
	if err != nil {
		// The user has most likely been deleted in YF itself
		if err == yfws.ErrYFCouldNotFindPerson {
			return nil, err
		}
		y.Log.Errorf("Failed to update yellowfin group for %v to %v: %v", identity, group, err)
	}

	return y.Login(identity, loginParams)
}

func (y *Yellowfin) Login(identity string, loginParams yellowfinLoginParameters) ([]*http.Cookie, error) {
	if !y.Enabled {
		return nil, nil
	}
	var params = map[string]string{
		"%ADMIN%":    AdminUser,
		"%PASSWORD%": y.AdminPassword,
		"%USER%":     identity,
	}

	// Should be temporary - used to test new reports with filters until all reports are ready for migration
	if y.ContentCategoryFilterEnabled {
		// Use the mapping specified in the config if it present.
		// E.g. The "Water Demand" module should map to the "Swift" Yellowfin category.
		var moduleFilter string = loginParams.ModuleFilter
		mappedName, ok := y.ModuleToCategoryMapping[moduleFilter]
		if ok {
			moduleFilter = mappedName
		}
		params["%CONTENTCATEGORY%"] = "CONTENT_INCLUDE=" + moduleFilter
	} else {
		params["%CONTENTCATEGORY%"] = ""
	}
	if y.SourceAccessFilterEnabled {
		params["%SCENARIOFILTER%"] = "SOURCEFILTER_SCENARIO=" + loginParams.ScenarioFilter
	} else {
		params["%SCENARIOFILTER%"] = ""
	}

	// Global filters
	var gf bytes.Buffer
	for field, values := range loginParams.GlobalFilters {
		for _, value := range values {
			gf.WriteString(`<item xsd:type="xsd:string">SOURCEFILTER_`)
			xml.EscapeText(&gf, []byte(strings.ToUpper(field)))
			gf.WriteString(`=`)
			xml.EscapeText(&gf, []byte(value))
			gf.WriteString(`</item>`)
		}
	}
	params["%GLOBALFILTERS%"] = gf.String()

	multirefs, err := yfws.SendRequest(y.Url+"services/AdministrationService", "login", params)
	if err != nil {
		return nil, err
	}

	sessionid, err := multirefs[0].ValueForPathString("loginSessionId.#text")
	if err != nil {
		return nil, err
	}

	url := y.Url + "logon.i4?LoginWebserviceId=" + sessionid
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header["Accept"] = []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"}
	req.Header["Connection"] = []string{"Close"}
	resp, err := y.Transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	return resp.Cookies(), nil
}

func (y *Yellowfin) Logout(identity string, r *http.Request) error {
	if !y.Enabled {
		return nil
	}
	sessionidCookie, err := r.Cookie("JSESSIONID")
	if err != nil {
		return err
	}
	sessionid := sessionidCookie.Value

	var params = map[string]string{
		"%ADMIN%":     AdminUser,
		"%PASSWORD%":  y.AdminPassword,
		"%USER%":      identity,
		"%SESSIONID%": sessionid,
	}

	_, err = yfws.SendRequest(y.Url+"services/AdministrationService", "logout", params)
	if err != nil {
		return err
	}
	return nil
}

type yellowfinLoginParameters struct {
	ModuleFilter   string              `json:"module_filter"`
	ScenarioFilter string              `json:"scenario_filter"`
	GlobalFilters  map[string][]string `json:"global_filters"`
}
