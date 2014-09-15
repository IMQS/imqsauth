package imqsauth

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

// Functions to allow for parallel login to yellowfin. This is done via a webservice; the first page
// is then called to receive the cookies and injected into the auth login result.

// These are contants because the unmarshalling is tightly bound to the xml - a change in xml
// will result in a change in code as well.

const (
	soapCreateUser = `<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ser="http://service.web.mi.hof.com" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
   <soapenv:Header/>
   <soapenv:Body>
      <ser:remoteAdministrationCall soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
         <in0 xsi:type="ser:AdministrationServiceRequest">
            <function xsi:type="xsd:string">ADDUSER</function>
            <loginId xsi:type="xsd:string">%ADMIN%</loginId>
            <orgId xsi:type="xsd:int">1</orgId>
            <password xsi:type="xsd:string">%PASSWORD%</password>
            <person xsi:type="ser:AdministrationPerson">
               <emailAddress xsi:type="xsd:string">%EMAIL%</emailAddress>
               <firstName xsi:type="xsd:string">%FIRSTNAME%</firstName>
               <initial xsi:type="xsd:string"></initial>
               <ipId xsi:type="xsd:int"></ipId>
               <languageCode xsi:type="xsd:string"></languageCode>
               <lastName xsi:type="xsd:string">%LASTNAME%</lastName>
               <password xsi:type="xsd:string">%USERPASSWORD%</password>
               <roleCode xsi:type="xsd:string">YFREPORTCONSUMER</roleCode>
               <salutationCode xsi:type="xsd:string">DR</salutationCode>
               <timeZoneCode xsi:type="xsd:string"></timeZoneCode>
               <userId xsi:type="xsd:string">%USERID%</userId>
            </person>
         </in0>
      </ser:remoteAdministrationCall>
   </soapenv:Body>
</soapenv:Envelope>`
	soapChangePassword = `<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ser="http://service.web.mi.hof.com" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
   <soapenv:Header/>
   <soapenv:Body>
      <ser:remoteAdministrationCall soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
         <in0 xsi:type="ser:AdministrationServiceRequest">
            <function xsi:type="xsd:string">CHANGEPASSWORD</function>
            <loginId xsi:type="xsd:string">%ADMIN%</loginId>
            <orgId xsi:type="xsd:int">1</orgId>
            <password xsi:type="xsd:string">%PASSWORD%</password>
            <person xsi:type="ser:AdministrationPerson">
               <userId xsi:type="xsd:string">%USERID%</userId>
               <password xsi:type="xsd:string">%USERPASSWORD%</password>
            </person>
         </in0>
      </ser:remoteAdministrationCall>
   </soapenv:Body>
</soapenv:Envelope>`
	soapGroup = `<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ser="http://service.web.mi.hof.com" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
   <soapenv:Header/>
   <soapenv:Body>
      <ser:remoteAdministrationCall soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
         <in0 xsi:type="ser:AdministrationServiceRequest">
            <function xsi:type="xsd:string">UPDATEUSER</function>
            <loginId xsi:type="xsd:string">%ADMIN%</loginId>
            <orgId xsi:type="xsd:int">1</orgId>
            <password xsi:type="xsd:string">%PASSWORD%</password>
            <person xsi:type="ser:AdministrationPerson">
               <roleCode xsi:type="xsd:string">%ROLE%</roleCode>
               <userId xsi:type="xsd:string">%USERID%</userId>
            </person>
         </in0>
      </ser:remoteAdministrationCall>
   </soapenv:Body>
</soapenv:Envelope>`
	soapLogin = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ser="http://service.web.mi.hof.com" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
   <soapenv:Header/>
   <soapenv:Body>
      <ser:remoteAdministrationCall soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
         <in0 xsi:type="ser:AdministrationServiceRequest">
            <function xsi:type="xsd:string">LOGINUSERNOPASSWORD</function>
            <loginId xsi:type="xsd:string">%ADMIN%</loginId>
            <orgId xsi:type="xsd:int">1</orgId>
            <orgRef xsi:type="xsd:string">Default</orgRef>
            <password xsi:type="xsd:string">%PASSWORD%</password>
            <person xsi:type="ser:AdministrationPerson">
               <userId xsi:type="xsd:string">%USER%</userId>
            </person>
         </in0>
      </ser:remoteAdministrationCall>
   </soapenv:Body>
</soapenv:Envelope>`
	soapLogout = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ser="http://service.web.mi.hof.com" xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/">
   <soapenv:Header/>
   <soapenv:Body>
      <ser:remoteAdministrationCall soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
         <in0 xsi:type="ser:AdministrationServiceRequest">
            <function xsi:type="xsd:string">LOGOUTUSER</function>
            <loginId xsi:type="xsd:string">%ADMIN%</loginId>
            <orgId xsi:type="xsd:int">1</orgId>
            <orgRef xsi:type="xsd:string">Default</orgRef>
            <password xsi:type="xsd:string">%PASSWORD%</password>
            <loginSessionId xsi:type="xsd:string">%SESSIONID%</loginSessionId>
            <person xsi:type="ser:AdministrationPerson">
               <userId xsi:type="xsd:string">%USER%</userId>
            </person>
         </in0>
      </ser:remoteAdministrationCall>
   </soapenv:Body>
</soapenv:Envelope>`
)

var (
	ErrYellowfinAuthFailed      = errors.New("Yellowfin authentication failed")
	ErrYellowfinPasswordTooLong = errors.New("Yellowfin password must be 20 characters or less")
	ErrYellowfinInvalidGroup    = errors.New("Invalid yellowfind group")
)

type YellowfinGroup int

const (
	YellowfinGroupNone YellowfinGroup = iota
	YellowfinGroupAdmin
	YellowfinGroupWriter
	YellowfinGroupConsumer
)

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
	Url           string `json:"url"`
	Enabled       bool   `json:"enabled"`
	Transport     *http.Transport
}

func NewYellowfin(logger *log.Logger) *Yellowfin {
	y := &Yellowfin{
		Log:     logger,
		Enabled: false,
		Url:     "http://localhost/yellowfin/",
	}
	if y.Log == nil {
		y.Log = log.New(ioutil.Discard, "", 0)
	}
	y.Transport = &http.Transport{
		DisableKeepAlives:  true,
		DisableCompression: true,
	}
	return y
}

func (y *Yellowfin) LoadConfig(configFile, adminPasswordFile, userPasswordFile string) error {
	rawConfig, err := ioutil.ReadFile(configFile)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(rawConfig, y); err != nil {
		return err
	}

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
	if err != nil {
		return err
	}
	y.UserPassword = string(rawPass)

	return nil
}

func (y *Yellowfin) CreateUser(identity string) error {
	if !y.Enabled {
		return nil
	}
	// See comments higher in file, about why we use a fixed password for all users
	password := y.UserPassword
	create := strings.Replace(soapCreateUser, "%ADMIN%", AdminUser, -1)
	create = strings.Replace(create, "%PASSWORD%", y.AdminPassword, -1)
	create = strings.Replace(create, "%USERID%", identity, -1)
	create = strings.Replace(create, "%EMAIL%", identity+"@imqs.co.za", -1)
	create = strings.Replace(create, "%FIRSTNAME%", identity, -1)
	create = strings.Replace(create, "%LASTNAME%", identity, -1)
	create = strings.Replace(create, "%USERPASSWORD%", password, -1)
	req, err := http.NewRequest("POST", y.Url+"services/AdministrationService", strings.NewReader(create))
	if err != nil {
		return err
	}
	setupSoapRequestHeaders(req)
	if resp, err := y.Transport.RoundTrip(req); err == nil {
		if resp.StatusCode != 200 {
			return errors.New(fmt.Sprintf("Error creating yellowfin user: HTTP code %v", resp.StatusCode))
		}
		result := y.parsexml(resp)
		if result.StatusCode == "SUCCESS" && result.ErrorCode == "0" {
			return y.UpdatePassword(identity, password)
		}
		return makeYellowfinError(result, "Error creating yellowfin user")
	} else {
		return err
	}
	return nil
}

func (y *Yellowfin) UpdatePassword(identity, password string) error {
	if !y.Enabled {
		return nil
	}
	passwd := strings.Replace(soapChangePassword, "%ADMIN%", AdminUser, -1)
	passwd = strings.Replace(passwd, "%PASSWORD%", y.AdminPassword, -1)
	passwd = strings.Replace(passwd, "%USERID%", identity, -1)
	passwd = strings.Replace(passwd, "%USERPASSWORD%", password, -1)
	req, err := http.NewRequest("POST", y.Url+"services/AdministrationService", strings.NewReader(passwd))
	if err != nil {
		return err
	}
	setupSoapRequestHeaders(req)
	if resp, err := y.Transport.RoundTrip(req); err == nil {
		if resp.StatusCode != 200 {
			return errors.New(fmt.Sprintf("Error updating yellowfin password: HTTP code %v", resp.StatusCode))
		}
		result := y.parsexml(resp)
		return makeYellowfinError(result, "Error updating yellowfin password")
	} else {
		return err
	}
	return nil
}

func (y *Yellowfin) ChangeGroup(identity string, group YellowfinGroup) error {
	if !y.Enabled {
		return nil
	}
	act := strings.Replace(soapGroup, "%ADMIN%", AdminUser, -1)
	act = strings.Replace(act, "%PASSWORD%", y.AdminPassword, -1)
	switch group {
	case YellowfinGroupAdmin:
		act = strings.Replace(act, "%ROLE%", "YFADMIN", -1)
	case YellowfinGroupWriter:
		act = strings.Replace(act, "%ROLE%", "YFREPORTWRITER", -1)
	case YellowfinGroupConsumer:
		act = strings.Replace(act, "%ROLE%", "YFREPORTCONSUMER", -1)
	default:
		return ErrYellowfinInvalidGroup
	}
	act = strings.Replace(act, "%USERID%", identity, -1)
	req, err := http.NewRequest("POST", y.Url+"services/AdministrationService", strings.NewReader(act))
	if err != nil {
		return err
	}
	setupSoapRequestHeaders(req)
	if resp, err := y.Transport.RoundTrip(req); err == nil {
		if resp.StatusCode != 200 {
			return errors.New(fmt.Sprintf("Error changing yellowfin group: HTTP code %v", resp.StatusCode))
		}
		result := y.parsexml(resp)
		return makeYellowfinError(result, "Error changing yellowfin group")
	} else {
		return err
	}
	return nil
}

func (y *Yellowfin) LoginAndUpdateGroup(identity string, group YellowfinGroup) ([]*http.Cookie, error) {
	// We must change the group before logging in, otherwise the user's UI will not reflect his new status
	err := y.ChangeGroup(identity, group)
	if err != nil {
		y.Log.Printf("Failed to update yellowfin group for %v to %v", identity, group)
	}

	return y.Login(identity)
}

func (y *Yellowfin) Login(identity string) ([]*http.Cookie, error) {
	if !y.Enabled {
		return nil, nil
	}
	//y.Log.Printf("YF Logging in %v:%v %v", AdminUser, y.AdminPassword, identity)
	act := strings.Replace(soapLogin, "%ADMIN%", AdminUser, -1)
	act = strings.Replace(act, "%PASSWORD%", y.AdminPassword, -1)
	act = strings.Replace(act, "%USER%", identity, -1)
	req, err := http.NewRequest("POST", y.Url+"services/AdministrationService", strings.NewReader(act))
	if err != nil {
		return nil, err
	}
	setupSoapRequestHeaders(req)
	if resp, err := y.Transport.RoundTrip(req); err == nil {
		if resp.StatusCode != 200 {
			return nil, errors.New(fmt.Sprintf("Login error (HTTP): %v", resp.StatusCode))
		}
		result := y.parsexml(resp)
		if result.StatusCode == "SUCCESS" && result.ErrorCode == "0" {
			url := y.Url + "logon.i4?LoginWebserviceId=" + result.SessionId
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
		} else {
			return nil, makeYellowfinError(result, "Error logging in to yellowfin")
		}
	} else {
		return nil, err
	}
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
	act := strings.Replace(soapLogout, "%ADMIN%", AdminUser, -1)
	act = strings.Replace(act, "%PASSWORD%", y.AdminPassword, -1)
	act = strings.Replace(act, "%USER%", identity, -1)
	act = strings.Replace(act, "%SESSIONID%", sessionid, -1)
	req, err := http.NewRequest("POST", y.Url+"services/AdministrationService", strings.NewReader(act))
	if err != nil {
		return nil
	}
	setupSoapRequestHeaders(req)
	resp, err := y.Transport.RoundTrip(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprintf("Error logging out of yellowfin: HTTP code %s", resp.StatusCode))
	}
	result := y.parsexml(resp)
	return makeYellowfinError(result, "Error loggout out of yellowfin")
}

type XMLResult struct {
	XMLName    xml.Name `xml:"Envelope"`
	ErrorCode  string   `xml:"Body>multiRef>errorCode"`
	SessionId  string   `xml:"Body>multiRef>loginSessionId"`
	StatusCode string   `xml:"Body>multiRef>statusCode"`
}

func (y *Yellowfin) parsexml(r *http.Response) *XMLResult {
	bdy, _ := ioutil.ReadAll(r.Body)
	r.Body.Close()
	result := XMLResult{}
	err := xml.Unmarshal(bdy, &result)
	if err != nil {
		return nil
	}
	return &result
}

func setupSoapRequestHeaders(req *http.Request) {
	req.Header["SOAPAction"] = []string{"\"\""}
	req.Header["Content-Type"] = []string{"text/xml;charset=UTF-8"}
	req.Header["Connection"] = []string{"Close"}
}

func makeYellowfinError(result *XMLResult, baseMsg string) error {
	if result.StatusCode == "SUCCESS" && result.ErrorCode == "0" {
		return nil
	}

	switch result.ErrorCode {
	case "25":
		return ErrYellowfinAuthFailed
	case "38":
		return ErrYellowfinPasswordTooLong
	}

	return errors.New(fmt.Sprintf("%v: %v, %v", baseMsg, result.StatusCode, result.ErrorCode))
}
