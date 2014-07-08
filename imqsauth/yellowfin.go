package imqsauth

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
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

type Yellowfin struct {
	Password  string `json:"password"`
	Url       string `json:"url"`
	User      string `json:"user"`
	Enabled   bool   `json:"enabled"`
	Transport *http.Transport
}

func (y *Yellowfin) LoadConfig(fn string) error {
	file, err := os.Open(fn)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	if err = decoder.Decode(y); err != nil {
		return err
	}
	y.Transport = &http.Transport{
		DisableKeepAlives:  true,
		DisableCompression: true,
	}
	return nil
}

func (y *Yellowfin) CreateUser(identity, password string) error {
	if !y.Enabled {
		return nil
	}
	create := strings.Replace(soapCreateUser, "%ADMIN%", y.User, -1)
	create = strings.Replace(create, "%PASSWORD%", y.Password, -1)
	create = strings.Replace(create, "%USERID%", identity, -1)
	create = strings.Replace(create, "%EMAIL%", identity+"@imqs.co.za", -1)
	create = strings.Replace(create, "%FIRSTNAME%", identity, -1)
	create = strings.Replace(create, "%LASTNAME%", identity, -1)
	create = strings.Replace(create, "%USERPASSWORD%", password, -1)
	req, err := http.NewRequest("POST", y.Url+"services/AdministrationService", strings.NewReader(create))
	if err != nil {
		return err
	}
	req.Header["SOAPAction"] = []string{"\"\""}
	req.Header["Content-Type"] = []string{"text/xml;charset=UTF-8"}
	req.Header["Connection"] = []string{"Close"}
	if resp, err := y.Transport.RoundTrip(req); err == nil {
		if resp.StatusCode != 200 {
			return errors.New(fmt.Sprintf("Create yf user error (HTTP): %v", resp.StatusCode))
		}
		result := y.parsexml(resp)
		if result.StatusCode == "SUCCESS" && result.ErrorCode == "0" {
			return y.UpdatePassword(identity, password)
		}
	} else {
		return err
	}
	return nil
}

func (y *Yellowfin) UpdatePassword(identity, password string) error {
	if !y.Enabled {
		return nil
	}
	passwd := strings.Replace(soapChangePassword, "%ADMIN%", y.User, -1)
	passwd = strings.Replace(passwd, "%PASSWORD%", y.Password, -1)
	passwd = strings.Replace(passwd, "%USERID%", identity, -1)
	passwd = strings.Replace(passwd, "%USERPASSWORD%", password, -1)
	req, err := http.NewRequest("POST", y.Url+"services/AdministrationService", strings.NewReader(passwd))
	if err != nil {
		return err
	}
	req.Header["SOAPAction"] = []string{"\"\""}
	req.Header["Content-Type"] = []string{"text/xml;charset=UTF-8"}
	req.Header["Connection"] = []string{"Close"}
	if resp, err := y.Transport.RoundTrip(req); err == nil {
		if resp.StatusCode != 200 {
			return errors.New(fmt.Sprintf("Update yf password error (HTTP): %v", resp.StatusCode))
		}
		result := y.parsexml(resp)
		if result.StatusCode == "SUCCESS" && result.ErrorCode == "0" {
			return nil
		}
	} else {
		return err
	}
	return nil
}

func (y *Yellowfin) ChangeGroup(admin bool, identity string) error {
	if !y.Enabled {
		return nil
	}
	act := strings.Replace(soapGroup, "%ADMIN%", y.User, -1)
	act = strings.Replace(act, "%PASSWORD%", y.Password, -1)
	if admin {
		act = strings.Replace(act, "%ROLE%", "YFADMIN", -1)
	} else {
		act = strings.Replace(act, "%ROLE%", "YFREPORTCONSUMER", -1)
	}
	act = strings.Replace(act, "%USERID%", identity, -1)
	req, err := http.NewRequest("POST", y.Url+"services/AdministrationService", strings.NewReader(act))
	if err != nil {
		return err
	}
	req.Header["SOAPAction"] = []string{"\"\""}
	req.Header["Content-Type"] = []string{"text/xml;charset=UTF-8"}
	req.Header["Connection"] = []string{"Close"}
	if resp, err := y.Transport.RoundTrip(req); err == nil {
		if resp.StatusCode != 200 {
			return errors.New(fmt.Sprintf("Login error (HTTP): %v", resp.StatusCode))
		}
		result := y.parsexml(resp)
		if result.StatusCode == "SUCCESS" && result.ErrorCode == "0" {
			return nil
		}
	} else {
		return err
	}
	return nil
}

func (y *Yellowfin) Login(identity string) ([]*http.Cookie, error) {
	if !y.Enabled {
		return nil, nil
	}
	act := strings.Replace(soapLogin, "%ADMIN%", y.User, -1)
	act = strings.Replace(act, "%PASSWORD%", y.Password, -1)
	act = strings.Replace(act, "%USER%", identity, -1)
	req, err := http.NewRequest("POST", y.Url+"services/AdministrationService", strings.NewReader(act))
	if err != nil {
		return nil, err
	}
	req.Header["SOAPAction"] = []string{"\"\""}
	req.Header["Content-Type"] = []string{"text/xml;charset=UTF-8"}
	req.Header["Connection"] = []string{"Close"}
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
			return nil, errors.New(fmt.Sprintf("Login error %v, %v", result.StatusCode, result.ErrorCode))
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
	act := strings.Replace(soapLogout, "%ADMIN%", y.User, -1)
	act = strings.Replace(act, "%PASSWORD%", y.Password, -1)
	act = strings.Replace(act, "%USER%", identity, -1)
	act = strings.Replace(act, "%SESSIONID%", sessionid, -1)
	req, err := http.NewRequest("POST", y.Url+"services/AdministrationService", strings.NewReader(act))
	if err != nil {
		return nil
	}
	req.Header["SOAPAction"] = []string{"\"\""}
	req.Header["Content-Type"] = []string{"text/xml;charset=UTF-8"}
	req.Header["Connection"] = []string{"Close"}
	resp, err := y.Transport.RoundTrip(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprintf("Logout error (HTTP): %s", resp.StatusCode))
	}
	result := y.parsexml(resp)
	if result.StatusCode == "SUCCESS" {
		return nil
	} else {
		return errors.New(fmt.Sprintf("Logout error (Response): %s", result.ErrorCode))
	}
	return nil
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
