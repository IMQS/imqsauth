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
	Transport *http.Transport
}

func NewYellowfin(fn string) *Yellowfin {
	yf := &Yellowfin{}
	file, err := os.Open(fn)
	if err != nil {
		return nil
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	if err = decoder.Decode(yf); err != nil {
		return nil
	}
	yf.Transport = &http.Transport{
		DisableKeepAlives:  true,
		DisableCompression: true,
	}
	return yf
}

func (y *Yellowfin) Login(identity string) []*http.Cookie {
	act := strings.Replace(soapLogin, "%ADMIN%", y.User, -1)
	act = strings.Replace(act, "%PASSWORD%", y.Password, -1)
	act = strings.Replace(act, "%USER%", identity, -1)
	req, err := http.NewRequest("POST", y.Url+"services/AdministrationService", strings.NewReader(act))
	if err != nil {
		return nil
	}
	req.Header["SOAPAction"] = []string{"\"\""}
	req.Header["Content-Type"] = []string{"text/xml;charset=UTF-8"}
	req.Header["Connection"] = []string{"Close"}
	if resp, err := y.Transport.RoundTrip(req); err == nil {
		result := y.parsexml(resp)
		if result.StatusCode == "SUCCESS" && result.ErrorCode == "0" {
			url := "http://localhost:2005/" + "logon.i4?LoginWebserviceId=" + result.SessionId
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return nil
			}
			req.Header["Accept"] = []string{"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"}
			req.Header["Host"] = []string{"localhost:2005"}
			req.Header["Connection"] = []string{"Close"}
			resp, err := y.Transport.RoundTrip(req)
			if err != nil {
				return nil
			}
			return resp.Cookies()
		}
	}
	return nil
}

func (y *Yellowfin) Logout(identity string, r *http.Request) error {
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
	result := y.parsexml(resp)
	if result.StatusCode == "SUCCESS" {
		return nil
	} else {
		return errors.New(fmt.Sprintf("Logout Error Code :%s", result.ErrorCode))
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
