package imqsauth

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/IMQS/authaus"
)

//ipAddressRange - a structure that holds the start and end of a range of ip addresses
type ipAddressRange struct {
	start net.IP
	end   net.IP
}

// inRange - check to see if a given ip address is within a range given
func inRange(r ipAddressRange, ipAddress net.IP) bool {
	// strcmp type byte comparison
	return bytes.Compare(ipAddress, r.start) >= 0 && bytes.Compare(ipAddress, r.end) < 0
}

// isPrivateSubnet - check to see if this ip is in a private subnet
func isPrivateSubnet(ipAddress net.IP) bool {
	var privateRanges = []ipAddressRange{
		ipAddressRange{
			start: net.ParseIP("10.0.0.0"),
			end:   net.ParseIP("10.255.255.255"),
		},
		ipAddressRange{
			start: net.ParseIP("100.64.0.0"),
			end:   net.ParseIP("100.127.255.255"),
		},
		ipAddressRange{
			start: net.ParseIP("172.16.0.0"),
			end:   net.ParseIP("172.31.255.255"),
		},
		ipAddressRange{
			start: net.ParseIP("192.0.0.0"),
			end:   net.ParseIP("192.0.0.255"),
		},
		ipAddressRange{
			start: net.ParseIP("192.168.0.0"),
			end:   net.ParseIP("192.168.255.255"),
		},
		ipAddressRange{
			start: net.ParseIP("198.18.0.0"),
			end:   net.ParseIP("198.19.255.255"),
		},
	}

	// Only works with ipv4 at the moment
	if ipCheck := ipAddress.To4(); ipCheck != nil {
		// iterate over all our ranges
		for _, r := range privateRanges {
			// check if this ip is in a private range
			if inRange(r, ipAddress) {
				return true
			}
		}
	}
	return false
}

// Source - https://husobee.github.io/golang/ip-address/2015/12/17/remote-ip-go.html
func getIPAddress(r *http.Request) string {
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip"} {
		addresses := strings.Split(r.Header.Get(h), ",")
		// march from right to left until we get a public address
		// that will be the address right before our proxy.
		for i := len(addresses) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(addresses[i])
			// header can contain spaces too, strip those out.
			realIP := net.ParseIP(ip)
			if !realIP.IsGlobalUnicast() || isPrivateSubnet(realIP) {
				// bad address, go to next
				continue
			}
			return ip
		}
	}
	return r.RemoteAddr
}

func auditUserLogAction(central *ImqsCentral, req *httpRequest, item string, actionType authaus.AuditActionType) {
	type ContextDetails struct {
		Service  string `json:"service"`
		Origin   string `json:"origin"`
		Username string `json:"username"`
		UserId   int64  `json:"userid"`
	}

	var loggedInUserId authaus.UserId

	contextDetails := ContextDetails{
		Service: "Auth",
		Origin:  getIPAddress(req.http),
	}

	if req.token != nil {
		loggedInUserId = req.token.UserId
		contextDetails.Username = req.token.Username
		contextDetails.UserId = int64(req.token.UserId)
	}

	contextData, err := json.Marshal(contextDetails)
	if err != nil {
		return
	}

	if central.Central.Auditor != nil {
		if loggedInUser, err := central.Central.GetUserFromUserId(authaus.UserId(loggedInUserId)); err == nil {
			central.Central.Auditor.AuditUserAction(loggedInUser.Username, item, string(contextData), actionType)
		}
	}
}
