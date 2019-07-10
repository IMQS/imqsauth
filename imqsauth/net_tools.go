package imqsauth

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/IMQS/authaus"
)

type ContextDetails struct {
	Service  string `json:"service"`
	Origin   string `json:"origin"`
	Username string `json:"username"`
	UserId   int64  `json:"userid"`
	Email    string `json:"email"`
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
			if !realIP.IsGlobalUnicast() {
				// bad address, go to next
				continue
			}
			return ip
		}
	}
	if remoteAddrNoPort, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return remoteAddrNoPort
	}
}

func auditUserLogAction(central *ImqsCentral, req *httpRequest, userId authaus.UserId, username, description string, actionType authaus.AuditActionType) {
	var actorUserId authaus.UserId

	var email string
	user, eUser := central.Central.GetUserFromIdentity(username)
	if eUser == nil {
		email = user.Email
	}

	contextDetails := ContextDetails{
		Service:  "auth",
		Origin:   getIPAddress(req.http),
		Username: username,
		UserId:   int64(userId),
		Email:    email,
	}

	if req.token != nil {
		actorUserId = req.token.UserId
	} else {
		actorUserId = userId
	}

	contextData, err := json.Marshal(contextDetails)
	if err != nil {
		return
	}

	if central.Central.Auditor != nil {
		if user, err := central.Central.GetUserFromUserId(authaus.UserId(actorUserId)); err == nil {
			central.Central.Auditor.AuditUserAction(user.Username, description, string(contextData), actionType)
		} else {
			central.Central.Auditor.AuditUserAction(username, description, string(contextData), actionType)
		}
	}
}
