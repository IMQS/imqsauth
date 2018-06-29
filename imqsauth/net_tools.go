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
	return r.RemoteAddr
}

func auditUserLogAction(central *ImqsCentral, req *httpRequest, userId authaus.UserId, username, description string, actionType authaus.AuditActionType) {
	var actorUserId authaus.UserId
	serverAddress := central.Config.GetHostname()
	if serverAddress == "" {
		serverAddress = getIPAddress(req.http)
	}
	contextDetails := ContextDetails{
		Service:  "auth",
		Origin:   serverAddress,
		Username: username,
		UserId:   int64(userId),
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
