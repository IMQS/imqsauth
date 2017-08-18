package imqsauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/IMQS/log"
	"github.com/IMQS/serviceauth"
)

type IMQSAuditor struct {
	Url string
	Log *log.Logger
}

func NewIMQSAuditor(url string, logger *log.Logger) *IMQSAuditor {
	return &IMQSAuditor{Url: url, Log: logger}
}

type Action struct {
	Who     string        `json:"who"`
	DidWhat string        `json:"did_what"`
	ToWhat  string        `json:"to_what"`
	AtTime  int64         `json:"at_time"`
	Context ActionContext `json:"context"`
}

type ActionContext struct {
	Location string `json:"location"`
}

func (a *IMQSAuditor) AuditUserAction(identity, clientIp, description string) {
	action := &Action{Who: identity, DidWhat: description, AtTime: time.Now().Unix()}

	var actionContext ActionContext
	actionContext.Location = clientIp
	action.Context = actionContext

	actionStr, err := json.Marshal(action)
	if err != nil {
		a.Log.Errorf("Failed to marshal action into json: (%v)", err)
		return
	}

	req, err := http.NewRequest("POST", a.Url, bytes.NewBuffer(actionStr))
	if err != nil {
		a.Log.Errorf("Error creating audit request: (%v)", err)
		return
	}
	req.Header.Add("Date", time.Now().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	req.Header.Set("Content-Type", "application/json")

	err = serviceauth.CreateInterServiceRequest(req, actionStr)
	if err != nil {
		a.Log.Errorf("Error creating audit interservice request: (%v)", err)
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.Log.Errorf("Error calling audit service: (%v)", err)
		return
	}
	resp.Body.Close()
}
