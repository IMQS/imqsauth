package imqsauth

import (
	"github.com/IMQS/log"
	"github.com/IMQS/serviceauth"
)

type IMQSAuditor struct {
	Log *log.Logger
}

func NewIMQSAuditor(logger *log.Logger) *IMQSAuditor {
	return &IMQSAuditor{Log: logger}
}

func (a *IMQSAuditor) AuditUserAction(identity, clientIp, description string) {
	err := serviceauth.AddToAuditLogServiceToService(identity, clientIp, description)
	if err != nil {
		a.Log.Errorf("%v", err)
	}
}
