package imqsauth

import (
	"github.com/IMQS/authaus"
	"github.com/IMQS/log"
	"github.com/IMQS/serviceauth"
)

type IMQSAuditor struct {
	Log *log.Logger
}

func NewIMQSAuditor(logger *log.Logger) *IMQSAuditor {
	return &IMQSAuditor{Log: logger}
}

func (a *IMQSAuditor) AuditUserAction(identity, clientIp, serviceName, description string, auditActionType authaus.AuditActionType) {
	err := serviceauth.AddToAuditLogServiceToService(identity, clientIp, serviceName, description, string(auditActionType))
	if err != nil {
		a.Log.Errorf("%v", err)
	}
}
