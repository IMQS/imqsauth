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

func (a *IMQSAuditor) AuditUserAction(username, item, context string, auditActionType authaus.AuditActionType) {
	err := serviceauth.AddToAuditLogServiceToService(username, string(auditActionType), item, context)
	if err != nil {
		a.Log.Errorf("%v", err)
	}
}
