package imqsauth

import (
	"github.com/IMQS/authaus"
)

const TestConfig1 = "!TESTCONFIG1"
const TestPort = 3377

func LoadTestConfig(ic *ImqsCentral, testConfigName string) bool {
	if testConfigName == TestConfig1 {
		ic.Config.ResetForUnitTests()
		ic.Config.Authaus.HTTP.Bind = "127.0.0.1"
		ic.Config.Authaus.HTTP.Port = TestPort
		ic.Central = authaus.NewCentralDummy("")
		ResetAuthGroups(ic)
		ic.Central.CreateAuthenticatorIdentity("joe", "JOE")
		ic.Central.CreateAuthenticatorIdentity("jack", "JACK")
		ic.Central.CreateAuthenticatorIdentity("admin", "ADMIN")
		ic.Central.CreateAuthenticatorIdentity("admin_disabled", "ADMIN_DISABLED")
		groupAdmin, _ := ic.Central.GetRoleGroupDB().GetByName(RoleGroupAdmin)
		groupEnabled, _ := ic.Central.GetRoleGroupDB().GetByName(RoleGroupEnabled)
		permitEnabled := &authaus.Permit{}
		permitEnabled.Roles = authaus.EncodePermit([]authaus.GroupIDU32{groupEnabled.ID})
		permitAdminEnabled := &authaus.Permit{}
		permitAdminEnabled.Roles = authaus.EncodePermit([]authaus.GroupIDU32{groupAdmin.ID, groupEnabled.ID})
		permitAdminDisabled := &authaus.Permit{}
		permitAdminDisabled.Roles = authaus.EncodePermit([]authaus.GroupIDU32{groupAdmin.ID})
		ic.Central.SetPermit("joe", permitEnabled)
		ic.Central.SetPermit("jack", permitEnabled)
		ic.Central.SetPermit("admin", permitAdminEnabled)
		ic.Central.SetPermit("admin_disabled", permitAdminDisabled)
		return true
	}
	return false
}
