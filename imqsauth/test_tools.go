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
		joeUserId, _ := ic.Central.CreateUserStoreIdentity("joe", "joeUsername", "joeFirstname", "joeLastname", "joe084", "JOE")
		jackUserId, _ := ic.Central.CreateUserStoreIdentity("jack", "jackUsername", "jackFirstname", "jackLastname", "jack084", "JACK")
		adminUserId, _ := ic.Central.CreateUserStoreIdentity("admin", "adminUsername", "adminFirstname", "adminLastname", "admin084", "ADMIN")
		adminDisabledUserId, _ := ic.Central.CreateUserStoreIdentity("admin_disabled", "admin_disabledUsername", "admin_disabledFirstname", "admin_disabledLastname", "admin_disabled084", "ADMIN_DISABLED")
		groupAdmin, _ := ic.Central.GetRoleGroupDB().GetByName(RoleGroupAdmin)
		groupEnabled, _ := ic.Central.GetRoleGroupDB().GetByName(RoleGroupEnabled)
		permitEnabled := &authaus.Permit{}
		permitEnabled.Roles = authaus.EncodePermit([]authaus.GroupIDU32{groupEnabled.ID})
		permitAdminEnabled := &authaus.Permit{}
		permitAdminEnabled.Roles = authaus.EncodePermit([]authaus.GroupIDU32{groupAdmin.ID, groupEnabled.ID})
		permitAdminDisabled := &authaus.Permit{}
		permitAdminDisabled.Roles = authaus.EncodePermit([]authaus.GroupIDU32{groupAdmin.ID})
		ic.Central.SetPermit(joeUserId, permitEnabled)
		ic.Central.SetPermit(jackUserId, permitEnabled)
		ic.Central.SetPermit(adminUserId, permitAdminEnabled)
		ic.Central.SetPermit(adminDisabledUserId, permitAdminDisabled)
		return true
	}
	return false
}
