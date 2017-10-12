package imqsauth

import (
	"time"

	"github.com/IMQS/authaus"
)

const TestConfig1 = "!TESTCONFIG1"
const TestPort = "3377"

func LoadTestConfig(ic *ImqsCentral, testConfigName string) bool {
	if testConfigName == TestConfig1 {
		ic.Config.ResetForUnitTests()
		ic.Config.Authaus.HTTP.Bind = "127.0.0.1"
		ic.Config.Authaus.HTTP.Port = TestPort
		ic.Central = authaus.NewCentralDummy("")
		ResetAuthGroups(ic)
		now := time.Now().UTC()
		joeUser := authaus.AuthUser{
			Email:           "joe",
			Username:        "joeUsername",
			Firstname:       "joeFirstname",
			Lastname:        "joeLastname",
			Mobilenumber:    "joe084",
			Telephonenumber: "joe021",
			Remarks:         "joe test",
			Created:         now,
			CreatedBy:       0,
			Modified:        now,
			ModifiedBy:      0,
		}
		joeUserId, _ := ic.Central.CreateUserStoreIdentity(&joeUser, "JOE")

		jackUser := authaus.AuthUser{
			Email:           "jack",
			Username:        "jackUsername",
			Firstname:       "jackFirstname",
			Lastname:        "jackLastname",
			Mobilenumber:    "jack084",
			Telephonenumber: "jack021",
			Remarks:         "jack test",
			Created:         now,
			CreatedBy:       0,
			Modified:        now,
			ModifiedBy:      0,
		}
		jackUserId, _ := ic.Central.CreateUserStoreIdentity(&jackUser, "JACK")

		adminUser := authaus.AuthUser{
			Email:           "admin",
			Username:        "adminUsername",
			Firstname:       "adminFirstname",
			Lastname:        "adminLastname",
			Mobilenumber:    "admin084",
			Telephonenumber: "admin021",
			Remarks:         "admin test",
			Created:         now,
			CreatedBy:       0,
			Modified:        now,
			ModifiedBy:      0,
		}
		adminUserId, _ := ic.Central.CreateUserStoreIdentity(&adminUser, "ADMIN")

		adminDisabledUser := authaus.AuthUser{
			Email:           "admin_disabled",
			Username:        "adminDisabledUsername",
			Firstname:       "adminDisabledFirstname",
			Lastname:        "adminDisabledLastname",
			Mobilenumber:    "adminDisabled084",
			Telephonenumber: "adminDisabled021",
			Remarks:         "adminDisabled test",
			Created:         now,
			CreatedBy:       0,
			Modified:        now,
			ModifiedBy:      0,
		}
		adminDisabledUserId, _ := ic.Central.CreateUserStoreIdentity(&adminDisabledUser, "ADMIN_DISABLED")
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
