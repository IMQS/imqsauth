IMQSAuth Service
===

## Overview and system context
The Auth service is an authentication and authorization service, that consists of 2 parts; Authaus and ImqsAuth.

**Authaus** consists of multiple components, namely: LDAP, MSAAD, OAuth, UserStore, SessionDB, PermitDB and RoleGroupsDB.

- The **LDAP** component's main responsibility is Authentication. It connects and binds to an LDAP/AD server for authentication purposes as well as data retrieval purposes (such as retrieving user objects).
- The **MSAAD** component's is responsible for merging of users from the configured MSAAD provider. In addition, it will also match up the **roles** present in MSAAD with **groups** in IMQS, based on a mapping in the `imqsauth.json` file. The synchronization also handles removing users from the system should their permissions have been revoked or the user has been removed or disabled.
- The **OAuth** component handles the OAuth flow with the required redirects via the front-end.
- The **UserStore** component stores user data and is also responsible for authentication when NOT using an LDAP server. When a user is stored in the **UserStore**, a unique id is generated for that user to identify that user throughout the system, and outside the system.
- The **SessionDB** stores session data related to a user.
- The **PermitDB** stores the permissions.
- The **RoleGroupDB** knows how to interpret the permissions.

**Definitions**

**Identity** - This refers to the Login Name of the user. It may be an email address e.g. joe@email.com or a username e.g. joey08. Typically, when using the Auth system without LDAP, we will use an email address. With LDAP/AD we would use an LDAP username. MSAAD would try and use email but can also support username only in some circumstances.

### AuthUserType
**AuthUserType** was introduced to the auth system, when we started integrating with LDAP. We needed to distinguish between IMQS managed users and users managed elsewhere. It is not limited to these 2 types, we can add more if need be in the future (IMQS, LDAP, MSAAD)

**LDAP and MSAAD Users:**

- We cannot change these users, they are imported from LDAP or MSAAD
- Authentication for these users will be delegated to the LDAP or MSAAD system specified in config.
- If a user uses the Forgot Password functionality, the auth system would simply email them, telling them to contact their system administrator, and also give their sysadmin's email address IF specified in config (SysAdminEmail).

## Installation Instructions
The Auth Service is installed as part of the standard v8 deployment bundle.

### Required configuration files
`imqsbin/static-conf/imqsauth.json` merged with `imqsbin/conf/imqsauth.json`
Even though the configuration primarily concerns the `authaus` module which **ImqsAuth** makes use of, we present the configuration here for easy reference.

Here is a snippet of the config:

```json
{
	"Authaus": {
		"Log": {
			"Filename": "[/var/log/imqs/|c:\\imqsvar\\logs\\]imqsauth.log"
		},
		"HTTP": {
			"Bind": "[0.0.0.0|127.0.0.1]",
			"Port": "[80|2003]"
		},
		"DB": {
			"Driver": "{{PG_DRIVER}}",
			"Host": "{{PG_DB_HOST}}",
			"Database": "auth",
			"User": "{{PG_DB_USERNAME}}",
			"Password": "{{PG_DB_PASSWORD}}",
			"SSL": false,
			"Port": 6432
		},
		"OAuth": {
			"Verbose": true,
			"DefaultProvider": "eMerge",
			"Providers": {
				"eMerge": {
					"Type": "msaad",
					"Title": "eMerge",
					"LoginURL": "https://login.microsoftonline.com/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/oauth2/v2.0/authorize",
					"TokenURL": "https://login.microsoftonline.com/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/oauth2/v2.0/token",
					"RedirectURL": "https://hostname/auth2/oauth/finish",
					"ClientID": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
					"Scope": "openid email offline_access",
					"ClientSecret": "zzzzz_zzzzzzz.-zz-zzzzzzzz_zzzzzzz",
					"AllowCreateUser": true
				}
			}
		},
		"MSAAD": {
			"Verbose": true,
			"DryRun": false,
			"TenantID": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			"ClientID": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
			"ClientSecret": "zzzzz_zzzzzzz.-zz-zzzzzzzz_zzzzzzz",
			"EssentialRoles": [

			],
			"DefaultRoles": [
				"enabled"
			],
			"RoleToGroup": {
				"APP_USER_DTPW_IMQS_PPRD_LEASING_Admin": "DTPW Leasing Admin",
				"APP_USER_DTPW_IMQS_PPRD_LEASING_Lease-in Analyst": "DTPW Lease-in Analyst",
				"APP_USER_DTPW_IMQS_PPRD_LEASING_Lease-in Approver": "DTPW Lease-in Approver",
				"APP_USER_DTPW_IMQS_PPRD_LEASING_Lease-in Manager": "DTPW Lease-in Manager",
				"APP_USER_DTPW_IMQS_PPRD_LEASING_Lease-out Analyst": "DTPW Lease-out Analyst",
				"APP_USER_DTPW_IMQS_PPRD_LEASING_Lease-out Approver": "DTPW Lease-out Approver",
				"APP_USER_DTPW_IMQS_PPRD_LEASING_Lease-out Manager": "DTPW Lease-out Manager",
				"APP_USER_DTPW_IMQS_PPRD_LEASING_Viewer": "DTPW Leasing Viewer",
				"APP_USER_DTPW_IMQS_PPRD_Admin": "admin",
				"APP_USER_DTPW_IMQS_PPRD_MM_SystemAdmin": "DTPW MM System Admin"
			},
			"PassthroughClientIDs": [
				"pppppppp-pppp-pppp-pppp-pppppppppppp",
				"qqqqqqqq-qqqq-qqqq-qqqq-qqqqqqqqqqqq"
			],
			"AllowArchiveUser": false
		},
		"SessionDB": {
			"SessionExpirySeconds": 43200
		}
	},
	"Permissions": {
		"dynamic": [
			{
				"id": "15000",
				"name": "WRSubmit",
				"friendly": "Work Request - Submit",
				"description": "Allow user to submit a work request",
				"module": "Maintenance Management"
			},
			{
				"id": "15001",
				"name": "WRActivate",
				"friendly": "Work Request - Activate",
				"description": "Allow user to activate a work request",
				"module": "Maintenance Management"
			},
			{
				"id": "15002",
				"name": "WRReject",
				"friendly": "Work Request - Reject",
				"description": "Allow user to reject a work request",
				"module": "Maintenance Management"
			}
		],
		"disable": [
			"mmWorkRequestView",
			"mmWorkRequestAddAndDelete",
			"mmWorkRequestUpdate"
		]
	}
}
```

\* Formal schema to be defined

Ldap config: This config is not mandatory, as the auth system does not need an LDAP implementation to rely on authentication. When not supplying an LDAP configuration, the system assumes it must perform its own authentication and there is no LDAP implementation.

UserStore config: This specifies the database that will be used to store users and the users' metadata.

### **DB Migrations**
In May 2016, we changed the migration tool, and the migration versioning tables have been changed.

Previously there was a migration version table for each table for example: table: `authuser` had its own migration version table called: `authuser\_version` containing the migration number that last took place.

However, after some altering and changes to them **Auth** system, we now use a migration tool, that utilizes one table to keep track of the last db migration number, called: migration\_version.

The last migration that took place with the old migration tool, before using the new migration tool, left the migration version tables on the following versions for each table:

| **Table**   | **Migration Version Table** | **Migration Version Number** |
|-------------|-----------------------------|------------------------------|
| authuser    | authuser\_version           | 3                            |
| authsession | authsession\_version        | 2                            |
| authgroup   | authgroup\_version          | 1                            |

## **Troubleshooting**
### **Logs**
The location of the log files are specified in `/imqsvar/logs/imqsauth.log`.
### **Known defects**
### **Authentication Service not Running**
#### **Symptoms:**
- Exceptions are visible in the log files 
#### **Solution:**
You will need to look at the trace log and investigate the cause of the exceptions. More than likely it is due to incorrect configuration of the database connection details.
### **Authentication Service Running but cannot Create Users, or Login etc**
#### **Symptoms:**
- Exceptions are visible in the log files
#### **Solution:**
It is possible that the db was not created/migrated to new version described in


### **User cannot log in after switching a system to use LDAP/AD**

#### **Symptoms:**


- A user cannot log in after the switch


#### **Solution:**


Any accounts created prior to the LDAP switch, that have a username that ALSO exists on the LDAP system, will become LDAP users (will no longer be IMQS users, see AuthUserType). This would mean that they would become authenticated by their LDAP system, and NOT IMQS Auth system. Thus, they should not be using their IMQS username and password (normally email and password), but their LDAP username and password.

## API

The fully documented API can be found [here](API.md).

## **Internal and design details**
Peer review:

[ben (Unlicensed)](https://imqssoftware.atlassian.net/wiki/people/557058:c3dcfbd6-b279-4504-b4ba-d0194d9595c5?ref=confluence)




