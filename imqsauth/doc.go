/*
Package imqsauth implements a service that answers various authentication and authorization questions.

'imqsauth' is built on top of Authaus, which is a generic authentication and authorization package.

There may come a day when we need data-dependent permissions, such as
"Allowed to edit assets with ID = 3017". These kinds of permissions
cannot be hard-coded into the application, so they don't fit into
this scheme. However, it should not be too difficult to expand this
system to accomodate that kind of thing.

Example config file:

{
	"Authaus": {...},								-- See config.go in Authaus package for description of the Authaus config
	"Yellowfin": {
		"Enabled": true
	},
	"PasswordResetExpirySeconds": 3600,
	"HostnameFile": "hostname",						-- Relative to the location of imqsauthconfig.json, or an absolute path
	"SendMailPassword": "password123"
}
*/
package imqsauth
