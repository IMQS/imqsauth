# POST /reset_password_start

TODO: Summary

## Query Parameters

| Param  | Description                                       |
| ------ | ------------------------------------------------- |
| userid | id of the user that needs their password reset    |
| email  | email of the user that needs their password reset |

## Authaus

TODO: Talk about our interaction with authaus, and include links to authaus
documentation on the functions we make use of.

# Structs

## MailParameters

```go
type MailParameters struct {
	// Name of the template that the mail server should use when generating the
	// email body. Optional.
	TemplateName *string `json:"TemplateName,omitempty"`
	// Custom from variable to be used by mailer service. Optional
	// eg: IMQS Password Reset <noreply@imqs.co.za>
	From *string `json:"From,omitempty"`
}
```

## SendMailDetails

```go
type SendMailDetails struct {
	// URL of mail server. Optional.
	URL           *string         `json:"URL,omitempty"`
	PasswordReset *MailParameters `json:"PasswordReset,omitempty"`
	NewAccount    *MailParameters `json:"NewAccount,omitempty"`
}
```

Refer to [MailParameters](#mailparameters) for more info on `PasswordReset` and
`NewAccount`.

# Config

Example config:
```json
{
	"SendMailDetails": {
		"URL": "https://imqs-mailer.appspot.com",
		"PasswordReset": {
			"TemplateName": "skypipe-inc-reset-password",							// See https://github.com/IMQS/imqs-mailer#api for more info on valid templates
			"From": "SkyPipe Inc. Password Reset <noreply@skypipeinc.com>"
		},
		"NewAccount": {
			"TemplateName": "skypipe-inc-new-account-confirm",						// See https://github.com/IMQS/imqs-mailer#api for more info on valid templates
			"From": "SkyPipe Inc. Account Confirmation <noreply@skypipeinc.com>"
		}
	}
}
```

Refer to [SendMailDetails](#sendmaildetails) for more info on each of its
variables.
