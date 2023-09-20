# Changelog

## Current

## v1.2.3

* fix: User management endpoints fail on missing groups (ASG-1990)
* fix: Update authaus to v1.0.31

## v1.2.2

* fix: Invalid check on group import for pre-existing groups

## v1.2.1

* fix: update authaus to v1.0.30 (enhance oauth logging)

## v1.2.0

* feat(mail): Adds new config to send custom `from` and `subject` for LDAP reset
password emails.
* feat(mail): Adds new config to send custom `from` and specify a template to be
used as an email body when resetting a password, or confirming a new account.
The URL for mailer has also been made configurable. (ASG-2630)

## v1.1.2

* fix: Update authaus version. (ASG-2622)
* fix: Change all MSAAD debug logs to info (ASG-2622) 

## v1.1.1

* fix: Updated authus version. (ASG-2452) 

## v1.1.0

* fix: Ensure that special users get mapped to usernamemap. (ASG-2210)
