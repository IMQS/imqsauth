# Changelog

## Current

* feat: Add group id to /groups endpoint (ASG-3348)

## v1.4.0

* feat: New "health" package for maintenance and health related actions (ASG-2921)
* feat: New "healthcheck" CLI function - stats re. users, missing groups and 
orphaned tokens (ASG-2921)
* feat: New "fixdb" CLI function - to remove missing groups from permits (ASG-2921)

## v1.3.0

* fix: Auth Audit records wrong email if username is blank (ASG-3270) 
* feat: Update authaus to v1.0.34
* fix: Update to Go 1.18  
Our builder image was set to Go 1.16, imqsauth to 1.17 and the previous version
of authaus to 1.17. All 3 has now been aligned to Go 1.18 in preparation for
upgrading to 1.20.

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
