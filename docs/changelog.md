# Changelog

## v1.9.0

* fix: Fix 'showidentities' command line option (NEXUS-4832)
* feat: Add provider function to retrieve visible entra groups (ASG-4959)
* fix: Set browser cookie to expire on /logout (asg-5004)

## v1.8.2

* perf: Uses new getUserStatsAll function in authaus (ASG-4879)

## v1.8.1

* fix: Updates the generation of the permissions and modules code (#104)
* docs: Updates OpenAPI servers property

## v1.8.0

* feat: Add new columns under "User List" exports (NEXUS-4245)
* feat: Update serviceauth to v1.4.0 (NEXUS-4245)
* feat: Update authaus to v1.3.7 (NEXUS-4245)
* feat: Update authaus to v1.3.6  (NEXUS-4317)
* feat: Enhance IMQS user update to include changed values

## v1.7.4

* fix: Update authaus version to v1.3.5 (NEXUS-4246)

## v1.7.3

* feat: Update authaus version to v1.3.4 (ASG-3268)
* feat: Add enabled and disabled audit user types (NEXUS-4244)
* fix: Ensure records does not duplicate on user audit trail (NEXUS-4161)
* fix: Ensure group changes works on user with no permit (NEXUS-4289)

## v1.7.2

* fix: Update authaus version to v1.3.1

## v1.7.1

* feat: Add user's group diff update to audit log 

## v1.7.0

* fix: Update golang to 1.22.7

## v1.6.5
* feat: Enhance IMQS user update to include changed values
* fix: Update authaus version to v1.1.2 (asg-3355)

## v1.6.4

* fix: Update authaus version to v1.1.1 (asg-3355)

## v1.6.3 (retracted)

* fix: Update authaus version to v1.1.0 (unarchive feature and fixes) (asg-3355)

## v1.6.2

* fix: Patch OAuth security breach in redirect URL (asg-3855)

## v1.6.1

* fix: Add missing log statements to align normal login logs with OAuth logs 

## v1.6.0

* feat: Adds userobject GET endpoint (#95) (ASG-3308)

## v1.5.1

* feat: Write empty permission list as <none> for Group Perm updates (ASG-3387)
* fix: Fix missing variable in MSAAD log

## v1.5.0

* feat: Update authaus to v1.0.36
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
