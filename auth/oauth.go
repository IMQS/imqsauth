package imqsauth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/IMQS/authaus"
)

// This file deals with OAuth authentication flows, and was initially built only for
// Microsoft Azure Active Directory

type oauthProviderJSON struct {
	Name      string // eg "emerge". Internal name that you use for example, in https://HOST/auth2/oauth/start?provider=<Name>
	Type      string // eg "msaad". Same as in config file
	Title     string // eg "eMerge". text title that you can show the user
	IsDefault bool   // If true, and the login URL doesn't instruct you otherwise, then "click" this button for the user as soon as page load finishes
}

func httpHandlerOAuthStart(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	if r.http.FormValue("provider") == "msaad" {
		_, e := authaus.HttpHandlerPrelude(&central.Config.Authaus.HTTP, central.Central, r.http)
		if errors.Is(authaus.ErrHttpNotAuthorized, e) {
			// inject an extra parameter here to enable profile selection
			r.http.URL.Query().Set("prompt", "select_account")
		}
	}
	central.Central.OAuth.HttpHandlerOAuthStart(w, r.http)
	// xxxx This is problematic, because httphandleroauthstart already returns
}

func httpHandlerOAuthFinish(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	err := central.oauthFinishInternal(w, r)

	if err != nil {
		central.Central.Log.Errorf("OAuth finish error : %v", err)
		http.Redirect(w, r.http, "/?oauthError="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}

	// oauthFinishInternal has already set the cookie on the response object, so all we need
	// to do is redirect the user to the page he wants to go to
	http.Redirect(w, r.http, "/", http.StatusFound)
}

func (icentral *ImqsCentral) oauthFinishInternal(w http.ResponseWriter, r *httpRequest) error {
	acentral := icentral.Central
	res, err := acentral.OAuth.OAuthFinish(r.http)
	if err != nil {
		return err
	}

	if res.UserId == authaus.UserId(0) {
		// This situation happens when AllowCreateUser is false in the OAuth config, and
		// a new user is trying to login. In such a case, the user is not allowed to login.
		// The idea with AllowCreateUser=false is that user profiles need to be loaded
		// via some other mechanism such as the MSAAD sync functionality in Authaus,
		// or perhaps LDAP sync.
		return errors.New("Your profile is not enabled for login")
	}

	// Ensure the user has a permit, regardless of whether it's a new user or not.
	// This is partly due to the messy upgrade paths that we follow on our live systems,
	// from trying our LDAP integration, to OAuth.
	// If a permit exists, then do nothing.
	// If no permit exists, then create an initial one with the 'enabled' permission.
	// Initially, I thought that I could follow this code path only if the user was
	// never-before-seen (ie res.IsNewUser), however that turns out to be insufficient,
	// because we may have seen the user via LDAP.
	_, err = acentral.GetPermit(res.UserId)
	if err != nil && strings.Index(err.Error(), authaus.ErrIdentityPermitNotFound.Error()) == 0 {
		// Permit not found.
		// Give the new user some initial permissions, by adding her to some groups
		if acentral.OAuth.Config.Verbose {
			acentral.Log.Infof("OAuth user permit not found, creating new permit for UserID:%v", res.UserId)
		}
		groups := []string{
			PermissionsTable[PermEnabled],
		}
		if err := setUserPermissionGroupsByName(icentral, res.UserId, groups); err != nil {
			return fmt.Errorf("Failed to set initial permission: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("Error retrieving permit: %w", err)
	} else {
		// user permit already exists, so don't mess with it
		if acentral.OAuth.Config.Verbose {
			acentral.Log.Infof("OAuth user permit already exists for UserID:%v", res.UserId)
		}
	}

	user, err := acentral.GetUserFromUserId(res.UserId)
	if err != nil {
		return fmt.Errorf("Failed to get full user record: %w", err)
	}

	// Log the user in
	sessionKey, token, err := acentral.CreateSession(&user, getIPAddress(r.http), res.OAuthSessionID)
	if err != nil {
		return fmt.Errorf("Failed to create session record: %w", err)
	}

	_, err = icentral.validateUserIsEnabledForNewLogin(sessionKey, token, r)
	if err != nil {
		return err
	}
	icentral.setSessionCookie(sessionKey, token, w)

	// User successfully logged in
	icentral.Central.Log.Infof("OAuth login successful (%v)", user.UserId)
	return nil
}

func httpHandlerOAuthProviders(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	available := []oauthProviderJSON{}
	for name, p := range central.Central.OAuth.Config.Providers {
		j := oauthProviderJSON{
			Type:      p.Type,
			Title:     p.Title,
			Name:      name,
			IsDefault: name == central.Central.OAuth.Config.DefaultProvider,
		}
		available = append(available, j)
	}
	authaus.HttpSendJSON(w, 200, available)
}

func httpHandlerOAuthTest(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	central.Central.OAuth.HttpHandlerOAuthTest(w, r.http)
}
