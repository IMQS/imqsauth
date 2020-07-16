package imqsauth

import (
	"fmt"
	"net/http"

	"github.com/IMQS/authaus"
)

// setSessionCookieIfPermitOK checks if the user has the 'enabled' permission, and if so, it sends a Set-Cookie
// header back to the browser. All code paths of this function will write a result into 'w'
func (icentral *ImqsCentral) setSessionCookieIfPermitOK(sessionKey string, token *authaus.Token, w http.ResponseWriter, r *httpRequest) {
	r.token = token
	auditUserLogAction(icentral, r, token.UserId, token.Identity, "User Profile: "+token.Identity, authaus.AuditActionAuthentication)
	if permList, egroup := authaus.PermitResolveToList(token.Permit.Roles, icentral.Central.GetRoleGroupDB()); egroup != nil {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, egroup.Error())
	} else {
		// Ensure that the user has the 'Enabled' permission
		if !permList.Has(PermEnabled) {
			httpSendAccountDisabled(w)
		} else {
			icentral.setSessionCookie(sessionKey, token, w)
			httpSendCheckJson(w, token, permList)
		}
	}
}

// Returns ErrUserDisabled if the user does not have the 'enabled' permission
func (icentral *ImqsCentral) validateUserIsEnabledForNewLogin(sessionKey string, token *authaus.Token, r *httpRequest) (authaus.PermissionList, error) {
	r.token = token
	auditUserLogAction(icentral, r, token.UserId, token.Identity, "User Profile: "+token.Identity, authaus.AuditActionAuthentication)
	permList, err := authaus.PermitResolveToList(token.Permit.Roles, icentral.Central.GetRoleGroupDB())
	if err != nil {
		return nil, fmt.Errorf("Failed to resolve permit: %w", err)
	} else if !permList.Has(PermEnabled) {
		return permList, ErrUserDisabled
	}
	return permList, nil
}

func (icentral *ImqsCentral) setSessionCookie(sessionKey string, token *authaus.Token, w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:    icentral.Config.Authaus.HTTP.CookieName,
		Value:   sessionKey,
		Path:    "/",
		Expires: token.Expires,
		Secure:  icentral.Config.Authaus.HTTP.CookieSecure,
	}
	http.SetCookie(w, cookie)
}
