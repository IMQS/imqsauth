package imqsauth

import (
	"fmt"
	"net/http"

	"github.com/IMQS/authaus"
)

// Returns ErrUserDisabled if the user does not have the 'enabled' permission
func (icentral *ImqsCentral) validateUserIsEnabledForNewLogin(sessionKey string, token *authaus.Token, r *httpRequest) (authaus.PermissionList, error) {
	r.token = token
	auditUserLogAction(icentral, r, token.UserId, token.Identity, "User Profile: "+token.Identity, authaus.AuditActionAuthentication)
	permList, err := authaus.PermitResolveToList(token.Permit.Roles, icentral.Central.GetRoleGroupDB())
	if err != nil && permList == nil {
		return nil, fmt.Errorf("Failed to resolve permit: %w", err)
	} else {
		if err != nil {
			if permList.Has(PermEnabled) {
				// Log here, since we'll be losing the detail error due to function semantics
				icentral.Central.Log.Warnf("validateUserIsEnabledForNewLogin: Failed to resolve permit : %v", err)
				return permList, nil
			} else {
				return permList, fmt.Errorf("Failed to resolve permit: %w", err)
			}
		} else {
			if !permList.Has(PermEnabled) {
				return permList, ErrUserDisabled
			}
			return permList, nil
		}
	}
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
