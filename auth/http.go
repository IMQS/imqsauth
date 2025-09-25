package imqsauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/IMQS/authaus"
	"github.com/IMQS/imqsauth/utils"
	"github.com/IMQS/serviceauth"
)

// On the usage of defer() and panic() inside this file, as an exception handling mechanism:
//
// If you use panic(), do so only from a function which has a defer() recover mechanism inside it.
// In other words, do not allow a panic() to escape from a single function. Doing so brings with it
// the worst property of exceptions, which is their opaqueness.

const (
	msgAccountDisabled = "Account disabled"
	msgNotAdmin        = "You are not an administrator"
)

var (
	errNoUserId = errors.New("No userid specified")
)

type HttpMethod string

type LoginType struct {
	LoginType string `json:"login_type"`
	ClientId  string `json:"client_id"`
}

const (
	HttpMethodGet  HttpMethod = "GET"
	HttpMethodPost            = "POST"
	HttpMethodPut             = "PUT"
	HttpMethodAny             = "*"
)

type handlerFlags uint32

const (
	handlerFlagNeedAdminRights  = 1 << iota // Request won't even reach your handler unless the user is an admin
	handlerFlagNeedToken                    // Populate the httpRequest object with 'token' and 'permList'
	handlerFlagNeedInterService             // Request requires interservice authorization
)

type httpRequest struct {
	http     *http.Request
	token    *authaus.Token // Only populated if you passed in handlerFlagNeedAdminRights or handlerFlagNeedToken
	permList authaus.PermissionList
}

type checkResponseJson struct {
	UserId       authaus.UserId
	Identity     string
	Email        string
	Username     string
	Roles        []string
	InternalUUID string
}

type notificationRequestJson struct {
	Channel string
	Msg     string
}

func (x *checkResponseJson) SetRoles(roles authaus.PermissionList) {
	x.Roles = make([]string, len(roles))
	for i, role := range roles {
		x.Roles[i] = fmt.Sprintf("%d", role)
	}
}

type groupResponseJson struct {
	Name  string
	Roles []string
	ID    string
}

func (x *groupResponseJson) SetGroup(group *authaus.AuthGroup) {
	x.Name = group.Name
	x.Roles = make([]string, len(group.PermList))
	for i, role := range group.PermList {
		x.Roles[i] = fmt.Sprintf("%d", role)
	}
	x.ID = fmt.Sprintf("%d", group.ID)
}

type groupsResponseJson struct {
	Email    string
	UserName string
	Name     string
	Surname  string
	Groups   []string
}

type userGroups struct {
	Groups          []authaus.RawAuthGroup
	Users           []exportGroupUser
	OverwriteGroups bool
}

type exportGroupUser struct {
	ID     string
	Groups []int
}
type ImqsCentral struct {
	Config  *Config
	Central *authaus.Central

	// Guards access to roleChangeSubscribers and lastSubscriberId
	subscriberLock sync.RWMutex
}

// Admin accounts are not lockable, otherwise an attack could lock all accounts with noone to unlock them.
// Additionally inter-service accounts are also admins, and we dont want "machine" accounts to be lockable.
func (x *ImqsCentral) IsLockable(identity string) (bool, error) {

	var err error
	if user, eUser := x.Central.GetUserFromIdentity(identity); eUser == nil {
		if perm, ePerm := x.Central.GetPermit(user.UserId); ePerm == nil {
			if pbits, eGroup := authaus.PermitResolveToList(perm.Roles, x.Central.GetRoleGroupDB()); eGroup == nil {
				return !pbits.Has(PermAdmin), nil
			}
		} else {
			err = ePerm
		}
	} else {
		err = eUser
	}

	return false, err
}

func (x *ImqsCentral) makeHandler(method HttpMethod, actual func(*ImqsCentral, http.ResponseWriter, *httpRequest), flags handlerFlags) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if string(method) != HttpMethodAny && r.Method != string(method) {
			authaus.HttpSendTxt(w, http.StatusBadRequest, fmt.Sprintf("API must be accessed using an HTTP %v method", method))
			return
		}
		httpReq := &httpRequest{
			http: r,
		}

		needAdmin := 0 != (flags & handlerFlagNeedAdminRights)
		needToken := 0 != (flags & handlerFlagNeedToken)
		needInterService := 0 != (flags & handlerFlagNeedInterService)
		if !needAdmin && !needToken && !needInterService {
			actual(x, w, httpReq)
			return
		}

		if err := serviceauth.VerifyInterServiceRequest(r); err == nil {
			actual(x, w, httpReq)
			return
		}

		if needInterService {
			authaus.HttpSendTxt(w, http.StatusInternalServerError, "API requires interservice permissions")
			return
		}

		permOK := false
		if token, err := authaus.HttpHandlerPreludeWithError(&x.Config.Authaus.HTTP, x.Central, w, r); err == nil {
			permList, errDecodePerms := authaus.PermitResolveToList(token.Permit.Roles, x.Central.GetRoleGroupDB())
			if errDecodePerms != nil && permList == nil {
				x.Central.Log.Errorf("%v: could not resolve permits: %v", r.URL.Path, errDecodePerms)
				authaus.HttpSendTxt(w, http.StatusInternalServerError, errDecodePerms.Error())
			} else {
				if errDecodePerms != nil {
					x.Central.Log.Warnf("%v: could not resolve permits: %v", r.URL.Path, errDecodePerms)
				}
				httpReq.token = token
				httpReq.permList = permList
				if needAdmin {
					if !permList.Has(PermAdmin) {
						authaus.HttpSendTxt(w, http.StatusForbidden, msgNotAdmin)
					} else if !permList.Has(PermEnabled) {
						httpSendAccountDisabled(w)
					} else {
						permOK = true
					}
				} else {
					// for this case (ie needToken), so long as we have the token and permList, we are fine
					permOK = true
				}
			}
		} else {
			// HttpHandlerPreludeWithError has already sent the error to http.ResponseWriter
			permOK = false
		}

		if !permOK {
			return
		}

		actual(x, w, httpReq)
	}
}

func (x *ImqsCentral) RunHttp() error {
	// The built-in go ServeMux does not support differentiating based on HTTP verb, so we have to make
	// the request path unique for each verb. I think this is OK as far as API design is concerned - at least in this domain.
	smux := http.NewServeMux()
	smux.HandleFunc("/hello", x.makeHandler(HttpMethodGet, httpHandlerHello, 0))
	smux.HandleFunc("/ping", x.makeHandler(HttpMethodGet, httpHandlerPing, 0))
	smux.HandleFunc("/hostname", x.makeHandler(HttpMethodGet, httpHanderHostname, 0))
	smux.HandleFunc("/login", x.makeHandler(HttpMethodPost, httpHandlerLogin, 0))
	smux.HandleFunc("/logout", x.makeHandler(HttpMethodPost, httpHandlerLogout, 0))
	smux.HandleFunc("/check", x.makeHandler(HttpMethodGet, httpHandlerCheck, 0))
	smux.HandleFunc("/create_user", x.makeHandler(HttpMethodPut, httpHandlerCreateUser, handlerFlagNeedAdminRights))
	smux.HandleFunc("/update_user", x.makeHandler(HttpMethodPost, httpHandlerUpdateUser, handlerFlagNeedAdminRights))
	smux.HandleFunc("/unlock_user", x.makeHandler(HttpMethodPost, httpHandlerUnlockUser, handlerFlagNeedAdminRights))
	smux.HandleFunc("/archive_user", x.makeHandler(HttpMethodPost, httpHandlerArchiveUser, handlerFlagNeedAdminRights))
	smux.HandleFunc("/create_group", x.makeHandler(HttpMethodPut, httpHandlerCreateGroup, handlerFlagNeedAdminRights))
	smux.HandleFunc("/update_group", x.makeHandler(HttpMethodPost, httpHandlerUpdateGroup, handlerFlagNeedAdminRights))
	smux.HandleFunc("/delete_group", x.makeHandler(HttpMethodPut, httpHandlerDeleteGroup, handlerFlagNeedAdminRights))
	smux.HandleFunc("/rename_user", x.makeHandler(HttpMethodPost, httpHandlerRenameUser, handlerFlagNeedToken))
	smux.HandleFunc("/set_group_roles", x.makeHandler(HttpMethodPut, httpHandlerSetGroupRoles, handlerFlagNeedAdminRights))
	smux.HandleFunc("/set_user_groups", x.makeHandler(HttpMethodPost, httpHandlerSetUserGroups, handlerFlagNeedAdminRights))
	smux.HandleFunc("/set_password", x.makeHandler(HttpMethodPost, httpHandlerSetPassword, handlerFlagNeedToken))
	smux.HandleFunc("/update_password", x.makeHandler(HttpMethodPost, httpHandlerUpdatePassword, 0))
	smux.HandleFunc("/check_password", x.makeHandler(HttpMethodPost, httpHandlerCheckPassword, 0))
	smux.HandleFunc("/reset_password_start", x.makeHandler(HttpMethodPost, httpHandlerResetPasswordStart, 0))
	smux.HandleFunc("/reset_password_finish", x.makeHandler(HttpMethodPost, httpHandlerResetPasswordFinish, 0))
	smux.HandleFunc("/users", x.makeHandler(HttpMethodGet, httpHandlerGetEmails, handlerFlagNeedToken))
	smux.HandleFunc("/userobjects", x.makeHandler(HttpMethodGet, httpHandlerGetUsers, handlerFlagNeedAdminRights))
	smux.HandleFunc("/userobject", x.makeHandler(HttpMethodGet, httpHandlerGetUser, handlerFlagNeedAdminRights))
	smux.HandleFunc("/groups", x.makeHandler(HttpMethodGet, httpHandlerGetGroups, 0))
	smux.HandleFunc("/exportgroups", x.makeHandler(HttpMethodGet, httpHandlerExportUserGroups, handlerFlagNeedAdminRights))
	smux.HandleFunc("/importgroups", x.makeHandler(HttpMethodPost, httpHandlerImportUserGroups, handlerFlagNeedInterService))
	smux.HandleFunc("/hasactivedirectory", x.makeHandler(HttpMethodGet, httpHandlerHasActiveDirectory, 0))
	smux.HandleFunc("/groups_perm_names", x.makeHandler(HttpMethodGet, httpHandlerGetGroupsPermNames, handlerFlagNeedAdminRights))
	smux.HandleFunc("/dynamic_permissions", x.makeHandler(HttpMethodGet, httpHandlerGetDynamicPermissions, 0))
	smux.HandleFunc("/oauth/providers", x.makeHandler(HttpMethodGet, httpHandlerOAuthProviders, 0))
	smux.HandleFunc("/oauth/start", x.makeHandler(HttpMethodAny, httpHandlerOAuthStart, 0))
	smux.HandleFunc("/oauth/finish", x.makeHandler(HttpMethodGet, httpHandlerOAuthFinish, 0))

	// It's useful to uncomment this when developing new OAuth concepts,
	// but it's obviously a bad idea to expose it in production.
	// smux.HandleFunc("/oauth/test", x.makeHandler(HttpMethodGet, httpHandlerOAuthTest, 0))

	server := &http.Server{}
	server.Handler = smux
	server.Addr = x.Config.Authaus.HTTP.Bind + ":" + x.Config.Authaus.HTTP.Port

	x.Central.Log.Infof("ImqsAuth is trying to listen on %v:%v", x.Config.Authaus.HTTP.Bind, x.Config.Authaus.HTTP.Port)

	if err := server.ListenAndServe(); err != nil {
		return err
	}

	return nil
}

// Returns an error if 'hostname' is not configured on this server
// Why don't we just use the "host" header of the HTTP request? Basically, it's unreliable,
// especially when our server sits behind a proxy that we don't control.
func (x *ImqsCentral) makeAbsoluteUrl(relativeUrl string) (string, error) {
	hostname := x.Config.GetHostname()
	if hostname == "" {
		return "", fmt.Errorf("Environment variable 'IMQS_HOSTNAME_URL' is not set on this server")
	}

	absolute := ""
	if strings.Index(hostname, "http:") == 0 || strings.Index(hostname, "https:") == 0 {
		absolute = hostname
	} else {
		absolute = "https://" + hostname
	}

	if absolute[len(absolute)-1] != '/' && relativeUrl[0] != '/' {
		absolute += "/"
	}

	absolute += relativeUrl
	return absolute, nil
}

// Returns (responseCode, message)
func (x *ImqsCentral) ResetPasswordStart(userId authaus.UserId, isNewAccount bool) (int, string) {
	if x.Config.SendMailPassword == "" {
		return http.StatusInternalServerError, "No password for sending email"
	}

	expireSeconds := x.Config.PasswordResetExpirySeconds
	if isNewAccount {
		expireSeconds = x.Config.NewAccountExpirySeconds
	}

	// We need to see what type of user this is, as we cannot reset the password of an LDAP user
	user, err := x.Central.GetUserFromUserId(userId)
	if err != nil {
		return http.StatusBadRequest, "Error retrieving auth user type: " + err.Error()
	}

	var mailQuery string
	var mailBody string
	if user.Type.CanSetPassword() {
		token, err := x.Central.ResetPasswordStart(userId, time.Now().Add(time.Duration(expireSeconds)*time.Second))
		if err != nil {
			return http.StatusForbidden, "Error resetting password: " + err.Error()
		}

		mailQuery, err = x.createDefaultMailQuery(user, token, isNewAccount, expireSeconds)
		if err != nil {
			return http.StatusServiceUnavailable, "Error constructing reset URL: " + err.Error()
		}
	} else if user.Type == authaus.UserTypeLDAP {
		mailQuery, mailBody = x.createLDAPMailQueryAndBody(user)
	}

	code, strErr := x.buildMailRequestAndSend(mailQuery, mailBody)
	if strErr != "" {
		return code, fmt.Sprintf("Error sending email: %v", strErr)
	}
	return code, ""
}

func (x *ImqsCentral) createDefaultMailQuery(user authaus.AuthUser, token string, isNewAccount bool, expireSeconds float64) (string, error) {
	strUserId := strconv.FormatInt(int64(user.UserId), 10)
	resetUrl, err := x.makeAbsoluteUrl("/#resetpassword=true&identity=" + url.QueryEscape(user.Email) + "&userid=" + url.QueryEscape(strUserId) + "&token=" + url.QueryEscape(token))
	if err != nil {
		return "", fmt.Errorf("Failed to build absolute URL for password reset link in email: %v", err)
	}
	if isNewAccount {
		resetUrl += "&welcome=true"
	}

	mailQuery := "passwordReset?"
	mailQuery += fmt.Sprintf("email=%v&resetUrl=%v&expireTime=%.0f", url.QueryEscape(user.Email), url.QueryEscape(resetUrl), expireSeconds)

	var params *MailParameters
	if isNewAccount {
		mailQuery += "&newAccount=true"

		if x.Config.SendMailDetails.NewAccount != nil {
			params = x.Config.SendMailDetails.NewAccount
		}
	} else {
		mailQuery += "&newAccount=false"

		if x.Config.SendMailDetails.PasswordReset != nil {
			params = x.Config.SendMailDetails.PasswordReset
		}
	}

	if params != nil {
		if params.TemplateName != nil {
			mailQuery += "&templateName=" + url.QueryEscape(*params.TemplateName)
		}

		if params.From != nil {
			mailQuery += "&from=" + url.QueryEscape(*params.From)
		}
	}

	return mailQuery, nil
}

func (x *ImqsCentral) createLDAPMailQueryAndBody(user authaus.AuthUser) (string, string) {
	var mailQuery string
	var mailBody string

	mailQuery += "sendEmail?"
	mailQuery += fmt.Sprintf("emailTo=%v&ishtml=True", url.QueryEscape(user.Email))

	subject := "IMQS Reset Password"

	// Handle optional overrides
	if x.Config.SendMailDetails.LDAPPasswordReset != nil {
		params := x.Config.SendMailDetails.LDAPPasswordReset

		if params.Subject != nil {
			subject = *params.Subject
		}

		if params.From != nil {
			mailQuery += "&from=" + url.QueryEscape(*params.From)
		}
	}

	mailQuery += "&subject=" + url.QueryEscape(subject)

	if len(x.Config.Authaus.LDAP.SysAdminEmail) > 0 {
		mailBody += fmt.Sprintf("This is an automated response.<br><br>To reset your password, please contact your System Administrator (%v).", x.Config.Authaus.LDAP.SysAdminEmail)
	} else {
		mailBody += "This is an automated response.<br><br>To reset your password, please contact your System Administrator."
	}

	return mailQuery, mailBody
}

func (x *ImqsCentral) buildMailRequestAndSend(mailQuery string, mailBody string) (int, string) {
	var sendMailReq *http.Request
	var err error

	if x.Config.SendMailDetails.URL == nil {
		return http.StatusInternalServerError, "Mail URL not specified"
	}

	if len(mailBody) > 0 {
		sendMailReq, err = http.NewRequest("POST", *x.Config.SendMailDetails.URL+"/"+mailQuery, strings.NewReader(mailBody))
	} else {
		sendMailReq, err = http.NewRequest("POST", *x.Config.SendMailDetails.URL+"/"+mailQuery, nil)
	}
	if err != nil {
		return http.StatusServiceUnavailable, err.Error()
	}
	sendMailReq.SetBasicAuth("imqs", x.Config.SendMailPassword)

	mailResp, err := http.DefaultClient.Do(sendMailReq)
	if err != nil {
		return http.StatusServiceUnavailable, err.Error()
	}
	defer mailResp.Body.Close()
	respBody, _ := ioutil.ReadAll(mailResp.Body)
	if mailResp.StatusCode != http.StatusOK {
		return http.StatusServiceUnavailable, mailResp.Status + "\n" + string(respBody)
	}

	return http.StatusOK, ""
}

func httpSendJson(w http.ResponseWriter, jsonObj interface{}) {
	jsonStr, jsonErr := json.Marshal(jsonObj)
	if jsonErr == nil {
		httpSendResponse(w, jsonStr)
	} else {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, jsonErr.Error())
	}
}

func httpSendResponse(w http.ResponseWriter, jsonStr []byte) {
	w.Header().Add("Content-Type", "application/json")
	w.Header().Add("Cache-Control", "no-cache, no-store, must revalidate")
	w.Header().Add("Pragma", "no-cache")
	w.Header().Add("Expires", "0")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonStr)
}

func httpSendCheckJson(w http.ResponseWriter, token *authaus.Token, permList authaus.PermissionList) {
	jresponse := &checkResponseJson{}
	jresponse.Identity = token.Identity
	jresponse.UserId = token.UserId
	jresponse.Username = token.Username
	jresponse.Email = token.Email
	jresponse.SetRoles(permList)
	jresponse.InternalUUID = token.InternalUUID
	httpSendJson(w, jresponse)
	//fmt.Fprintf(w, "%v", encodePermBitsToString(permList))
	//fmt.Fprintf(w, "%v", hex.EncodeToString(token.Permit.Roles))
}

func httpSendGroupsJson(w http.ResponseWriter, groups []*authaus.AuthGroup) {
	jresponse := make([]*groupResponseJson, len(groups))
	for i, group := range groups {
		jresponse[i] = &groupResponseJson{}
		jresponse[i].SetGroup(group)
	}
	httpSendJson(w, jresponse)
}

func httpSendPermitsJson(central *ImqsCentral, users []authaus.AuthUser, ident2perm map[authaus.UserId]*authaus.Permit, w http.ResponseWriter) {
	jresponse, err := getPermitsJSON(central, users, ident2perm)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpSendJson(w, jresponse)
}

func getPermitsJSON(central *ImqsCentral, users []authaus.AuthUser, ident2perm map[authaus.UserId]*authaus.Permit) ([]*groupsResponseJson, error) {
	emptyPermit := authaus.Permit{}

	groupCache := map[authaus.GroupIDU32]string{}
	jresponse := make([]*groupsResponseJson, 0)
	for _, user := range users {
		var validUser groupsResponseJson
		permit := ident2perm[user.UserId]
		if permit == nil {
			permit = &emptyPermit
		}
		groups, err := authaus.DecodePermit(permit.Roles)
		if err != nil {
			return nil, fmt.Errorf("Could not decode permit: %v", err)
		}
		validUser.UserName = user.Username
		validUser.Email = user.Email
		validUser.Name = user.Firstname
		validUser.Surname = user.Lastname
		validUser.Groups, err = authaus.GroupIDsToNames(groups, central.Central.GetRoleGroupDB(), groupCache)
		if err != nil && validUser.Groups == nil {
			err2 := fmt.Errorf("error fetching group names for user %v : %v", user.UserId, err)
			return nil, err2
		} else if err != nil {
			central.Central.Log.Warnf("issue fetching group names for user %v : %v", user.UserId, err)
		}
		jresponse = append(jresponse, &validUser)
	}

	return jresponse, nil
}

func getUserObjectJSON(central *ImqsCentral, user authaus.AuthUser, permit *authaus.Permit) (*serviceauth.UserObject, error) {
	emptyPermit := authaus.Permit{}

	if permit == nil {
		permit = &emptyPermit
	}

	groups, err := authaus.DecodePermit(permit.Roles)
	if err != nil {
		return nil, err
	}
	groupCache := map[authaus.GroupIDU32]string{}
	groupnames, err := authaus.GroupIDsToNames(groups, central.Central.GetRoleGroupDB(), groupCache)
	if err != nil && groupnames == nil {
		e := fmt.Errorf("error fetching group names for user %v : %v", user.UserId, err)
		return nil, e
	} else if err != nil {
		central.Central.Log.Warnf("issue fetching group names for user %v : %v", user.UserId, err)
	}

	jresponse := &serviceauth.UserObject{
		Email:         user.Email,
		UserId:        int64(user.UserId),
		Username:      user.Username,
		Name:          user.Firstname,
		Surname:       user.Lastname,
		Mobile:        user.Mobilenumber,
		Telephone:     user.Telephonenumber,
		Remarks:       user.Remarks,
		Created:       user.Created,
		CreatedBy:     central.Central.GetUserNameFromUserId(user.CreatedBy),
		Modified:      user.Modified,
		ModifiedBy:    central.Central.GetUserNameFromUserId(user.ModifiedBy),
		Groups:        groupnames,
		AuthUserType:  int(user.Type),
		Archived:      user.Archived,
		AccountLocked: user.AccountLocked,
		InternalUUID:  user.InternalUUID,
	}

	return jresponse, nil
}

// getUserObjectsJSON is specifically used for large list of users
// due to its caching capabilities
func getUserObjectsJSON(central *ImqsCentral, users []authaus.AuthUser, ident2perm map[authaus.UserId]*authaus.Permit) ([]*serviceauth.UserObject, error) {
	emptyPermit := authaus.Permit{}

	groupCache := map[authaus.GroupIDU32]string{}
	jresponse := make([]*serviceauth.UserObject, 0)

	//'users' is an array of AuthUser, which already contains the name and surname of the user
	// we can re-map it to serve as a lookup later in the jresponse code
	// The only caveat is that we need the special system user names
	// This should move to authaus, see caching mechanism implemented for group name mapping in authaus commit
	// 		65f544ed Ben Harper <rogojin@gmail.com> on 2021/07/27 at 9:54 PM

	// Build username lookup for modifiedby and createdby
	usernamemap := make(map[authaus.UserId]string)
	for _, user := range users {
		usernamemap[user.UserId] = user.Firstname + " " + user.Lastname
	}

	usernamemap[authaus.UserIdAdministrator] = "Administrator"
	usernamemap[authaus.UserIdLDAPMerge] = "LDAP Merge"
	usernamemap[authaus.UserIdOAuthImplicitCreate] = "OAuth Sign-in"
	usernamemap[authaus.UserIdMSAADMerge] = "MSAAD Merge"
	userStats, err := central.Central.GetUserStatsAll()
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		permit := ident2perm[user.UserId]
		if permit == nil || user.Archived { // Do not include permits of archived users
			permit = &emptyPermit
		}
		groups, err := authaus.DecodePermit(permit.Roles)
		if err != nil {
			return nil, err
		}
		groupnames, err := authaus.GroupIDsToNames(groups, central.Central.GetRoleGroupDB(), groupCache)
		if err != nil && groupnames == nil {
			e := fmt.Errorf("error fetching group names for user %v : %v", user.UserId, err)
			return nil, e
		} else if err != nil {
			central.Central.Log.Warnf("issue fetching group names for user %v : %v", user.UserId, err)
		}

		userStat, _ := userStats[user.UserId]

		jresponse = append(jresponse, &serviceauth.UserObject{
			Email:         user.Email,
			UserId:        int64(user.UserId),
			Username:      user.Username,
			Name:          user.Firstname,
			Surname:       user.Lastname,
			Mobile:        user.Mobilenumber,
			Telephone:     user.Telephonenumber,
			Remarks:       user.Remarks,
			Created:       user.Created,
			CreatedBy:     usernamemap[user.CreatedBy],
			Modified:      user.Modified,
			ModifiedBy:    usernamemap[user.ModifiedBy],
			Groups:        groupnames,
			AuthUserType:  int(user.Type),
			Archived:      user.Archived,
			AccountLocked: user.AccountLocked,
			InternalUUID:  user.InternalUUID,
			LastLogin:     userStat.LastLoginDate.Time,
			EnabledDate:   userStat.EnabledDate.Time,
			DisabledDate:  userStat.DisabledDate.Time,
		})
	}

	return jresponse, nil
}

// To filter users with withPerm permission,
func filterUserObjectsByPermission(users []*serviceauth.UserObject, central *ImqsCentral, ident2perm map[authaus.UserId]*authaus.Permit, perm authaus.PermissionU16) ([]*serviceauth.UserObject, error) {
	emptyPermit := authaus.Permit{}
	jFiltered := make([]*serviceauth.UserObject, 0)

	if perm == 0 {
		return append(jFiltered, users...), nil
	}

	// get groups with 'perm' permission
	var authGroupsWithPerm []authaus.GroupIDU32
	authGroups, err := central.Central.GetRoleGroupDB().GetGroups()
	if err != nil {
		return nil, err
	}
	for _, g := range authGroups {
		if g.HasPerm(perm) {
			authGroupsWithPerm = append(authGroupsWithPerm, g.ID)
		}
	}

	for _, user := range users {
		permit := ident2perm[authaus.UserId(user.UserId)]
		if permit == nil { // here we INCLUDE permits for archived users
			permit = &emptyPermit
		}
		groups, err := authaus.DecodePermit(permit.Roles)
		if err != nil {
			return nil, err
		}

		include := false
		for _, g := range groups {
			include = containsElement(authGroupsWithPerm, g)
			if include {
				break
			}
		}
		if !include {
			continue // user doesn't have the specified permission
		}

		jFiltered = append(jFiltered, user)
	}

	return jFiltered, nil
}

func httpSendAccountDisabled(w http.ResponseWriter) {
	authaus.HttpSendTxt(w, http.StatusForbidden, msgAccountDisabled)
}

func httpSendNoIdentity(w http.ResponseWriter) {
	authaus.HttpSendTxt(w, http.StatusUnauthorized, authaus.ErrIdentityEmpty.Error())
}

func httpHandlerLogout(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	identity := ""
	if token, err := authaus.HttpHandlerPrelude(&central.Config.Authaus.HTTP, central.Central, r.http); err == nil {
		identity = token.Identity
	}

	// Try to erase the session cookie regardless of whether we could locate a valid token.
	sessioncookie, _ := r.http.Cookie(central.Config.Authaus.HTTP.CookieName)
	if sessioncookie != nil {
		central.Central.Logout(sessioncookie.Value)
	}

	if identity == "" {
		httpSendNoIdentity(w)
		return
	}

	authaus.HttpSendTxt(w, http.StatusOK, "")
}

// Handle the 'login' request, sending back a session token (via Set-Cookie),
// Headers may contain additional login details pertaining to pass-through, which
// Auth will try and authenticate against msaad if normal login fails (session may be invalid)
func httpHandlerLogin(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	identity, password, basicOK := r.http.BasicAuth()
	if !basicOK {
		authaus.HttpSendTxt(w, http.StatusBadRequest, authaus.ErrHttpBasicAuth.Error())
		return
	}

	if identity == "" {
		httpSendNoIdentity(w)
		return
	}

	loginType, err := getLoginType(r)
	central.Central.Log.Infof("loginType: %+v", loginType)
	if err != nil {
		central.Central.Log.Warn(err.Error())
		authaus.HttpSendTxt(w, http.StatusBadRequest, err.Error())
		return
	}

	// both client_id and login_type are either set or blank/not present
	var sessionKey string
	var token *authaus.Token
	if loginType.LoginType == "" {
		central.Central.Log.Info("Normal IMQS login...")
		sessionKey, token, err = central.Central.Login(identity, password, getIPAddress(r.http))
		if err != nil {
			user, eUser := central.Central.GetUserFromIdentity(identity)
			authaus.HttpSendTxt(w, http.StatusUnauthorized, err.Error())
			if eUser == nil {
				auditUserLogAction(central, r, user.UserId, identity, "User Profile: "+identity, authaus.AuditActionFailedLogin)
			}
			return
		}
	} else {
		central.Central.Log.Info("MSAAD passthrough login...")
		user, eUser := central.Central.GetUserFromIdentity(identity)
		if eUser != nil {
			// User does not exist (not synchronized from e.g. msaad)
			// We specifically log this, since want to know who is trying to use this trusted login incorrectly.
			central.Central.Log.Warnf("MSAAD passthrough for %s failed, user does not exist.", identity)
			authaus.HttpSendTxt(w, http.StatusUnauthorized, authaus.ErrIdentityAuthNotFound.Error())
			return
		}

		code, err, key := msaadLogin(central, r, identity, user, password)
		if err != nil {
			authaus.HttpSendTxt(w, code, err.Error())
			auditUserLogAction(central, r, user.UserId, identity, "User Profile: "+identity, authaus.AuditActionFailedLogin)
			return
		}

		// we create a new Auth session here, because we need it for the OAuth session link
		sessionKey, token, err = central.Central.CreateSession(&user, r.http.RemoteAddr, key)
		if err != nil {
			authaus.HttpSendTxt(w, http.StatusForbidden, err.Error())
			return
		}
		central.Central.Log.Info("MSAAD Passthrough user successfully logged in.\n")
	}

	perms, err := central.validateUserIsEnabledForNewLogin(sessionKey, token, r)
	if err != nil {
		if errors.Is(err, ErrUserDisabled) {
			httpSendAccountDisabled(w)
		} else {
			central.Central.Log.Errorf("error validating if user is enabled : %v", err)
			authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	central.setSessionCookie(sessionKey, token, w)
	httpSendCheckJson(w, token, perms)
}

// getLoginType
// This function determines the type of login requested based on the form fields populated.
// If none are present, assume normal (IMQS) login.
// Required form fields if msaad: client_id, login_type
func getLoginType(r *httpRequest) (ltype *LoginType, err error) {
	err = r.http.ParseForm()
	if err != nil {
		return nil, err
	}
	l1 := &LoginType{}
	l1.LoginType = r.http.Form.Get("login_type")
	l1.ClientId = r.http.Form.Get("client_id")

	if (l1.LoginType == "" && l1.ClientId == "") || (l1.LoginType != "" && l1.ClientId != "") {
		return l1, nil
	}
	return nil, fmt.Errorf("Malformed login form data.")
}

// Perform checks and log user into MSAAD.
// Only client (app) id's white-listed in the config can utilize this method of login.
// Returns an http code and/or error as appropriate.
func msaadLogin(central *ImqsCentral, r *httpRequest, identity string, user authaus.AuthUser, password string) (httpCode int, err error, key string) {
	whiteListed := false

	// validate against whitelist
	clientId := r.http.Form.Get("client_id")
	for _, cid := range central.Config.Authaus.MSAAD.PassthroughClientIDs {
		if clientId == cid {
			whiteListed = true
			break
		}
	}

	if !whiteListed {
		whiteListFailedMsg := fmt.Sprintf("Passthrough auth: client_id specified [%v] is not whitelisted. \n", clientId)
		central.Central.Log.Warn(whiteListFailedMsg)
		return http.StatusForbidden, fmt.Errorf(whiteListFailedMsg), ""
	}

	if user.Type != authaus.UserTypeMSAAD {
		notMSAADUserMsg := "Not an MSAAD user."
		central.Central.Log.Warn(notMSAADUserMsg)
		return http.StatusUnauthorized, fmt.Errorf(notMSAADUserMsg), ""
	}

	// MSAAD call
	e2, key := central.Central.OAuth.OAuthLoginUsernamePassword(identity, password)
	if e2 != nil {
		central.Central.Log.Warn("Login call to MSAAD failed")
		return http.StatusUnauthorized, e2, ""
	}

	return http.StatusOK, nil, key
}

// Note that we do not create a permit here for the user, so he will not yet be able to login.
// In order to finish the job, you will need to call httpHandlerSetUserGroups which will
// create a permit for this user.
func httpHandlerCreateUser(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	email := strings.TrimSpace(r.http.URL.Query().Get("email"))
	username := strings.TrimSpace(r.http.URL.Query().Get("username"))
	firstname := strings.TrimSpace(r.http.URL.Query().Get("firstname"))
	lastname := strings.TrimSpace(r.http.URL.Query().Get("lastname"))
	mobilenumber := strings.TrimSpace(r.http.URL.Query().Get("mobilenumber"))
	telephonenumber := strings.TrimSpace(r.http.URL.Query().Get("telephonenumber"))
	remarks := strings.TrimSpace(r.http.URL.Query().Get("remarks"))
	password := strings.TrimSpace(r.http.URL.Query().Get("password"))
	internalUUID := strings.TrimSpace(r.http.URL.Query().Get("uuid"))

	var identity string
	if len(username) > 0 {
		identity = username
	} else {
		identity = email
	}

	sendPasswordResetEmail := false

	if password == "" {
		// Create a random password for the user.
		// We will use the password reset mechanism to allow the user to pick his own password.
		sendPasswordResetEmail = true
		password = authaus.RandomString(20, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	}

	// Get the userId of the logged-in user
	var createdby authaus.UserId
	if r.token != nil {
		createdby = r.token.UserId
	}
	created := time.Now().UTC()
	user := authaus.AuthUser{
		Email:           email,
		Username:        username,
		Firstname:       firstname,
		Lastname:        lastname,
		Mobilenumber:    mobilenumber,
		Telephonenumber: telephonenumber,
		Remarks:         remarks,
		Created:         created,
		CreatedBy:       createdby,
		Modified:        created,
		ModifiedBy:      createdby,
		InternalUUID:    internalUUID,
	}

	if userId, err := central.Central.CreateUserStoreIdentity(&user, password); err != nil {
		authaus.HttpSendTxt(w, http.StatusForbidden, err.Error())
	} else {
		auditUserLogAction(central, r, user.UserId, user.Username, "User Profile: "+user.Username, authaus.AuditActionCreated)
		if sendPasswordResetEmail {
			code, msg := central.ResetPasswordStart(userId, true)
			if code != http.StatusOK {
				authaus.HttpSendTxt(w, http.StatusOK, fmt.Sprintf("Created identity '%v'. However, failed to initiate password reset: %v\n", identity, msg))
				return
			}
		}
		authaus.HttpSendTxt(w, http.StatusOK, fmt.Sprintf("Created identity '%v'", identity))
		/* // This has been moved to Login
		if yfErr := central.Yellowfin.CreateUser(identity); yfErr != nil {
			central.Central.Log.Printf("Error creating Yellowfin user '%v': %v", identity, yfErr)
		}
		*/
	}
}

func httpHandlerUpdateUser(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	email := strings.TrimSpace(r.http.URL.Query().Get("email"))
	username := strings.TrimSpace(r.http.URL.Query().Get("username"))
	firstname := strings.TrimSpace(r.http.URL.Query().Get("firstname"))
	lastname := strings.TrimSpace(r.http.URL.Query().Get("lastname"))
	mobilenumber := strings.TrimSpace(r.http.URL.Query().Get("mobilenumber"))
	telephonenumber := strings.TrimSpace(r.http.URL.Query().Get("telephonenumber"))
	remarks := strings.TrimSpace(r.http.URL.Query().Get("remarks"))
	strAuthusertype := strings.TrimSpace(r.http.URL.Query().Get("authusertype"))
	authUserType, err := parseAuthUserTypeString(strAuthusertype)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusBadRequest, fmt.Sprintf("Invalid AuthUserType: '%v'", strAuthusertype))
		return
	}

	userId, err := getUserId(r)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusBadRequest, err.Error())
		return
	}

	oldUser, e := central.Central.GetUserFromUserId(userId)
	if e != nil {
		central.Central.Log.Errorf("Error fetching user for comparison: %v", e)
		authaus.HttpSendTxt(w, http.StatusBadRequest, err.Error())
		return
	}

	// Get the userId of the logged-in user
	modifiedby := r.token.UserId
	modified := time.Now().UTC()
	user := authaus.AuthUser{
		UserId:          authaus.UserId(userId),
		Email:           email,
		Username:        username,
		Firstname:       firstname,
		Lastname:        lastname,
		Mobilenumber:    mobilenumber,
		Telephonenumber: telephonenumber,
		Remarks:         remarks,
		Modified:        modified,
		ModifiedBy:      modifiedby,
		Type:            authUserType,
	}

	if err := central.Central.UpdateIdentity(&user); err != nil {
		authaus.HttpSendTxt(w, http.StatusForbidden, err.Error())
	} else {
		// patch up missing fields
		user.InternalUUID = oldUser.InternalUUID
		userChanges, e := authaus.UserInfoDiff(oldUser, user)
		if e != nil {
			central.Central.Log.Warnf("IMQS user merge: Could not diff user %v (%v)", user.UserId, e)
			userChanges = "<error comparing> New values: " + authaus.UserInfoToJSON(user)
		}
		logMessage := authaus.UserDiffLogMessage(userChanges, user)
		auditUserLogAction(central, r, user.UserId, user.Username, logMessage, authaus.AuditActionUpdated)
		authaus.HttpSendTxt(w, http.StatusOK, fmt.Sprintf("Updated user: '%v'", userId))
	}
}

func httpHandlerUnlockUser(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	username := strings.TrimSpace(r.http.URL.Query().Get("username"))

	// Get the userId of the locked out user
	userId, err := getUserId(r)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusBadRequest, err.Error())
		return
	}

	user := authaus.AuthUser{
		UserId:   authaus.UserId(userId),
		Username: username,
	}

	x := central.Central

	if err := x.UnlockAccount(userId); err != nil {
		authaus.HttpSendTxt(w, http.StatusForbidden, err.Error())
	} else {
		auditUserLogAction(central, r, user.UserId, user.Username, "User Profile: "+user.Username, authaus.AuditActionUnlocked)
		authaus.HttpSendTxt(w, http.StatusOK, fmt.Sprintf("Unlocked user: '%v'", userId))
	}
}

func parseAuthUserTypeString(authUserTypeString string) (authaus.AuthUserType, error) {
	switch authUserTypeString {
	case "DEFAULT":
		return authaus.UserTypeDefault, nil
	case "LDAP":
		return authaus.UserTypeLDAP, nil
	default:
		return authaus.UserTypeDefault, errors.New("Invalid AuthUserType")
	}
}

func httpHandlerArchiveUser(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	var err error
	var userId authaus.UserId
	var user authaus.AuthUser

	userId, err = getUserId(r)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusForbidden, err.Error())
		return
	}

	if user, err = central.Central.GetUserFromUserId(authaus.UserId(userId)); err != nil {
		authaus.HttpSendTxt(w, http.StatusForbidden, err.Error())
		return
	}

	if err := central.Central.ArchiveIdentity(authaus.UserId(userId)); err != nil {
		authaus.HttpSendTxt(w, http.StatusForbidden, err.Error())
		return
	}
	auditUserLogAction(central, r, user.UserId, user.Username, "User Profile: "+user.Username, authaus.AuditActionDeleted)
	authaus.HttpSendTxt(w, http.StatusOK, fmt.Sprintf("Archived user: '%v'", userId))
}

func httpHandlerDeleteGroup(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	groupname := strings.TrimSpace(r.http.URL.Query().Get("groupname"))
	if groupname == "" {
		authaus.HttpSendTxt(w, http.StatusNotAcceptable, "Group name may not be blank.")
		return
	}
	// Guard against accidentally deleting the admin or enabled groups
	if groupname == RoleGroupAdmin || groupname == RoleGroupEnabled {
		authaus.HttpSendTxt(w, http.StatusMethodNotAllowed, fmt.Sprintf("Deleting group %v is not permitted", groupname))
		return
	}

	// Remove group from all users before deleting
	users, err := central.Central.GetAuthenticatorIdentities(authaus.GetIdentitiesFlagNone)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		return
	}

	for _, user := range users {
		perm, eGetPermit := central.Central.GetPermit(user.UserId)
		if eGetPermit != nil && strings.Index(eGetPermit.Error(), authaus.ErrIdentityPermitNotFound.Error()) == 0 {
			continue // Leave user untouched and continue to next user
		} else if eGetPermit != nil {
			authaus.HttpSendTxt(w, http.StatusInternalServerError, eGetPermit.Error())
			return
		}

		if group, eGetGroup := central.Central.GetRoleGroupDB().GetByName(groupname); eGetGroup == nil {
			groupsChanged := false
			if groups, eDecode := authaus.DecodePermit(perm.Roles); eDecode == nil {
				for i, gid := range groups {
					if gid == group.ID {
						groupsChanged = true
						groups = append(groups[0:i], groups[i+1:]...)
						continue
					}
				}
				if groupsChanged {
					perm.Roles = authaus.EncodePermit(groups)
					if eSet := central.Central.SetPermit(user.UserId, perm); eSet != nil {
						authaus.HttpSendTxt(w, http.StatusInternalServerError, eSet.Error())
						return
					}
				}
			}
		}
	}

	if err := authaus.DeleteGroup(central.Central.GetRoleGroupDB(), groupname); err != nil {
		central.Central.Log.Warnf("Error deleting group (%v): %v", groupname, err)
		authaus.HttpSendTxt(w, http.StatusBadRequest, fmt.Sprintf("Error deleting group (%v): %v", groupname, err))
		return
	}

	if r.token != nil {
		if user, err := central.Central.GetUserFromUserId(authaus.UserId(r.token.UserId)); err == nil {
			auditUserLogAction(central, r, user.UserId, user.Username, "Group: "+groupname+" deleted", authaus.AuditActionDeleted)
		}
	}

	central.Central.Log.Infof("Group deleted: %v", groupname)
	authaus.HttpSendTxt(w, http.StatusOK, "")
}

func httpHandlerCreateGroup(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	groupname := strings.TrimSpace(r.http.URL.Query().Get("groupname"))
	if groupname == "" {
		authaus.HttpSendTxt(w, http.StatusNotAcceptable, "Group name may not be blank.")
		return
	}

	if _, err := authaus.LoadOrCreateGroup(central.Central.GetRoleGroupDB(), groupname, true); err != nil {
		central.Central.Log.Warnf("Error creating group (%v): %v", groupname, err)
		authaus.HttpSendTxt(w, http.StatusBadRequest, fmt.Sprintf("Error creating group (%v): %v", groupname, err))
		return
	}

	if r.token != nil {
		if user, err := central.Central.GetUserFromUserId(authaus.UserId(r.token.UserId)); err == nil {
			auditUserLogAction(central, r, user.UserId, user.Username, "Group: "+groupname+" created", authaus.AuditActionCreated)
		}
	}

	central.Central.Log.Infof("New group added: %v", groupname)
	authaus.HttpSendTxt(w, http.StatusOK, "")
}

func httpHandlerUpdateGroup(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	groupName := strings.TrimSpace(r.http.URL.Query().Get("name"))
	newName := strings.TrimSpace(r.http.URL.Query().Get("newname"))

	if newName == "" {
		authaus.HttpSendTxt(w, http.StatusNotAcceptable, "Group name may not be blank.")
		return
	}

	roleDb := central.Central.GetRoleGroupDB()

	existingGroup, err := roleDb.GetByName(groupName)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusBadRequest, err.Error())
		return
	}

	newGroup := existingGroup.Clone()
	newGroup.Name = newName
	if err = roleDb.UpdateGroup(newGroup); err != nil {
		authaus.HttpSendTxt(w, http.StatusBadRequest, err.Error())
		return
	}

	if r.token != nil {
		if user, err := central.Central.GetUserFromUserId(authaus.UserId(r.token.UserId)); err == nil {
			auditUserLogAction(central, r, user.UserId, user.Username, "Group: "+newName+" updated", authaus.AuditActionUpdated)
		}
	}

	central.Central.Log.Infof("Group %v updated", newName)
	authaus.HttpSendTxt(w, http.StatusOK, "")
}

func pcsRenameUser(hostname, oldIdent, newIdent string) error {
	servicenames, ioerr := ioutil.ReadFile("c:/imqsbin/conf/service-names.txt")
	if ioerr != nil {
		return fmt.Errorf("Unable to read c:/imqsbin/conf/service-names.txt: %v", ioerr)
	}

	if !strings.Contains(string(servicenames), "imqs-pcs-webservice") {
		return nil
	}

	if hostname == "" {
		return fmt.Errorf("'hostname' not configured")
	}

	r, err := http.NewRequest("PUT", hostname+"/pcs/changeUsername?fromName="+url.QueryEscape(oldIdent)+"&toName="+url.QueryEscape(newIdent), nil)
	if err != nil {
		return err
	}

	r.Header.Add("Date", time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))

	if err = serviceauth.CreateInterServiceRequest(r, nil); err != nil {
		return err
	}

	response, err := http.DefaultClient.Do(r)
	if err != nil {
		return err
	}
	if response.Body != nil {
		defer response.Body.Close()
	}

	if response.StatusCode != 200 {
		body, _ := ioutil.ReadAll(response.Body)
		return errors.New("PCS rename: " + strconv.Itoa(response.StatusCode) + "; body: " + string(body))
	}
	return nil
}

// TODO RenameIdentity was deprecated in May 2016, replaced by UpdateIdentity. We need to remove this endpoint and handler once PCS team has made the necessary updates
func httpHandlerRenameUser(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	oldIdent := authaus.CanonicalizeIdentity(strings.TrimSpace(r.http.URL.Query().Get("old")))
	newIdent := authaus.CanonicalizeIdentity(strings.TrimSpace(r.http.URL.Query().Get("new")))
	user, getUserIdErr := central.Central.GetUserFromIdentity(oldIdent)
	if getUserIdErr != nil {
		authaus.HttpSendTxt(w, http.StatusBadRequest, "Identity '"+oldIdent+"'' not found")
		return
	}
	if oldIdent == "" {
		authaus.HttpSendTxt(w, http.StatusBadRequest, "No 'old' identity given")
		return
	}
	if newIdent == "" {
		authaus.HttpSendTxt(w, http.StatusBadRequest, "No 'new' identity given")
		return
	}

	if !r.permList.Has(PermAdmin) {
		token, err := authaus.HttpHandlerBasicAuth(central.Central, r.http)
		authMsg := "'rename_user' must be accompanied by HTTP BASIC authentication of the user that is being renamed (this confirms that you know your own password). " +
			"Alternatively, if you have admin rights, you can rename any user."
		if err != nil {
			authaus.HttpSendTxt(w, http.StatusForbidden, authMsg+" Error: "+err.Error())
			return
		}
		if token.UserId != user.UserId {
			authaus.HttpSendTxt(w, http.StatusForbidden, authMsg+" Authenticated with '"+token.Identity+"', but tried to rename user '"+oldIdent+"'")
			return
		}
	}

	if err := central.Central.RenameIdentity(oldIdent, newIdent); err != nil {
		authaus.HttpSendTxt(w, http.StatusBadRequest, err.Error())
		return
	}

	auditUserLogAction(central, r, user.UserId, user.Username, "User Profile: "+oldIdent+" renamed to "+newIdent, authaus.AuditActionUpdated)
	if central.Config.enablePcsRename {
		if err := pcsRenameUser(central.Config.GetHostname(), oldIdent, newIdent); err != nil {
			central.Central.Log.Warnf("Error: failed to rename PCS: %v", err)
			rollbackErrorTxt := ""
			if err_rollback := central.Central.RenameIdentity(newIdent, oldIdent); err_rollback != nil {
				rollbackErrorTxt = "Rollback failed: " + err_rollback.Error()
				central.Central.Log.Warnf("Error: failed to roll back username rename: %v", err_rollback)
			}

			authaus.HttpSendTxt(w, http.StatusBadRequest, err.Error()+"\n"+rollbackErrorTxt)
			return
		}
	}

	authaus.HttpSendTxt(w, http.StatusOK, "Renamed '"+oldIdent+"' to '"+newIdent+"'")
}

// httpHandlerGetGroupsPermNames returns a JSON object containing a list of the permission name and ID
// for all of the permissions. This is used to know which ID is used in the permission list for the user
// when matched to the human readable permission names.
func httpHandlerGetGroupsPermNames(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	responseJSON, _ := json.Marshal(PermissionsTable)
	httpSendResponse(w, responseJSON)
}

func httpHandlerSetGroupRoles(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	//TODO : Add check so current user cannot remove own Admin rights
	groupname := strings.TrimSpace(r.http.URL.Query().Get("groupname"))
	rolesstring := strings.TrimSpace(r.http.URL.Query().Get("roles"))

	newPerms := authaus.PermissionList{}
	if len(rolesstring) > 0 {
		for _, pname := range strings.Split(rolesstring, ",") {
			perm, _ := strconv.ParseInt(pname, 10, 16)
			newPerms = append(newPerms, authaus.PermissionU16(perm))
		}
	}

	if group, e := authaus.LoadOrCreateGroup(central.Central.GetRoleGroupDB(), groupname, false); e == nil {
		// we have the stored group here as 'group', as well as
		central.Central.Log.Infof("Roles %v set for group %v", rolesstring, groupname)
		existingPerms := group.PermList

		removed := existingPerms.Diff(&newPerms)
		added := newPerms.Diff(&existingPerms)

		// Convert to real names
		changednames := "Added: "
		changednames += permListToText(central, added)
		changednames += " Removed: "
		changednames += permListToText(central, removed)

		description := ""
		//set the new perms
		group.PermList = newPerms
		if err := central.Central.GetRoleGroupDB().UpdateGroup(group); err == nil {
			central.Central.Log.Infof("Set group roles for %v", groupname)
			if r.token != nil {
				if user, err := central.Central.GetUserFromUserId(authaus.UserId(r.token.UserId)); err == nil {
					description = "Group: " + groupname + " roles updated: " + changednames
					auditUserLogAction(central, r, user.UserId, user.Username,
						description,
						authaus.AuditActionUpdated)
				}
			}
			authaus.HttpSendTxt(w, http.StatusOK, description)
		} else {
			central.Central.Log.Warnf("Could not set group roles for %v: %v", groupname, err)
			authaus.HttpSendTxt(w, http.StatusNotAcceptable, fmt.Sprintf("Could not set group roles for %v: %v", groupname, err))
			return
		}
	} else {
		central.Central.Log.Warnf("Group '%v' not found: %v", groupname, e)
		authaus.HttpSendTxt(w, http.StatusNotFound, fmt.Sprintf("Group '%v' not found: %v", groupname, e))
		return
	}

	broadcastGroupChange(central, r, groupname)
}

func permListToText(central *ImqsCentral, permList *authaus.PermissionList) string {
	s := ""
	if permList == nil {
		central.Central.Log.Warnf("permListToText: 'permList' is nil")
		return "<error>"
	}
	if len(*permList) > 0 {
		for _, e := range *permList {
			s += " " + PermissionsTable[e]
		}
	} else {
		return "<none>"
	}
	return strings.TrimSpace(s)
}

func broadcastGroupChange(central *ImqsCentral, r *httpRequest, groupname string) {
	users, err := central.Central.GetAuthenticatorIdentities(authaus.GetIdentitiesFlagNone)
	if err != nil {
		central.Central.Log.Warnf("Unable to broadcast change, unable to read identities: %v", err)
		return
	}

	// find group id of changed group
	groupnamelist := []string{groupname}
	changedGroupIds, _ := authaus.GroupNamesToIDs(groupnamelist, central.Central.GetRoleGroupDB())
	changedGroupId := changedGroupIds[0]

	// find all identities which belong to the group in question
	changedUserIds := []string{}
	for _, user := range users {
		if r.token != nil && r.token.UserId == user.UserId {
			// skip user that performed the request
			continue
		}
		// find all identity's group id's
		identityGroupIds := getIdentityGroupIDs(central, user.UserId)
		if containsElement(identityGroupIds, changedGroupId) {
			changedUserIds = append(changedUserIds, strconv.FormatInt(int64(user.UserId), 10))
		}
	}

	if len(changedUserIds) > 0 {
		central.broadcastToAllSubscribers(createGroupsChangedNotificationMessage(strings.Join(changedUserIds, " ")))
	}
}

func containsElement(list []authaus.GroupIDU32, elem authaus.GroupIDU32) bool {
	for _, s := range list {
		if s == elem {
			return true
		}
	}
	return false
}

func containsStr(list []string, str string) bool {
	for _, v := range list {
		if v == str {
			return true
		}
	}
	return false
}

func getIdentityGroupIDs(central *ImqsCentral, userId authaus.UserId) []authaus.GroupIDU32 {
	if perm, e := central.Central.GetPermit(userId); e == nil {
		if permGroups, eDecode := authaus.DecodePermit(perm.Roles); eDecode == nil {
			return permGroups
		} else {
			central.Central.Log.Warnf("(Http.getRolesList) Error decoding permit: %v\n", eDecode)
		}
	} else {
		central.Central.Log.Warnf("(Http.getRolesList) Error retrieving permit: %v\n", e)
	}
	return []authaus.GroupIDU32{}
}

func httpHandlerSetUserGroups(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	defer func() {
		if ex := recover(); ex != nil {
			str, isStr := ex.(string)
			if !isStr {
				str = fmt.Sprintf("%v", ex)
			}
			authaus.HttpSendTxt(w, http.StatusForbidden, str)
		}
	}()

	// Get userid
	userId, errGetUserID := getUserId(r)
	if errGetUserID != nil {
		panic(errGetUserID.Error())
	}
	groupsParam := strings.TrimSpace(r.http.URL.Query().Get("groups"))

	groups := strings.Split(groupsParam, ",")
	// strings.Split() will always yield at least 1 object, even if that's just an empty string
	// It is completely legal however, to assign zero groups to a user.
	if len(groups) == 1 && groups[0] == "" {
		groups = make([]string, 0)
	}
	groupIDs, errGroupIDs := authaus.GroupNamesToIDs(groups, central.Central.GetRoleGroupDB())
	if errGroupIDs != nil {
		panic("Invalid groups: " + errGroupIDs.Error())
	}

	// Determine the user's current groups before changing them

	var currentGroups []string

	// Retrieve the permit for the given user ID
	perm, err := central.Central.GetPermit(userId)
	if err != nil {
		if err != authaus.ErrIdentityPermitNotFound {
			panic("Error retrieving permit: " + err.Error())
		}
	} else {

		// Decode the roles from the permit
		permGroups, errDecode := authaus.DecodePermit(perm.Roles)
		if errDecode != nil {
			panic("Error decoding permit: " + errDecode.Error())
		}

		// Retrieve the group details for the decoded group IDs using authaus.GroupIDsToNames
		groupCache := map[authaus.GroupIDU32]string{}
		var errGroups error
		currentGroups, errGroups = authaus.GroupIDsToNames(permGroups, central.Central.GetRoleGroupDB(), groupCache)
		if errGroups != nil {
			panic("Error retrieving group names: " + errGroups.Error())
		}
	}

	// Determine the groups that are being added and removed
	groupsToAdd := utils.ComputeDifference(groups, currentGroups)    // In groups but not in currentGroups
	groupsToRemove := utils.ComputeDifference(currentGroups, groups) // In currentGroups but not in groups

	permit := &authaus.Permit{}
	permit.Roles = authaus.EncodePermit(groupIDs)
	if eSetPermit := central.Central.SetPermit(userId, permit); eSetPermit != nil {
		panic(eSetPermit)
	}

	if user, err := central.Central.GetUserFromUserId(authaus.UserId(userId)); err == nil {

		// If groupsToAdd contains 'enabled', then we need to log a special auditUserLogAction
		// Also remove 'enabled' from groupsToAdd so that it is not logged as a group added
		if containsStr(groupsToAdd, RoleGroupEnabled) {
			auditUserLogAction(central, r, user.UserId, user.Username, "User Profile: "+user.Username+" profile enabled", authaus.AuditActionEnabled)
			central.Central.SetUserStats(user.UserId, authaus.UserStatActionEnable)
			groupsToAdd = utils.RemoveStr(groupsToAdd, RoleGroupEnabled)
		}

		// If groupsToRemove contains 'enabled', then we need to log a special auditUserLogAction
		// Also remove 'enabled' from groupsToRemove so that it is not logged as a group removed
		if containsStr(groupsToRemove, RoleGroupEnabled) {
			auditUserLogAction(central, r, user.UserId, user.Username, "User Profile: "+user.Username+" profile disabled", authaus.AuditActionDisabled)
			central.Central.SetUserStats(user.UserId, authaus.UserStatActionDisable)
			groupsToRemove = utils.RemoveStr(groupsToRemove, RoleGroupEnabled)
		}

		// Only log if there are changes (i.e., either added or removed groups)
		if len(groupsToAdd) > 0 || len(groupsToRemove) > 0 {

			// Prepare the audit log message for groups added
			logMessage := "User Profile: " + user.Username + " roles changed."

			// Add the groups to the message if any groups were added
			if len(groupsToAdd) > 0 {
				logMessage += " Roles added: " + strings.Join(groupsToAdd, ",") + "."
			}

			// Add the groups to the message if any groups were removed
			if len(groupsToRemove) > 0 {
				logMessage += " Roles removed: " + strings.Join(groupsToRemove, ",") + "."
			}

			auditUserLogAction(central, r, user.UserId, user.Username, logMessage, authaus.AuditActionUpdated)
		}
	}

	summary := strings.Join(groups, ",")
	authaus.HttpSendTxt(w, http.StatusOK, fmt.Sprintf("'%v' groups set to (%v)", userId, summary))

	// Also update the modified user parameters when changing user permissions
	// Ignore permission denied errors for updating the modified parameters as
	// you can create permits for users that do not exist in the authentication system
	user, getIDerr := central.Central.GetUserFromUserId(userId)
	if getIDerr == nil {
		user.Modified = time.Now().UTC()
		user.ModifiedBy = r.token.UserId
		central.Central.UpdateIdentity(&user)
	}

	// Change yellowfin permissions
	/* // this has been moved into Login
	if permList, errList := authaus.PermitResolveToList(permit.Roles, central.Central.GetRoleGroupDB()); errList != nil {
		central.Central.Log.Printf("Permit resolve failed: %v", errList)
	} else {
		if errYFGroup := central.Yellowfin.ChangeGroup(permList.Has(PermAdmin), identity); errYFGroup != nil {
			central.Central.Log.Printf("Yellowfin role change error for %v: %v", identity, errYFGroup)
		}
	}
	*/
	central.broadcastToAllSubscribers(createGroupsChangedNotificationMessage(strconv.FormatInt(int64(userId), 10)))
}

func createGroupsChangedNotificationMessage(messageContent string) string {
	return fmt.Sprintf("%v:%v", "permissions_changed", messageContent)
}

func httpHandlerSetPassword(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	userId, getUserIdErr := getUserId(r)
	if getUserIdErr != nil {
		authaus.HttpSendTxt(w, http.StatusBadRequest, getUserIdErr.Error())
		return
	}
	password := strings.TrimSpace(r.http.URL.Query().Get("password"))

	// TODO: get rid of the URL-transmitted password, because it leaks into HTTP logs
	passwordFromHeader := strings.TrimSpace(r.http.Header.Get("X-NewPassword"))
	if passwordFromHeader != "" {
		password = passwordFromHeader
	}

	// admin permission allows you to change anybody's password
	if userId != r.token.UserId && !r.permList.Has(PermAdmin) {
		authaus.HttpSendTxt(w, http.StatusForbidden, msgNotAdmin)
		return
	}

	central.Central.Log.Infof("Setting password for %v", userId)

	// There is no need to update the Yellowfin user's password, because we use a fixed
	// secret password for all yellowfin users.

	err := central.Central.SetPassword(userId, password)
	if err != nil {
		central.Central.Log.Infof("Error setting password for %v: %v", userId, err)
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		return
	}

	if user, err := central.Central.GetUserFromUserId(authaus.UserId(userId)); err == nil {
		auditUserLogAction(central, r, user.UserId, user.Username, "User Profile: "+user.Username, authaus.AuditActionResetPassword)
	}

	authaus.HttpSendTxt(w, http.StatusOK, "Password changed")
}

func httpHandlerUpdatePassword(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	username := strings.TrimSpace(r.http.URL.Query().Get("email"))
	if username == "" {
		authaus.HttpSendTxt(w, http.StatusBadRequest, "Empty identity")
		return
	}

	oldPassword := strings.TrimSpace(r.http.Header.Get("X-OldPassword"))
	if oldPassword == "" {
		authaus.HttpSendTxt(w, http.StatusBadRequest, "Empty old password")
		return
	}

	newPassword := strings.TrimSpace(r.http.Header.Get("X-NewPassword"))
	if newPassword == "" {
		authaus.HttpSendTxt(w, http.StatusBadRequest, "Empty new password")
		return
	}

	err := central.Central.AuthenticateUser(username, oldPassword, authaus.AuthCheckDefault)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusForbidden, err.Error())
		return
	}

	user, err := central.Central.GetUserFromIdentity(username)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusBadRequest, err.Error())
		return
	}
	central.Central.Log.Infof("Setting password for %v", user.UserId)
	if err := central.Central.SetPassword(user.UserId, newPassword); err != nil {
		central.Central.Log.Infof("Error setting password for %v: %v", user.UserId, err)
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditUserLogAction(central, r, user.UserId, user.Username, "User Profile: "+user.Username, authaus.AuditActionResetPassword)
	authaus.HttpSendTxt(w, http.StatusOK, "Password changed")
}

func httpHandlerCheckPassword(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	identity, password, basicOK := r.http.BasicAuth()
	if !basicOK {
		authaus.HttpSendTxt(w, http.StatusBadRequest, authaus.ErrHttpBasicAuth.Error())
		return
	}
	if identity == "" {
		httpSendNoIdentity(w)
		return
	}

	authUser, err := central.Central.GetUserFromIdentity(identity)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := central.Central.AuthenticateUser(identity, password, authaus.AuthCheckDefault); err != nil {
		authaus.HttpSendTxt(w, http.StatusForbidden, err.Error())
		return
	}

	central.Central.Log.Infof("Verified password for %v", authUser.UserId)
	authaus.HttpSendTxt(w, http.StatusOK, "Password verified")
}

func httpHandlerResetPasswordStart(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	identity, userId, err := getUserIdOrIdentity(r)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusBadRequest, err.Error())
		return
	}
	if identity != "" {
		user, err := central.Central.GetUserFromIdentity(identity)
		userId = user.UserId
		if err != nil {
			authaus.HttpSendTxt(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	code, msg := central.ResetPasswordStart(userId, false)
	authaus.HttpSendTxt(w, code, msg)
}

func httpHandlerResetPasswordFinish(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	userId, getUserIdErr := getUserId(r)
	if getUserIdErr != nil {
		authaus.HttpSendTxt(w, http.StatusBadRequest, getUserIdErr.Error())
		return
	}
	token := r.http.Header.Get("X-ResetToken")
	password := strings.TrimSpace(r.http.Header.Get("X-NewPassword"))

	// Authenticate password against forbidden list in auth config
	for _, forbiddenPassword := range central.Config.ForbiddenPasswords {
		if forbiddenPassword == password {
			authaus.HttpSendTxt(w, http.StatusBadRequest, "Password you attempted to set is forbidden by your company policy")
			return
		}
	}

	if token == "" || password == "" {
		authaus.HttpSendTxt(w, http.StatusBadRequest, "Need the two headers X-ResetToken and X-NewPassword")
		return
	}
	err := central.Central.ResetPasswordFinish(userId, token, password)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusForbidden, err.Error())
		return
	}

	if user, err := central.Central.GetUserFromUserId(authaus.UserId(userId)); err == nil {
		auditUserLogAction(central, r, user.UserId, user.Username, "User Profile: "+user.Username, authaus.AuditActionResetPassword)
	}

	authaus.HttpSendTxt(w, http.StatusOK, "Password reset")
}

func httpHandlerHello(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	authaus.HttpSendTxt(w, http.StatusOK, "Hello!")
}

func httpHandlerPing(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	authaus.HttpSendTxt(w, http.StatusOK, fmt.Sprintf("{\"Timestamp\": %v}", time.Now().Unix()))
}

func httpHanderHostname(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	authaus.HttpSendTxt(w, http.StatusOK, fmt.Sprintf("{\"Hostname\": \"%v\"}", central.Config.GetHostname()))
}

func httpHandlerCheck(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	if token, err := authaus.HttpHandlerPreludeWithError(&central.Config.Authaus.HTTP, central.Central, w, r.http); err == nil {
		permList, egroup := authaus.PermitResolveToList(token.Permit.Roles, central.Central.GetRoleGroupDB())
		if egroup != nil && permList == nil {
			central.Central.Log.Errorf("%v : failed to resolve permit : %v", r.http.URL, egroup)
			authaus.HttpSendTxt(w, http.StatusInternalServerError, egroup.Error())
		} else {
			if egroup != nil {
				central.Central.Log.Warnf("%v : failed to resolve permit : %v", r.http.URL, egroup)
			}
			// Ensure that the user has the 'Enabled' permission
			if !permList.Has(PermEnabled) {
				httpSendAccountDisabled(w)
			} else {
				httpSendCheckJson(w, token, permList)
			}
		}
	}
}

func httpHandlerGetEmails(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	users, err := central.Central.GetAuthenticatorIdentities(authaus.GetIdentitiesFlagNone)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		return
	}

	ident2perm, err := central.Central.GetPermits()
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		return
	}

	httpSendPermitsJson(central, users, ident2perm, w)
}

func httpHandlerGetUser(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {

	strUserId := strings.TrimSpace(r.http.URL.Query().Get("userid"))
	identity := strings.TrimSpace(r.http.URL.Query().Get("identity"))

	if strUserId == "" && identity == "" {
		authaus.HttpSendTxt(w, http.StatusBadRequest, "No parameter given")
		return
	}

	var user authaus.AuthUser
	var err error

	if strUserId != "" {
		userId, err := strconv.ParseInt(strUserId, 10, 64)
		if err != nil {
			authaus.HttpSendTxt(w, http.StatusBadRequest, fmt.Sprintf("Invalid parameter: %v", strUserId))
			return
		}

		user, err = central.Central.GetUserFromUserId(authaus.UserId(userId))
		if err != nil {
			authaus.HttpSendTxt(w, http.StatusNotFound, err.Error())
			return
		}
	} else if identity != "" {
		user, err = central.Central.GetUserFromIdentity(identity)
		if err != nil {
			authaus.HttpSendTxt(w, http.StatusNotFound, err.Error())
			return
		}
	}

	permit, err := central.Central.GetPermit(user.UserId)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		return
	}

	jresponse, err := getUserObjectJSON(central, user, permit)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		return
	}

	httpSendJson(w, jresponse)
}

func httpHandlerGetUsers(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	includeArchived := strings.TrimSpace(r.http.URL.Query().Get("archived"))
	var getIdentitiesFlag authaus.GetIdentitiesFlag
	includeArchivedFlag, _ := strconv.ParseBool(includeArchived)

	if includeArchivedFlag {
		getIdentitiesFlag = authaus.GetIdentitiesFlagDeleted
	} else {
		getIdentitiesFlag = authaus.GetIdentitiesFlagNone
	}

	users, err := central.Central.GetAuthenticatorIdentities(getIdentitiesFlag)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		return
	}

	ident2perm, err := central.Central.GetPermits()
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		return
	}

	jresponse, err := getUserObjectsJSON(central, users, ident2perm)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		return
	}

	permission := strings.TrimSpace(r.http.URL.Query().Get("permission"))
	if permission != "" {
		if perm, err := strconv.ParseInt(permission, 10, 16); err == nil {
			withPerm := authaus.PermissionU16(perm)

			// override jresponse with filtered version
			if jresponse, err = filterUserObjectsByPermission(jresponse, central, ident2perm, withPerm); err != nil {
				authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
	}

	httpSendJson(w, jresponse)
}

func httpHandlerGetGroups(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	if groups, err := central.Central.GetRoleGroupDB().GetGroups(); err != nil {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
	} else {
		httpSendGroupsJson(w, groups)
	}
}

func httpHandlerExportUserGroups(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	users, err := central.Central.GetAuthenticatorIdentities(authaus.GetIdentitiesFlagNone)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		return
	}

	ident2perm, err := central.Central.GetPermits()
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		return
	}

	groups, err := central.Central.GetRoleGroupDB().GetGroupsRaw()
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		return
	}

	groupsResp, err := getPermitsJSON(central, users, ident2perm)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		return
	}

	groupNametoID := make(map[string]int)
	for _, group := range groups {
		groupNametoID[group.Name] = int(group.ID)
	}

	var exportGroupUsers []exportGroupUser

	for _, user := range groupsResp {
		groups := make([]int, len(user.Groups))
		for i, group := range user.Groups {
			groups[i] = groupNametoID[group]
		}
		if user.Email != "" {
			exportGroupUsers = append(exportGroupUsers, exportGroupUser{ID: "email: " + user.Email, Groups: groups})
		} else if user.UserName != "" {
			exportGroupUsers = append(exportGroupUsers, exportGroupUser{ID: "username: " + user.UserName, Groups: groups})
		}
	}

	httpSendJson(w, userGroups{Users: exportGroupUsers, Groups: groups, OverwriteGroups: true})
}

func httpHandlerImportUserGroups(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	body, err := ioutil.ReadAll(r.http.Body)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusBadRequest, err.Error())
		return
	}

	var userGroupsJson userGroups
	if err := json.Unmarshal(body, &userGroupsJson); err != nil {
		authaus.HttpSendTxt(w, http.StatusBadRequest, err.Error())
		return
	}

	importedGroupIDtoName := make(map[int]string)
	for _, group := range userGroupsJson.Groups {
		importedGroupIDtoName[int(group.ID)] = group.Name
	}

	parsedGroups, err := authaus.ReadRawGroups(userGroupsJson.Groups)
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusBadRequest, err.Error())
		return
	}
	for _, group := range parsedGroups {
		for _, permission := range group.PermList {
			if PermissionsTable[permission] == "" {
				invalidPerm := fmt.Sprintf("Invalid Permission from import %v in group %v", permission, group.Name)
				central.Central.Log.Warnf(invalidPerm)
				authaus.HttpSendTxt(w, http.StatusBadRequest, invalidPerm)
				return
			}
		}
	}

	for _, group := range parsedGroups {
		if localGroup, err := central.Central.GetRoleGroupDB().GetByName(group.Name); err == nil && userGroupsJson.OverwriteGroups {
			group.ID = localGroup.ID

			localGroup.PermList = group.PermList
			if eupdate := central.Central.GetRoleGroupDB().UpdateGroup(localGroup); eupdate != nil {
				authaus.HttpSendTxt(w, http.StatusInternalServerError, eupdate.Error())
				return
			}
			// audit log required for permissions update diff
		} else if err == nil && !userGroupsJson.OverwriteGroups {
			central.Central.Log.Warnf("Group %v not updated, overwrite set to false", group.Name)
		} else if err != nil && strings.Index(err.Error(), authaus.ErrGroupNotExist.Error()) != -1 {
			if einsert := central.Central.GetRoleGroupDB().InsertGroup(&group); einsert != nil {
				authaus.HttpSendTxt(w, http.StatusInternalServerError, einsert.Error())
				return
			}
			// audit log required for new group
		} else {
			authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	ident2perm, err := central.Central.GetPermits()
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		return
	}

	for _, importUser := range userGroupsJson.Users {
		identity := importUser.ID
		identity = identity[strings.Index(identity, ":")+1 : len(identity)]
		user, usererr := central.Central.GetUserFromIdentity(identity)
		if usererr != nil {
			central.Central.Log.Warnf("Warning: User not found, skipping")
			continue
		}
		var groupNames []string
		for _, groupID := range importUser.Groups {
			groupNames = append(groupNames, importedGroupIDtoName[groupID])
		}

		userSlice := []authaus.AuthUser{user}

		groupsResp, err := getPermitsJSON(central, userSlice, ident2perm)
		if err != nil {
			authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
			return
		}

		for _, name := range groupsResp[0].Groups {
			if !containsStr(groupNames, name) {
				groupNames = append(groupNames, name)
			}
		}

		setUserPermissionGroupsByName(central, user.UserId, groupNames)
	}

	authaus.HttpSendTxt(w, http.StatusOK, "")
}

func httpHandlerHasActiveDirectory(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	if len(central.Config.Authaus.LDAP.LdapHost) > 0 {
		httpSendResponse(w, []byte("1"))
	} else {
		httpSendResponse(w, []byte("0"))
	}
}

// httpHanderGetDynamicPermissions returns all of the dynamic/client specific permissions
// as set in the imqsauth config file.
func httpHandlerGetDynamicPermissions(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	response := []byte("{}")
	var err error
	if central.Config.Permissions != nil {
		response, err = json.Marshal(central.Config.Permissions)
		if err != nil {
			authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	w.Header().Add("content-type", "application/json")
	httpSendResponse(w, response)
}

func getUserId(r *httpRequest) (authaus.UserId, error) {
	uidStr := strings.TrimSpace(r.http.URL.Query().Get("userid"))
	if uidStr == "" {
		return authaus.NullUserId, errNoUserId
	}
	if iUserId, err := strconv.ParseInt(uidStr, 10, 64); err == nil {
		return authaus.UserId(iUserId), nil
	} else {
		return authaus.NullUserId, fmt.Errorf("Invalid userid '%v': %v", uidStr, err)
	}
}

func getUserIdOrIdentity(r *httpRequest) (string, authaus.UserId, error) {
	uidStr := strings.TrimSpace(r.http.URL.Query().Get("userid"))
	email := strings.TrimSpace(r.http.URL.Query().Get("email"))
	if email != "" {
		return email, authaus.NullUserId, nil
	}
	if uidStr == "" {
		return "", authaus.NullUserId, errNoUserId
	}
	if iUserId, err := strconv.ParseInt(uidStr, 10, 64); err == nil {
		return "", authaus.UserId(iUserId), nil
	} else {
		return "", authaus.NullUserId, fmt.Errorf("Invalid userid '%v': %v", uidStr, err)
	}
}

func (central *ImqsCentral) broadcastToAllSubscribers(msg string) {
	jsonString, err := json.Marshal(&notificationRequestJson{Channel: "authNotifications", Msg: msg})
	if err != nil {
		central.Central.Log.Warnf("An error occurred creating json message: %v", err)
		return
	}

	req, err := http.NewRequest("POST", central.Config.NotificationUrl, bytes.NewReader(jsonString))
	if err != nil {
		central.Central.Log.Warnf("An error occurred creating request to distributor: %v", err)
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		central.Central.Log.Warnf("An error occurred sending message to distributor: %v", err)
		return
	}
	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		central.Central.Log.Warnf("An error occurred reading response from distributor: %v", err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		central.Central.Log.Warnf("An error occurred while distributor was processing message: %v\n%v", err, string(respBody))
	}
}
