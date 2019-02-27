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
	"github.com/IMQS/serviceauth"
	"github.com/IMQS/yfws"
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
	errYellowfinDisabled = errors.New("Yellowfin is disabled")
	errNoUserId          = errors.New("No userid specified")
)

type HttpMethod string

const (
	HttpMethodGet  HttpMethod = "GET"
	HttpMethodPost            = "POST"
	HttpMethodPut             = "PUT"
)

type handlerFlags uint32

const (
	handlerFlagNeedAdminRights = 1 << iota // Request won't even reach your handler unless the user is an admin
	handlerFlagNeedToken                   // Populate the httpRequest object with 'token' and 'permList'
)

type httpRequest struct {
	http     *http.Request
	token    *authaus.Token // Only populated if you passed in handlerFlagNeedAdminRights or handlerFlagNeedToken
	permList authaus.PermissionList
}

type checkResponseJson struct {
	UserId   authaus.UserId
	Identity string
	Email    string
	Username string
	Roles    []string
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
}

func (x *groupResponseJson) SetGroup(group *authaus.AuthGroup) {
	x.Name = group.Name
	x.Roles = make([]string, len(group.PermList))
	for i, role := range group.PermList {
		x.Roles[i] = fmt.Sprintf("%d", role)
	}
}

type groupsResponseJson struct {
	Email    string
	UserName string
	Groups   []string
}

type userResponseJson struct {
	UserId       authaus.UserId
	Email        string
	Username     string
	Name         string
	Surname      string
	Mobile       string
	Telephone    string
	Remarks      string
	Created      time.Time
	CreatedBy    string
	Modified     time.Time
	ModifiedBy   string
	Groups       []string
	AuthUserType authaus.AuthUserType
	Archived     bool
}

type ImqsCentral struct {
	Config    *Config
	Central   *authaus.Central
	Yellowfin *Yellowfin

	// Guards access to roleChangeSubscribers and lastSubscriberId
	subscriberLock sync.RWMutex
}

func (x *ImqsCentral) makeHandler(method HttpMethod, actual func(*ImqsCentral, http.ResponseWriter, *httpRequest), flags handlerFlags) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != string(method) {
			authaus.HttpSendTxt(w, http.StatusBadRequest, fmt.Sprintf("API must be accessed using an HTTP %v method", method))
			return
		}
		httpReq := &httpRequest{
			http: r,
		}

		needAdmin := 0 != (flags & handlerFlagNeedAdminRights)
		needToken := 0 != (flags & handlerFlagNeedToken)
		if !needAdmin && !needToken {
			actual(x, w, httpReq)
			return
		}

		if err := serviceauth.VerifyInterServiceRequest(r); err == nil {
			actual(x, w, httpReq)
			return
		}

		permOK := false
		if token, err := authaus.HttpHandlerPreludeWithError(&x.Config.Authaus.HTTP, x.Central, w, r); err == nil {
			if permList, errDecodePerms := authaus.PermitResolveToList(token.Permit.Roles, x.Central.GetRoleGroupDB()); errDecodePerms != nil {
				authaus.HttpSendTxt(w, http.StatusInternalServerError, errDecodePerms.Error())
			} else {
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
	smux.HandleFunc("/login", x.makeHandler(HttpMethodPost, httpHandlerLogin, 0))
	smux.HandleFunc("/login_yellowfin", x.makeHandler(HttpMethodPost, httpHandlerLoginYellowfin, handlerFlagNeedToken))
	smux.HandleFunc("/logout", x.makeHandler(HttpMethodPost, httpHandlerLogout, 0))
	smux.HandleFunc("/check", x.makeHandler(HttpMethodGet, httpHandlerCheck, 0))
	smux.HandleFunc("/create_user", x.makeHandler(HttpMethodPut, httpHandlerCreateUser, handlerFlagNeedAdminRights))
	smux.HandleFunc("/update_user", x.makeHandler(HttpMethodPost, httpHandlerUpdateUser, handlerFlagNeedAdminRights))
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
	smux.HandleFunc("/groups", x.makeHandler(HttpMethodGet, httpHandlerGetGroups, 0))
	smux.HandleFunc("/hasactivedirectory", x.makeHandler(HttpMethodGet, httpHandlerHasActiveDirectory, 0))

	server := &http.Server{}
	server.Handler = smux
	server.Addr = x.Config.Authaus.HTTP.Bind + ":" + x.Config.Authaus.HTTP.Port

	x.Central.Log.Infof("ImqsAuth is trying to listen on %v:%v", x.Config.Authaus.HTTP.Bind, x.Config.Authaus.HTTP.Port)

	if err := server.ListenAndServe(); err != nil {
		return err
	}

	return nil
}

func (x *ImqsCentral) IsAdmin(r *http.Request) (bool, error) {
	if token, err := authaus.HttpHandlerPrelude(&x.Config.Authaus.HTTP, x.Central, r); err == nil {
		if pbits, egroup := authaus.PermitResolveToList(token.Permit.Roles, x.Central.GetRoleGroupDB()); egroup == nil {
			return pbits.Has(PermAdmin), nil
		} else {
			return false, egroup
		}
	} else {
		return false, err
	}
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

	return x.buildMailRequestAndSend(mailQuery, mailBody)
}

func (x *ImqsCentral) createDefaultMailQuery(user authaus.AuthUser, token string, isNewAccount bool, expireSeconds float64) (string, error) {
	strUserId := strconv.FormatInt(int64(user.UserId), 10)
	resetUrl, err := x.makeAbsoluteUrl("/#resetpassword=true&identity=" + url.QueryEscape(user.Email) + "&userid=" + url.QueryEscape(strUserId) + "&token=" + url.QueryEscape(token))
	if err != nil {
		return "", err
	}
	if isNewAccount {
		resetUrl += "&welcome=true"
	}

	mailQuery := "passwordReset?"
	mailQuery += fmt.Sprintf("email=%v&resetUrl=%v&expireTime=%.0f", url.QueryEscape(user.Email), url.QueryEscape(resetUrl), expireSeconds)
	if isNewAccount {
		mailQuery += "&newAccount=true"
	} else {
		mailQuery += "&newAccount=false"
	}

	return mailQuery, nil
}

func (x *ImqsCentral) createLDAPMailQueryAndBody(user authaus.AuthUser) (string, string) {
	var mailQuery string
	var mailBody string
	mailQuery += "sendEmail?"
	mailQuery += fmt.Sprintf("emailTo=%v&subject=%v&ishtml=True", url.QueryEscape(user.Email), url.QueryEscape("IMQS Reset Password"))
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
	if len(mailBody) > 0 {
		sendMailReq, err = http.NewRequest("POST", "https://imqs-mailer.appspot.com/"+mailQuery, strings.NewReader(mailBody))
	} else {
		sendMailReq, err = http.NewRequest("POST", "https://imqs-mailer.appspot.com/"+mailQuery, nil)
	}
	if err != nil {
		return http.StatusServiceUnavailable, "Error sending mail: " + err.Error()
	}
	sendMailReq.SetBasicAuth("imqs", x.Config.SendMailPassword)

	mailResp, err := http.DefaultClient.Do(sendMailReq)
	if err != nil {
		return http.StatusServiceUnavailable, "Error sending email: " + err.Error()
	}
	defer mailResp.Body.Close()
	respBody, _ := ioutil.ReadAll(mailResp.Body)
	if mailResp.StatusCode != http.StatusOK {
		return http.StatusServiceUnavailable, fmt.Sprintf("Error sending email: %v\n%v", mailResp.Status, string(respBody))
	}

	return http.StatusOK, ""
}

func makeYellowfinGroup(permList authaus.PermissionList) YellowfinGroup {
	table := []struct {
		perm  authaus.PermissionU16
		group YellowfinGroup
	}{
		// More permissive roles must be first in this table, because we take whatever we see first.
		{PermAdmin, YellowfinGroupAdmin},
		{PermReportCreator, YellowfinGroupWriter},
		{PermReportViewer, YellowfinGroupConsumer},
	}
	for _, t := range table {
		if permList.Has(t.perm) {
			return t.group
		}
	}
	return YellowfinGroupNone
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
	emptyPermit := authaus.Permit{}

	jresponse := make([]*groupsResponseJson, 0)
	for _, user := range users {
		var validUser groupsResponseJson
		permit := ident2perm[user.UserId]
		if permit == nil {
			permit = &emptyPermit
		}
		groups, err := authaus.DecodePermit(permit.Roles)
		if err != nil {
			authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
			return
		}
		validUser.UserName = user.Username
		validUser.Email = user.Email
		validUser.Groups, err = authaus.GroupIDsToNames(groups, central.Central.GetRoleGroupDB())
		if err != nil {
			authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
			return
		}
		jresponse = append(jresponse, &validUser)
	}
	httpSendJson(w, jresponse)
}

func httpSendUserObjectsJSON(central *ImqsCentral, users []authaus.AuthUser, ident2perm map[authaus.UserId]*authaus.Permit, w http.ResponseWriter) ([]*userResponseJson, error) {
	emptyPermit := authaus.Permit{}

	//jresponse := make(map[string]*userResponseJson)
	jresponse := make([]*userResponseJson, 0)
	for _, user := range users {
		permit := ident2perm[user.UserId]
		if permit == nil || user.Archived { // Do not include permits of archived users
			permit = &emptyPermit
		}
		groups, err := authaus.DecodePermit(permit.Roles)
		if err != nil {
			return nil, err
		}
		groupnames, err := authaus.GroupIDsToNames(groups, central.Central.GetRoleGroupDB())
		if err != nil {
			return nil, err
		}

		jresponse = append(jresponse, &userResponseJson{
			Email:        user.Email,
			UserId:       user.UserId,
			Username:     user.Username,
			Name:         user.Firstname,
			Surname:      user.Lastname,
			Mobile:       user.Mobilenumber,
			Telephone:    user.Telephonenumber,
			Remarks:      user.Remarks,
			Created:      user.Created,
			CreatedBy:    central.Central.GetUserNameFromUserId(user.CreatedBy),
			Modified:     user.Modified,
			ModifiedBy:   central.Central.GetUserNameFromUserId(user.ModifiedBy),
			Groups:       groupnames,
			AuthUserType: user.Type,
			Archived:     user.Archived,
		})
	}

	return jresponse, nil
}

// To filter users with withPerm permission,
func filterUserObjectsByPermission(users []*userResponseJson, central *ImqsCentral, ident2perm map[authaus.UserId]*authaus.Permit, perm authaus.PermissionU16) ([]*userResponseJson, error) {
	emptyPermit := authaus.Permit{}
	jFiltered := make([]*userResponseJson, 0)

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
		permit := ident2perm[user.UserId]
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

	// Only attempt YF logout if its cookie (JSESSIONID) is present in the logout call
	if _, err := r.http.Cookie("JSESSIONID"); err == nil {
		if err := central.Yellowfin.Logout(identity, r.http); err != nil {
			central.Central.Log.Errorf("Yellowfin logout error: %v", err)
		}
	}
	authaus.HttpSendTxt(w, http.StatusOK, "")
}

// Handle the 'login' request, sending back a session token (via Set-Cookie),
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

	if sessionkey, token, err := central.Central.Login(identity, password); err != nil {
		authaus.HttpSendTxt(w, http.StatusForbidden, err.Error())
	} else {
		r.token = token
		auditUserLogAction(central, r, token.UserId, token.Username, "User Profile: "+token.Identity, authaus.AuditActionAuthentication)
		if permList, egroup := authaus.PermitResolveToList(token.Permit.Roles, central.Central.GetRoleGroupDB()); egroup != nil {
			authaus.HttpSendTxt(w, http.StatusInternalServerError, egroup.Error())
		} else {
			// Ensure that the user has the 'Enabled' permission
			if !permList.Has(PermEnabled) {
				httpSendAccountDisabled(w)
			} else {
				cookie := &http.Cookie{
					Name:    central.Config.Authaus.HTTP.CookieName,
					Value:   sessionkey,
					Path:    "/",
					Expires: token.Expires,
					Secure:  central.Config.Authaus.HTTP.CookieSecure,
				}
				http.SetCookie(w, cookie)
				if central.Config.Yellowfin.UseLegacyAuth {
					if err = httpLoginYellowfin(central, w, r, identity, permList); err != nil {
						central.Central.Log.Errorf("Yellowfin login error: %v", err)
					}
				}
				httpSendCheckJson(w, token, permList)
			}
		}
	}
}

// This is a top-level HTTP API, built to allow an explicit login to Yellowfin only.
func httpHandlerLoginYellowfin(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	if err := httpLoginYellowfin(central, w, r, r.token.Identity, r.permList); err == nil {
		authaus.HttpSendTxt(w, http.StatusOK, "OK")
	} else {
		// Possible YF request HTTP error code will be included in the error message.
		errMsg := fmt.Sprintf("Yellowfin login error: %v", err)
		central.Central.Log.Error(errMsg)
		authaus.HttpSendTxt(w, http.StatusInternalServerError, errMsg)
	}
}

// This is a sub-function, intended to be called by httpHandlerLogin
func httpLoginYellowfin(central *ImqsCentral, w http.ResponseWriter, r *httpRequest, identity string, permList authaus.PermissionList) error {
	if !central.Yellowfin.Enabled {
		return errYellowfinDisabled
	}
	yfGroup := makeYellowfinGroup(permList)
	if yfGroup != YellowfinGroupNone {
		paramsBytes, err := ioutil.ReadAll(r.http.Body)
		if err != nil {
			return err
		}

		var yfLoginParams yellowfinLoginParameters
		err = json.Unmarshal(paramsBytes, &yfLoginParams)
		if err != nil {
			return err
		}

		cookies, err := central.Yellowfin.LoginAndUpdateGroup(identity, yfGroup, yfLoginParams)
		if err == yfws.ErrYFCouldNotAuthenticateUser || err == yfws.ErrYFCouldNotFindPerson {

			// Try to create the identity in yellowfin
			if err = central.Yellowfin.CreateUser(identity); err == nil {
				// Try again to login
				cookies, err = central.Yellowfin.LoginAndUpdateGroup(identity, yfGroup, yfLoginParams)
			}
		}
		if err != nil {
			return err
		} else if cookies != nil {
			for _, cookie := range cookies {
				// Despite raising the tomcat session timeout in web.xml to 31 days,
				// the cookies that yellowfin returns us have an expiry of 12 hours.
				// That is why we simply override the cookie timeout here.
				if cookie.Name == "JSESSIONID" || cookie.Name == "IPID" {
					newcookie := &http.Cookie{
						Name:    cookie.Name,
						Value:   cookie.Value,
						Path:    "/",
						Expires: time.Now().Add(yellowfinCookieExpiry),
						Secure:  cookie.Secure,
					}
					http.SetCookie(w, newcookie)
				}
			}
		}
	}
	return nil
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
	createdby := r.token.UserId
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
		auditUserLogAction(central, r, user.UserId, user.Username, "User Profile: "+user.Username, authaus.AuditActionUpdated)
		authaus.HttpSendTxt(w, http.StatusOK, fmt.Sprintf("Updated user: '%v'", userId))
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

func httpHandlerSetGroupRoles(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	//TODO : Add check so current user cannot remove own Admin rights
	groupname := strings.TrimSpace(r.http.URL.Query().Get("groupname"))
	rolesstring := strings.TrimSpace(r.http.URL.Query().Get("roles"))

	perms := authaus.PermissionList{}

	if len(rolesstring) > 0 {
		for _, pname := range strings.Split(rolesstring, ",") {
			perm, _ := strconv.ParseInt(pname, 10, 16)
			perms = append(perms, authaus.PermissionU16(perm))
		}
	}

	if group, e := authaus.LoadOrCreateGroup(central.Central.GetRoleGroupDB(), groupname, false); e == nil {
		central.Central.Log.Infof("Roles %v set for group %v", rolesstring, groupname)
		group.PermList = perms
		if err := central.Central.GetRoleGroupDB().UpdateGroup(group); err == nil {
			central.Central.Log.Infof("Set group roles for %v", groupname)
			if r.token != nil {
				if user, err := central.Central.GetUserFromUserId(authaus.UserId(r.token.UserId)); err == nil {
					auditUserLogAction(central, r, user.UserId, user.Username, "Group: "+groupname+" roles updated", authaus.AuditActionUpdated)
				}
			}
			authaus.HttpSendTxt(w, http.StatusOK, "")
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
		if r.token.UserId == user.UserId {
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

	permit := &authaus.Permit{}
	permit.Roles = authaus.EncodePermit(groupIDs)
	if eSetPermit := central.Central.SetPermit(userId, permit); eSetPermit != nil {
		panic(eSetPermit)
	}

	if user, err := central.Central.GetUserFromUserId(authaus.UserId(userId)); err == nil {
		auditUserLogAction(central, r, user.UserId, user.Username, "User Profile: User "+user.Username+" permissions changed", authaus.AuditActionUpdated)
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

func httpHandlerCheck(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	if token, err := authaus.HttpHandlerPreludeWithError(&central.Config.Authaus.HTTP, central.Central, w, r.http); err == nil {
		if permList, egroup := authaus.PermitResolveToList(token.Permit.Roles, central.Central.GetRoleGroupDB()); egroup != nil {
			authaus.HttpSendTxt(w, http.StatusInternalServerError, egroup.Error())
		} else {
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

	jresponse, err := httpSendUserObjectsJSON(central, users, ident2perm, w)
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

func httpHandlerHasActiveDirectory(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	if len(central.Config.Authaus.LDAP.LdapHost) > 0 {
		httpSendResponse(w, []byte("1"))
	} else {
		httpSendResponse(w, []byte("0"))
	}
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
