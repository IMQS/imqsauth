package imqsauth

import (
	"encoding/json"
	"fmt"
	"github.com/IMQS/authaus"
	"net/http"
	"strconv"
	"strings"
	"time"
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
	Identity string
	Roles    []string
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

type userGroupsResponseJson struct {
	Groups []string
}

type ImqsCentral struct {
	Config    *Config
	Central   *authaus.Central
	Yellowfin *Yellowfin
}

func (x *ImqsCentral) RunHttp() error {

	// The built-in go ServeMux does not support differentiating based on HTTP verb, so we have to make
	// the request path unique for each verb. I think this is OK as far as API design is concerned - at least in this domain.
	makehandler := func(method HttpMethod, actual func(*ImqsCentral, http.ResponseWriter, *httpRequest), flags handlerFlags) func(http.ResponseWriter, *http.Request) {
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
			if needAdmin || needToken {
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
			}

			actual(x, w, httpReq)
		}
	}

	smux := http.NewServeMux()
	smux.HandleFunc("/hello", makehandler(HttpMethodGet, httpHandlerHello, 0))
	smux.HandleFunc("/login", makehandler(HttpMethodPost, httpHandlerLogin, 0))
	smux.HandleFunc("/logout", makehandler(HttpMethodPost, httpHandlerLogout, 0))
	smux.HandleFunc("/check", makehandler(HttpMethodGet, httpHandlerCheck, 0))
	smux.HandleFunc("/create_user", makehandler(HttpMethodPut, httpHandlerCreateUser, handlerFlagNeedAdminRights))
	smux.HandleFunc("/create_group", makehandler(HttpMethodPut, httpHandlerCreateGroup, handlerFlagNeedAdminRights))
	smux.HandleFunc("/rename_user", makehandler(HttpMethodPost, httpHandlerRenameUser, handlerFlagNeedToken))
	smux.HandleFunc("/set_group_roles", makehandler(HttpMethodPut, httpHandlerSetGroupRoles, handlerFlagNeedAdminRights))
	smux.HandleFunc("/set_user_groups", makehandler(HttpMethodPost, httpHandlerSetUserGroups, handlerFlagNeedAdminRights))
	smux.HandleFunc("/set_password", makehandler(HttpMethodPost, httpHandlerSetPassword, handlerFlagNeedToken))
	smux.HandleFunc("/users", makehandler(HttpMethodGet, httpHandlerGetUsers, 0))
	smux.HandleFunc("/groups", makehandler(HttpMethodGet, httpHandlerGetGroups, 0))

	server := &http.Server{}
	server.Handler = smux
	server.Addr = x.Config.Authaus.HTTP.Bind + ":" + strconv.Itoa(x.Config.Authaus.HTTP.Port)

	x.Central.Log.Printf("ImqsAuth is trying to listen on %v:%v", x.Config.Authaus.HTTP.Bind, x.Config.Authaus.HTTP.Port)

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
		w.Header().Add("Content-Type", "application/json")
		w.Header().Add("Cache-Control", "no-cache, no-store, must revalidate")
		w.Header().Add("Pragma", "no-cache")
		w.Header().Add("Expires", "0")
		w.WriteHeader(http.StatusOK)
		w.Write(jsonStr)
	} else {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, jsonErr.Error())
	}
}

func httpSendCheckJson(w http.ResponseWriter, token *authaus.Token, permList authaus.PermissionList) {
	jresponse := &checkResponseJson{}
	jresponse.Identity = token.Identity
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

func httpSendPermitsJson(central *ImqsCentral, identities []string, ident2perm map[string]*authaus.Permit, w http.ResponseWriter) {
	//central.Central.Log.Printf("Number of identities %v", len(permits))

	emptyPermit := authaus.Permit{}

	jresponse := make(map[string]*userGroupsResponseJson)
	for _, identity := range identities {
		permit := ident2perm[authaus.CanonicalizeIdentity(identity)]
		if permit == nil {
			permit = &emptyPermit
		}
		jresponse[identity] = &userGroupsResponseJson{}
		groups, err := authaus.DecodePermit(permit.Roles)
		if err != nil {
			authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
			return
		}
		jresponse[identity].Groups, err = authaus.GroupIDsToNames(groups, central.Central.GetRoleGroupDB())
		if err != nil {
			authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	httpSendJson(w, jresponse)
}

func httpSendAccountDisabled(w http.ResponseWriter) {
	authaus.HttpSendTxt(w, http.StatusForbidden, msgAccountDisabled)
}

func httpSendNoIdentity(w http.ResponseWriter) {
	authaus.HttpSendTxt(w, http.StatusUnauthorized, authaus.ErrIdentityEmpty.Error())
}

func httpHandlerLogout(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	identity := ""
	if token, err := authaus.HttpHandlerPreludeWithError(&central.Config.Authaus.HTTP, central.Central, w, r.http); err == nil {
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

	if err := central.Yellowfin.Logout(identity, r.http); err != nil {
		central.Central.Log.Printf("Yellowfin logout error: %v", err)
	}
	authaus.HttpSendTxt(w, http.StatusOK, "")
}

// Handle the 'login' request, sending back a session token (via Set-Cookie),
func httpHandlerLogin(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	identity, password, eBasic := authaus.HttpReadBasicAuth(r.http)
	if eBasic != nil {
		authaus.HttpSendTxt(w, http.StatusBadRequest, eBasic.Error())
		return
	}
	if identity == "" {
		httpSendNoIdentity(w)
		return
	}

	if sessionkey, token, err := central.Central.Login(identity, password); err != nil {
		authaus.HttpSendTxt(w, http.StatusForbidden, err.Error())
	} else {
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
				httpLoginYellowfin(central, w, r, identity, permList)
				httpSendCheckJson(w, token, permList)
			}
		}
	}
}

// This is intended to be called by httpHandlerLogin
func httpLoginYellowfin(central *ImqsCentral, w http.ResponseWriter, r *httpRequest, identity string, permList authaus.PermissionList) {
	if !central.Yellowfin.Enabled {
		return
	}
	yfGroup := makeYellowfinGroup(permList)
	if yfGroup != YellowfinGroupNone {
		cookies, err := central.Yellowfin.LoginAndUpdateGroup(identity, yfGroup)
		if err == ErrYellowfinAuthFailed {
			// Try to create the identity in yellowfin
			if err = central.Yellowfin.CreateUser(identity); err == nil {
				// Try again to login
				cookies, err = central.Yellowfin.LoginAndUpdateGroup(identity, yfGroup)
			}
		}
		if err != nil {
			central.Central.Log.Printf("Yellowfin login error: %v", err)
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
}

// Note that we do not create a permit here for the user, so he will not yet be able to login.
// In order to finish the job, you will need to call httpHandlerSetUserGroups which will
// create a permit for this user.
func httpHandlerCreateUser(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	identity := strings.TrimSpace(r.http.URL.Query().Get("identity"))
	password := strings.TrimSpace(r.http.URL.Query().Get("password"))
	if err := central.Central.CreateAuthenticatorIdentity(identity, password); err != nil {
		authaus.HttpSendTxt(w, http.StatusForbidden, err.Error())
	} else {
		authaus.HttpSendTxt(w, http.StatusOK, fmt.Sprintf("Created identity '%v'", identity))
		/* // This has been moved to Login
		if yfErr := central.Yellowfin.CreateUser(identity); yfErr != nil {
			central.Central.Log.Printf("Error creating Yellowfin user '%v': %v", identity, yfErr)
		}
		*/
	}
}

func httpHandlerCreateGroup(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	groupname := strings.TrimSpace(r.http.URL.Query().Get("groupname"))
	if groupname == "" {
		authaus.HttpSendTxt(w, http.StatusNotAcceptable, "Group name may not be blank.")
		return
	}

	if _, err := authaus.LoadOrCreateGroup(central.Central.GetRoleGroupDB(), groupname, true); err == nil {
		central.Central.Log.Printf("New group added: %v", groupname)
		authaus.HttpSendTxt(w, http.StatusOK, "")
		return
	} else {
		central.Central.Log.Printf("Error creating group (%v): %v", groupname, err)
		authaus.HttpSendTxt(w, http.StatusBadRequest, fmt.Sprintf("Error creating group (%v): %v", groupname, err))
		return
	}
}

func httpHandlerRenameUser(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	oldIdent := authaus.CanonicalizeIdentity(strings.TrimSpace(r.http.URL.Query().Get("old")))
	newIdent := authaus.CanonicalizeIdentity(strings.TrimSpace(r.http.URL.Query().Get("new")))
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
		if token.Identity != oldIdent {
			authaus.HttpSendTxt(w, http.StatusForbidden, authMsg+" Authenticated with '"+token.Identity+"', but tried to rename user '"+oldIdent+"'")
			return
		}
	}

	if err := central.Central.RenameIdentity(oldIdent, newIdent); err == nil {
		authaus.HttpSendTxt(w, http.StatusOK, "Renamed '"+oldIdent+"' to '"+newIdent+"'")
	} else {
		authaus.HttpSendTxt(w, http.StatusBadRequest, err.Error())
	}
}

func httpHandlerSetGroupRoles(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	//TODO : Add check so current user cannot remove own Admin rights
	groupname := strings.TrimSpace(r.http.URL.Query().Get("groupname"))
	rolesstring := strings.TrimSpace(r.http.URL.Query().Get("roles"))

	perms := authaus.PermissionList{}

	for _, pname := range strings.Split(rolesstring, ",") {
		perm, _ := strconv.ParseInt(pname, 10, 16)
		perms = append(perms, authaus.PermissionU16(perm))
	}

	if group, e := authaus.LoadOrCreateGroup(central.Central.GetRoleGroupDB(), groupname, false); e == nil {
		central.Central.Log.Printf("Roles %v set for group %v", rolesstring, groupname)
		group.PermList = perms
		if err := central.Central.GetRoleGroupDB().UpdateGroup(group); err == nil {
			central.Central.Log.Printf("Set group roles for %v", groupname)
			authaus.HttpSendTxt(w, http.StatusOK, "")
		} else {
			central.Central.Log.Printf("Could not set group roles for %v: %v", groupname, err)
			authaus.HttpSendTxt(w, http.StatusNotAcceptable, fmt.Sprintf("Could not set group roles for %v: %v", groupname, err))
		}
	} else {
		central.Central.Log.Printf("Group '%v' not found: %v", groupname, e)
		authaus.HttpSendTxt(w, http.StatusNotFound, fmt.Sprintf("Group '%v' not found: %v", groupname, e))
	}
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

	identity := strings.TrimSpace(r.http.URL.Query().Get("identity"))
	groupsParam := strings.TrimSpace(r.http.URL.Query().Get("groups"))

	if identity == "" {
		panic("Identity is empty")
	}
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
	if eSetPermit := central.Central.SetPermit(identity, permit); eSetPermit != nil {
		panic(eSetPermit)
	}

	summary := strings.Join(groups, ",")
	authaus.HttpSendTxt(w, http.StatusOK, fmt.Sprintf("'%v' groups set to (%v)", identity, summary))

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
}

func httpHandlerSetPassword(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	identity := strings.TrimSpace(r.http.URL.Query().Get("identity"))
	password := strings.TrimSpace(r.http.URL.Query().Get("password"))

	// admin permission allows you to change anybody's password
	if identity != r.token.Identity && !r.permList.Has(PermAdmin) {
		authaus.HttpSendTxt(w, http.StatusForbidden, msgNotAdmin)
		return
	}

	central.Central.Log.Printf("Setting password for %v", identity)

	err := central.Central.SetPassword(identity, password)
	if err == nil {
		if err = central.Yellowfin.UpdatePassword(identity, password); err != nil {
			central.Central.Log.Printf("Error setting Yellowfin password for %v: %v", identity, err)
			authaus.HttpSendTxt(w, http.StatusInternalServerError, fmt.Sprintf("Yellowfin password update failed for %v: %v", identity, err))
			return
		}
	} else {
		central.Central.Log.Printf("Error setting password for %v: %v", identity, err)
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		return
	}

	authaus.HttpSendTxt(w, http.StatusOK, "Password changed")
}

func httpHandlerHello(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	authaus.HttpSendTxt(w, http.StatusOK, "Hello!")
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

func httpHandlerGetUsers(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	identities, err := central.Central.GetAuthenticatorIdentities()
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		return
	}

	ident2perm, err := central.Central.GetPermits()
	if err != nil {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
		return
	}

	httpSendPermitsJson(central, identities, ident2perm, w)
}

func httpHandlerGetGroups(central *ImqsCentral, w http.ResponseWriter, r *httpRequest) {
	if groups, err := central.Central.GetRoleGroupDB().GetGroups(); err != nil {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
	} else {
		httpSendGroupsJson(w, groups)
	}
}
