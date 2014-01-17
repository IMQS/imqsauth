package imqsauth

import (
	"encoding/json"
	"fmt"
	"github.com/IMQS/authaus"
	"net/http"
	"strconv"
	"strings"
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
	handlerFlagNeedAdminRights = 1 << iota
)

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
	Config  *authaus.Config
	Central *authaus.Central
}

func (x *ImqsCentral) RunHttp() error {

	// The built-in go ServeMux does not support differentiating based on HTTP verb, so we have to make
	// the request path unique for each verb. I think this is OK as far as API design is concerned - at least in this domain.
	makehandler := func(method HttpMethod, actual func(*ImqsCentral, http.ResponseWriter, *http.Request), flags handlerFlags) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != string(method) {
				authaus.HttpSendTxt(w, http.StatusBadRequest, fmt.Sprintf("API must be accessed using an HTTP %v method", method))
				return
			}
			if 0 != (flags & handlerFlagNeedAdminRights) {
				permOK := false
				if token, err := authaus.HttpHandlerPreludeWithError(&x.Config.HTTP, x.Central, w, r); err == nil {
					if permList, errDecodePerms := authaus.PermitResolveToList(token.Permit.Roles, x.Central.GetRoleGroupDB()); errDecodePerms != nil {
						authaus.HttpSendTxt(w, http.StatusInternalServerError, errDecodePerms.Error())
					} else {
						if !permList.Has(PermAdmin) {
							authaus.HttpSendTxt(w, http.StatusForbidden, msgNotAdmin)
						} else if !permList.Has(PermEnabled) {
							httpSendAccountDisabled(w)
						} else {
							x.Central.Log.Printf("Admin is OK")
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

			actual(x, w, r)
		}
	}

	smux := http.NewServeMux()
	smux.HandleFunc("/login", makehandler(HttpMethodPost, httpHandlerLogin, 0))
	smux.HandleFunc("/check", makehandler(HttpMethodGet, httpHandlerCheck, 0))
	smux.HandleFunc("/create_user", makehandler(HttpMethodPut, httpHandlerCreateUser, handlerFlagNeedAdminRights))
	smux.HandleFunc("/set_user_groups", makehandler(HttpMethodPost, httpHandlerSetUserGroups, handlerFlagNeedAdminRights))
	smux.HandleFunc("/users", makehandler(HttpMethodGet, httpHandlerGetUsers, handlerFlagNeedAdminRights))
	smux.HandleFunc("/groups", makehandler(HttpMethodGet, httpHandlerGetGroups, handlerFlagNeedAdminRights))

	server := &http.Server{}
	server.Handler = smux
	server.Addr = x.Config.HTTP.Bind + ":" + strconv.Itoa(x.Config.HTTP.Port)

	x.Central.Log.Printf("ImqsAuth is listening on %v:%v\n", x.Config.HTTP.Bind, x.Config.HTTP.Port)

	if err := server.ListenAndServe(); err != nil {
		return err
	}

	return nil
}

func (x *ImqsCentral) LoadConfigAndRunHttp() error {
	var err error
	if x.Central, err = authaus.NewCentralFromConfig(x.Config); err != nil {
		return err
	} else {
		err := x.RunHttp()
		x.Central.Close()
		return err
	}
}

func (x *ImqsCentral) IsAdmin(r *http.Request) (bool, error) {
	if token, err := authaus.HttpHandlerPrelude(&x.Config.HTTP, x.Central, r); err == nil {
		if pbits, egroup := authaus.PermitResolveToList(token.Permit.Roles, x.Central.GetRoleGroupDB()); egroup == nil {
			return pbits.Has(PermAdmin), nil
		} else {
			return false, egroup
		}
	} else {
		return false, err
	}
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
	//central.Central.Log.Printf("Number of identities %v\n", len(permits))

	emptyPermit := authaus.Permit{}

	jresponse := make(map[string]*userGroupsResponseJson)
	for _, identity := range identities {
		permit := ident2perm[identity]
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

// Handle the 'login' request, sending back a session token (via Set-Cookie),
func httpHandlerLogin(central *ImqsCentral, w http.ResponseWriter, r *http.Request) {
	identity, password, eBasic := authaus.HttpReadBasicAuth(r)
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
					Name:    central.Config.HTTP.CookieName,
					Value:   sessionkey,
					Path:    "/",
					Expires: token.Expires,
					Secure:  central.Config.HTTP.CookieSecure,
				}
				http.SetCookie(w, cookie)
				httpSendCheckJson(w, token, permList)
			}
		}
	}
}

// Note that we do not create a permit here for the user, so he will not yet be able to login.
// In order to finish the job, you will need to call httpHandlerSetUserGroups which will
// create a permit for this user.
func httpHandlerCreateUser(central *ImqsCentral, w http.ResponseWriter, r *http.Request) {
	identity := strings.TrimSpace(r.URL.Query().Get("identity"))
	password := strings.TrimSpace(r.URL.Query().Get("password"))
	if err := central.Central.CreateAuthenticatorIdentity(identity, password); err != nil {
		authaus.HttpSendTxt(w, http.StatusForbidden, err.Error())
	} else {
		authaus.HttpSendTxt(w, http.StatusOK, "Created identity '"+identity+"'")
	}
}

func httpHandlerSetUserGroups(central *ImqsCentral, w http.ResponseWriter, r *http.Request) {
	defer func() {
		if ex := recover(); ex != nil {
			str, isStr := ex.(string)
			if !isStr {
				str = ex.(error).Error()
			}
			authaus.HttpSendTxt(w, http.StatusForbidden, str)
		}
	}()

	identity := strings.TrimSpace(r.URL.Query().Get("identity"))
	groupsParam := strings.TrimSpace(r.URL.Query().Get("groups"))

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
	authaus.HttpSendTxt(w, http.StatusOK, "'"+identity+"' groups set to ("+summary+")")
}

func httpHandlerCheck(central *ImqsCentral, w http.ResponseWriter, r *http.Request) {
	if token, err := authaus.HttpHandlerPreludeWithError(&central.Config.HTTP, central.Central, w, r); err == nil {
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

func httpHandlerGetUsers(central *ImqsCentral, w http.ResponseWriter, r *http.Request) {
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

func httpHandlerGetGroups(central *ImqsCentral, w http.ResponseWriter, r *http.Request) {
	if groups, err := central.Central.GetRoleGroupDB().GetGroups(); err != nil {
		authaus.HttpSendTxt(w, http.StatusInternalServerError, err.Error())
	} else {
		httpSendGroupsJson(w, groups)
	}
}
