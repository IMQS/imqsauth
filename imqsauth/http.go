package imqsauth

import (
	"encoding/json"
	"fmt"
	"github.com/IMQS/authaus"
	"net/http"
	"strconv"
	"strings"
	//"sync/atomic"
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

type ImqsCentral struct {
	Config  *authaus.Config
	Central *authaus.Central
	//StopSignal uint32
}

const (
	msgAccountDisabled = "Account disabled"
)

type HttpMethod string

const (
	HttpMethodGet  HttpMethod = "GET"
	HttpMethodPost            = "POST"
	HttpMethodPut             = "PUT"
)

func (x *ImqsCentral) RunHttp() error {

	// The built-in go ServeMux does not support differentiating based on HTTP verb, so we have to make
	// the request path unique for each verb. I think this is OK as far as API design is concerned - at least in this domain.
	makehandler := func(method HttpMethod, actual func(*ImqsCentral, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != string(method) {
				authaus.HttpSendTxt(w, http.StatusBadRequest, fmt.Sprintf("API must be accessed using an HTTP %v method", method))
			} else {
				actual(x, w, r)
			}
		}
	}

	smux := http.NewServeMux()
	smux.HandleFunc("/login", makehandler(HttpMethodPost, HttpHandlerLogin))
	smux.HandleFunc("/check", makehandler(HttpMethodGet, HttpHandlerCheck))

	// Do not expose this until we have planned the API better. The use case for this class of functionality
	// is an 'admin' web app that allows you to administer permission groups etc.
	//smux.HandleFunc("/setuser", makehandler(HttpMethodPut, HttpHandlerSetUser))

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
	// unreachable
	return nil
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
	// unreachable
	return false, nil
}

// Handle the 'login' request, sending back a session token (via Set-Cookie),
func HttpHandlerLogin(central *ImqsCentral, w http.ResponseWriter, r *http.Request) {
	identity, password, eBasic := authaus.HttpReadBasicAuth(r)
	if eBasic != nil {
		authaus.HttpSendTxt(w, http.StatusBadRequest, eBasic.Error())
		return
	}

	if sessionkey, token, err := central.Central.Login(identity, password); err != nil {
		authaus.HttpSendTxt(w, http.StatusForbidden, err.Error())
	} else {
		if pbits, egroup := authaus.PermitResolveToList(token.Permit.Roles, central.Central.GetRoleGroupDB()); egroup != nil {
			authaus.HttpSendTxt(w, http.StatusInternalServerError, egroup.Error())
		} else {
			// Ensure that the user has the 'Enabled' permission
			if !pbits.Has(PermEnabled) {
				authaus.HttpSendTxt(w, http.StatusForbidden, msgAccountDisabled)
			} else {
				cookie := &http.Cookie{
					Name:    central.Config.HTTP.CookieName,
					Value:   sessionkey,
					Path:    "/",
					Expires: token.Expires,
					Secure:  central.Config.HTTP.CookieSecure,
				}
				http.SetCookie(w, cookie)
				w.WriteHeader(http.StatusOK)
			}
		}
	}
}

func HttpHandlerCheck(central *ImqsCentral, w http.ResponseWriter, r *http.Request) {
	if token, err := authaus.HttpHandlerPreludeWithError(&central.Config.HTTP, central.Central, w, r); err == nil {
		if permList, egroup := authaus.PermitResolveToList(token.Permit.Roles, central.Central.GetRoleGroupDB()); egroup != nil {
			authaus.HttpSendTxt(w, http.StatusInternalServerError, egroup.Error())
		} else {
			// Ensure that the user has the 'Enabled' permission
			if !permList.Has(PermEnabled) {
				authaus.HttpSendTxt(w, http.StatusForbidden, msgAccountDisabled)
			} else {
				jresponse := &checkResponseJson{}
				jresponse.Identity = token.Identity
				jresponse.SetRoles(permList)
				json, jsonErr := json.Marshal(jresponse)
				if jsonErr == nil {
					w.WriteHeader(http.StatusOK)
					w.Header().Add("Content-Type", "application/json")
					w.Write(json)
				} else {
					authaus.HttpSendTxt(w, http.StatusInternalServerError, jsonErr.Error())
				}
				//fmt.Fprintf(w, "%v", encodePermBitsToString(permList))
				//fmt.Fprintf(w, "%v", hex.EncodeToString(token.Permit.Roles))
			}
		}
	}
}

// This is a Work In Progress, so it is not currently exposed
func HttpHandlerSetUser(central *ImqsCentral, w http.ResponseWriter, r *http.Request) {
	defer func() {
		if ex := recover(); ex == nil {
			w.WriteHeader(http.StatusOK)
		} else {
			str, isStr := ex.(string)
			if !isStr {
				str = ex.(error).Error()
			}
			authaus.HttpSendTxt(w, http.StatusForbidden, str)
		}
	}()

	if isAdmin, err := central.IsAdmin(r); err != nil {
		panic(err)
	} else if !isAdmin {
		panic("You are not authorized to make this change")
	}

	authc := central.Central
	create := strings.TrimSpace(r.URL.Query().Get("create"))
	identity := strings.TrimSpace(r.URL.Query().Get("identity"))
	password := strings.TrimSpace(r.URL.Query().Get("password"))
	groups := strings.Split(strings.TrimSpace(r.URL.Query().Get("groups")), ",")
	// strings.Split() will always yield at least 1 object, even if that's just an empty string
	if len(groups) == 1 && groups[0] == "" {
		groups = make([]string, 0)
	}
	groupIDs, errGroupIDs := authaus.GroupNamesToIDs(groups, central.Central.GetRoleGroupDB())
	if errGroupIDs != nil {
		panic("Invalid groups: " + errGroupIDs.Error())
	}
	if identity == "" {
		panic("Identity is empty")
	}
	if create == "1" {
		if password == "" {
			panic("Password is empty")
		}
		if eCreate := authc.CreateAuthenticatorIdentity(identity, password); eCreate != nil {
			panic(eCreate)
		}
	} else {
		if ePassword := authc.SetPassword(identity, password); ePassword != nil {
			panic(ePassword)
		}
	}
	// WARNING: What if the administrator wants to make this user a member of no groups?
	if len(groups) != 0 {
		permit := &authaus.Permit{}
		permit.Roles = authaus.EncodePermit(groupIDs)
		if eSetPermit := authc.SetPermit(identity, permit); eSetPermit != nil {
			panic(eSetPermit)
		}
	}
}
