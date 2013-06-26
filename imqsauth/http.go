package imqsauth

import (
	"encoding/json"
	"fmt"
	"github.com/IMQS/authaus"
	"net/http"
	"strconv"
	"strings"
)

// IMQS permission bits (each number in the range 0..65535 means something)
const (
	PermReservedZero authaus.PermissionU16 = 0 // Avoid the danger of having a zero mean something
	PermAdmin        authaus.PermissionU16 = 1 // Super-user who can control all aspects of the auth system
	PermEnabled      authaus.PermissionU16 = 2 // User is allowed to use the system. Without this no request is authorized
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
}

func (x *ImqsCentral) runHttpInternal() error {
	makehandler := func(actual func(*ImqsCentral, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			actual(x, w, r)
		}
	}
	//makehandlerAuthaus := func(actual func(*authaus.ConfigHTTP, *authaus.Central, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	//	return func(w http.ResponseWriter, r *http.Request) {
	//		actual(&x.Config.HTTP, x.Central, w, r)
	//	}
	//}
	//http.HandleFunc("/whoami", makehandlerAuthaus(authaus.HttpHandlerWhoAmI))
	//http.HandleFunc("/initialize", makehandler(HttpHandlerInitialize))

	http.HandleFunc("/login", makehandler(HttpHandlerLogin))
	http.HandleFunc("/check", makehandler(HttpHandlerCheck))
	http.HandleFunc("/setuser", makehandler(HttpHandlerSetUser))

	x.Central.Log.Printf("ImqsAuth is listening on %v:%v\n", x.Config.HTTP.Bind, x.Config.HTTP.Port)
	if err := http.ListenAndServe(x.Config.HTTP.Bind+":"+strconv.Itoa(x.Config.HTTP.Port), nil); err != nil {
		return err
	}

	return nil
}

func (x *ImqsCentral) RunHttp() error {
	var err error
	if x.Central, err = authaus.NewCentralFromConfig(x.Config); err != nil {
		return err
	} else {
		err := x.runHttpInternal()
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

//func HttpHandlerInitialize(central *ImqsCentral, w http.ResponseWriter, r *http.Request) {
//}

// Handle the 'login' request, sending back a session token (via Set-Cookie),
func HttpHandlerLogin(central *ImqsCentral, w http.ResponseWriter, r *http.Request) {
	identity := r.URL.Query().Get("identity")
	password := r.URL.Query().Get("password")
	if sessionkey, token, err := central.Central.Login(identity, password); err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Header().Add("Content-Type", "text/plain")
		fmt.Fprintf(w, "%v", err)
	} else {
		if pbits, egroup := authaus.PermitResolveToList(token.Permit.Roles, central.Central.GetRoleGroupDB()); egroup != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "Internal Error: %v", egroup)
		} else {
			// Ensure that the user has the 'Login' role
			if !pbits.Has(PermEnabled) {
				w.WriteHeader(http.StatusForbidden)
				w.Header().Add("Content-Type", "text/plain")
				fmt.Fprintf(w, "Login not allowed")
			} else {
				// TODO: Set Cookie's "Secure: true" when appropriate
				// It should actually be hard to send a cookie with Secure: false.
				// One way might be to use r.TLS, but I haven't tested that yet.
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
			w.WriteHeader(http.StatusInternalServerError)
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "Error: %v", egroup)
		} else {
			if !permList.Has(PermEnabled) {
				w.WriteHeader(http.StatusForbidden)
				w.Header().Add("Content-Type", "text/plain")
				fmt.Fprintf(w, "Account disabled")
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
					w.WriteHeader(http.StatusInternalServerError)
					w.Header().Set("Content-Type", "text/plain")
					fmt.Fprintf(w, "Error: %v", jsonErr)
				}
				//fmt.Fprintf(w, "%v", encodePermBitsToString(permList))
				//fmt.Fprintf(w, "%v", hex.EncodeToString(token.Permit.Roles))
			}
		}
	}
}

// This is a Work In Progress
func HttpHandlerSetUser(central *ImqsCentral, w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err == nil {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "text/plain")
			fmt.Fprintf(w, "%v", err)
		}
	}()

	if isAdmin, err := central.IsAdmin(r); err != nil {
		panic(err.Error())
	} else if !isAdmin {
		panic("Not authorized")
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
			panic(eCreate.Error())
		}
	} else {
		if ePassword := authc.SetPassword(identity, password); ePassword != nil {
			panic(ePassword.Error())
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
