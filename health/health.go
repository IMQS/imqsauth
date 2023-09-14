package health

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	"github.com/IMQS/authaus"
	auth "github.com/IMQS/imqsauth/auth"
)

const unArchivedWithoutPermit = "nrUnarchivedWithoutPermit"
const archived = "nrArchived"
const enabled = "nrEnabled"
const admin = "nrAdmin"

type enabledTotal struct {
	enabled int
	total   int
}

func Check(ic *auth.ImqsCentral) bool {
	db := ic.Central.GetRoleGroupDB()
	sb := strings.Builder{}
	w := tabwriter.NewWriter(&sb, 0, 8, 1, '\t', tabwriter.AlignRight)
	errorSet := map[string]error{}
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "Health Check\n")
	fmt.Fprintf(w, "------------\n")

	// General info
	// ------------

	// Migration version
	v, eTokens := authaus.GetMigrationVersion(&ic.Config.Authaus.DB)
	if eTokens != nil {
		fmt.Fprintf(w, "Could not read migration version...\n%v\n", eTokens)
	} else {
		fmt.Fprintf(w, "Migration version:\t%v\n", v)
	}

	// Groups
	groups, err := db.GetGroups()
	if err == nil {
		fmt.Fprintf(w, "Total nr of groups:\t%v\n", len(groups))
	} else {
		fmt.Fprintf(w, "Total nr of groups:\t%v\n", err)
	}

	// Users
	users, errIdentities := ic.Central.GetAuthenticatorIdentities(authaus.GetIdentitiesFlagDeleted)
	if errIdentities == nil {
		fmt.Fprintf(w, "Total nr of users:\t%v\n", len(users))
	} else {
		fmt.Fprintf(w, "Total nr of users:\t%v\n", errIdentities)
	}

	// Non-archived users without sessions
	tokens, eTokens := ic.Central.GetAllTokens(false)
	if eTokens == nil {
		fmt.Fprintf(w, "Active auth session tokens retrieved:\t%v\n", len(tokens))
	} else {
		fmt.Fprintf(w, "Could not retrieve auth session tokens:\t%v\n", eTokens)
	}

	oAuthTokenIDs, eOAuthTokens := ic.Central.GetAllOAuthTokenIDs()
	if eOAuthTokens == nil {
		fmt.Fprintf(w, "OAuth session tokens retrieved:\t%v\n", len(oAuthTokenIDs))
		// detect any missing oauth sessions
		if eTokens == nil {
			nrSessionsWithOrphanedOAuthIds := findMissingOAuthTokens(oAuthTokenIDs, tokens)
			fmt.Fprintf(w, "Nr of sessions with orphaned OAuth IDs:\t%v\n", nrSessionsWithOrphanedOAuthIds)
		} else {
			fmt.Fprintf(w, "Could not determine missing oauth tokens (auth sessions not available)\n")
		}
	} else {
		fmt.Fprintf(w, "Could not retrieve oauth tokens from session db:\t%v\n", eTokens)
	}

	var missingGroups map[authaus.GroupIDU32][]authaus.UserId
	var groupKeys []authaus.GroupIDU32
	useIdentities := errIdentities == nil && len(users) > 0
	if useIdentities {
		stats := initUserStats()
		typeCounts := initTypeCounts()

		errPerms2 := false
		missingGroups, errPerms2, _ = getUserStats(ic, users, stats, typeCounts, errorSet)
		errFlag := ""
		if errPerms2 {
			errFlag = "*"
		}
		fmt.Fprintf(w, "Nr of enabled users:\t%v%v\n", stats[enabled], errFlag)
		fmt.Fprintf(w, "Nr of admin users:\t%v%v\n", stats[admin], errFlag)
		fmt.Fprintf(w, "Nr of archived users:\t%v\n", stats[archived])
		fmt.Fprintf(w, "* - indicates possibly inaccurate values.\n")

		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, "User type counts (archived):\n")
		typeKeys := maps.Keys(typeCounts)
		slices.SortFunc(typeKeys, func(a authaus.AuthUserType, b authaus.AuthUserType) int { return int(a) - int(b) })
		for _, v := range typeKeys {
			fmt.Fprintf(w, "\tType %v(%v):\t%v\t(%v)\n", authaus.AuthUserTypeStrings[v], v, typeCounts[v].enabled, typeCounts[v].total)
		}

		// Error checks
		// ------------

		// Permits check
		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, "Permits:\n")
		plist, err := ic.Central.GetPermits()
		if err != nil {
			errorSet[err.Error()] = err
			fmt.Fprintf(w, "\tPermit list ERROR\n")
		} else {
			fmt.Fprintf(w, "\tPermit list ok:\t%v permits\n", len(plist))
			fmt.Fprintf(w, "\t*Nr of non-archived users without permits:\t%v\n", stats[unArchivedWithoutPermit])
			fmt.Fprintf(w, "\t*Nr of archived users without permits:\t%v\n", len(users)-len(plist)-stats[unArchivedWithoutPermit])
		}

		// Non-existent groups
		fmt.Fprintf(w, "\n")
		if len(missingGroups) > 0 {
			fmt.Fprintf(w, "Missing groups:\n")
		} else {
			fmt.Fprintf(w, "Missing groups:\n\tNone\n")
		}

		groupKeys = maps.Keys(missingGroups)
		slices.SortFunc(groupKeys, func(a authaus.GroupIDU32, b authaus.GroupIDU32) int { return int(a) - int(b) })
		for _, v := range groupKeys {
			slices.SortFunc(missingGroups[v], func(a authaus.UserId, b authaus.UserId) int { return int(a) - int(b) })
			fmt.Fprintf(w, "\tGroup missing:\t%v\tUsers: %v\n", v, missingGroups[v])
		}
	} else {
		fmt.Fprintf(w, "*Errors retrieving users, type statistics not calculated.\n")
	}
	// Errors
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Group errors (explicit only - review the missing group list for all missing groups)")
	fmt.Fprintln(w, "------")

	errKeys := maps.Keys(errorSet)
	sort.Strings(errKeys)

	if len(errKeys) > 0 {
		for _, e := range errKeys {
			fmt.Fprintf(w, "%v\n", errorSet[e])
		}
	} else {
		fmt.Fprintf(w, "No errors\n")
	}

	// FINAL HEALTHCHECK OUTPUT
	w.Flush()
	fmt.Print(sb.String())
	return true
}

func initUserStats() map[string]int {
	stats := map[string]int{}
	stats[enabled] = 0
	stats[admin] = 0
	stats[archived] = 0
	stats[unArchivedWithoutPermit] = 0
	return stats
}

func initTypeCounts() map[authaus.AuthUserType]*enabledTotal {
	typeCounts := map[authaus.AuthUserType]*enabledTotal{
		authaus.UserTypeDefault: {0, 0},
		authaus.UserTypeLDAP:    {0, 0},
		authaus.UserTypeOAuth:   {0, 0},
		authaus.UserTypeMSAAD:   {0, 0},
	}
	return typeCounts
}

func FixDB(ic *auth.ImqsCentral) bool {
	users, errIdentities := ic.Central.GetAuthenticatorIdentities(authaus.GetIdentitiesFlagDeleted)
	if errIdentities != nil {
		if len(users) == 0 {
			fmt.Printf("Error retrieving any users, fixdb cancelled: %v\n", errIdentities)
			return false
		} else {
			fmt.Printf("Error retrieving some users, continuing with fixdb: %v\n", errIdentities)
		}
	}
	stats := initUserStats()
	typeCounts := initTypeCounts()
	errorSet := map[string]error{}

	missingGroups, _, err := getUserStats(ic, users, stats, typeCounts, errorSet)
	if err != nil {
		fmt.Printf("Error retrieving missing groups: %v\n", err)
		if len(missingGroups) == 0 {
			fmt.Printf("No missing groups found, fixdb cancelled.\n")
			return false
		} else {
			fmt.Printf("Some missing groups found, continuing with fixdb.\n")
		}
	}

	fmt.Printf("Cleaning missing groups...\n")
	if missingGroups != nil {
		groupKeys := maps.Keys(missingGroups)
		slices.SortFunc(groupKeys, func(a authaus.GroupIDU32, b authaus.GroupIDU32) int { return int(a) - int(b) })
		for _, v := range groupKeys {
			err := ic.Central.RemoveGroupFromAllUsers(strconv.Itoa(int(v)))
			if err != nil {
				fmt.Printf("Error cleaning group %v: %v\n", v, err)
			}
		}
	}
	return true
}

func findMissingOAuthTokens(oAuthTokenIDs []string, tokens []*authaus.Token) int {
	oAuthIDs := map[string]struct{}{}
	nrSessionsWithOrphanedOAuthIds := 0
	for _, t := range oAuthTokenIDs {
		if t != "" {
			oAuthIDs[t] = struct{}{}
		}
	}

	for _, t := range tokens {
		if t.OAuthSessionID != "" {
			if _, ok := oAuthIDs[t.OAuthSessionID]; !ok {
				nrSessionsWithOrphanedOAuthIds++
			}
		}
	}
	return nrSessionsWithOrphanedOAuthIds
}

func getUserStats(ic *auth.ImqsCentral, users []authaus.AuthUser, stats map[string]int, typeCounts map[authaus.AuthUserType]*enabledTotal, errorSet map[string]error) (map[authaus.GroupIDU32][]authaus.UserId, bool, error) {
	var err error
	errPerms := false
	missingGroups := map[authaus.GroupIDU32][]authaus.UserId{}
	for _, u := range users {
		p, _ := ic.Central.GetPermit(u.UserId)

		if u.Archived {
			stats[archived]++
		}

		if p == nil && !u.Archived {
			stats[unArchivedWithoutPermit]++
		}

		typeCounts[u.Type].total++
		if perm, ePerm := ic.Central.GetPermit(u.UserId); ePerm == nil {
			// cycle through permit and check if group exists
			groupIds, _ := authaus.DecodePermit(perm.Roles)
			for _, r := range groupIds {
				if _, err := ic.Central.GetRoleGroupDB().GetByID(r); err != nil {
					missingGroups[r] = append(missingGroups[r], u.UserId)
				}

			}
			pbits, eGroup := authaus.PermitResolveToList(perm.Roles, ic.Central.GetRoleGroupDB())
			if pbits != nil {
				if eGroup != nil {
					errPerms = true
					errorSet[eGroup.Error()] = eGroup
				}
				if pbits.Has(auth.PermEnabled) {
					stats[enabled]++
					typeCounts[u.Type].enabled++
				}
				if pbits.Has(auth.PermAdmin) {
					stats[admin]++
				}
			} else {
				errPerms = true
			}
		} else {
			err = ePerm
		}
	}
	return missingGroups, errPerms, err
}
