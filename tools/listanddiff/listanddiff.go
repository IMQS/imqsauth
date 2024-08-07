package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
)

type PermissionU16 uint16
type PermissionList []PermissionU16
type Permissions struct {
	Permissions struct {
		Dynamic []struct {
			Id          string `json:"id"`
			Name        string `json:"name"`
			Friendly    string `json:"friendly"`
			Description string `json:"description"`
			Module      string `json:"module"`
		} `json:"dynamic"`
		Disable []string `json:"disable"`
	} `json:"Permissions"`
}

type AuthPermsLight map[string]string

type GroupItem struct {
	ID       int    `json:"ID"`
	Name     string `json:"Name"`
	PermList string `json:"PermList"`
}
type Group struct {
	Groups []GroupItem `json:"Groups"`
}

type AuthClean struct {
	Source string
	Groups []*GroupClean
}
type GroupClean struct {
	Name     string
	PermList PermissionList
}

func main() {
	//load auth permissions configuration
	e, permsMap := loadImqsAuth("imqsauth.json")
	if e != nil {
		fmt.Printf("Error: %v\n", e)
		os.Exit(1)
	}
	e, permsMap2 := loadImqsAuth("imqsauth2.json")
	if e != nil {
		fmt.Printf("Error: %v\n", e)
		os.Exit(1)
	}

	// merge the two permission maps
	for k, v := range permsMap2 {
		if _, ok := permsMap[k]; !ok {
			permsMap[k] = v
		}
	}

	// load endpoint-retrieved perms maps if available
	permsLight, er := LoadAuthMap("authmap.json")
	if er != nil {
		fmt.Printf("Error: %v\n", e)
		os.Exit(1)
	}

	permsLight2, er := LoadAuthMap("authmap2.json")
	if er != nil {
		fmt.Printf("Error: %v\n", e)
		os.Exit(1)
	}

	// merge the two permission maps
	for k, v := range permsLight2 {
		if _, ok := permsLight[k]; !ok {
			permsLight[k] = v
		}
	}

	for k, v := range permsLight {
		i, e := strconv.Atoi(k)
		if e != nil {
			fmt.Printf("Error converting %s to int: %v\n", k, e)
			continue
		}
		if _, ok := permsMap[i]; !ok {
			permsMap[i] = v
		}
	}
	if len(os.Args) < 2 {
		os.Exit(1)
	}

	// parse authgroup input files
	startFileNr := 1
	endFileNr := len(os.Args) - 1
	allFilesGroups := make(map[string]*AuthClean)
	//var groupCleanList []*GroupClean
	for i := startFileNr; i <= endFileNr; i++ {
		filename := os.Args[i]
		g := parseFile(filename)
		printGroups(g, filename, permsMap)
		a := &AuthClean{
			Source: filename,
			Groups: g,
		}
		allFilesGroups[filename] = a
		fmt.Printf("Found %v groups for %s\n", len(g), filename)
	}

	// compare auth groups
	sb := strings.Builder{}
	fmt.Fprintf(&sb, "%s", "GroupName, PermissionId, PermissionName, Comment\n")
	for i := startFileNr; i <= endFileNr; i++ {
		for j := i; j <= endFileNr; j++ {
			if i != j {
				fileNameSource := os.Args[i]
				fileNameTarget := os.Args[j]
				e := compareGroups(&sb, allFilesGroups[fileNameSource], allFilesGroups[fileNameTarget], permsMap)
				if e != nil {
					fmt.Printf("Error: %v\n", e)
					os.Exit(1)
				}
			}
		}
	}
	e = os.WriteFile("output.csv", []byte(sb.String()), 0666)
	if e != nil {
		fmt.Printf("Error: %v\n", e)
	}
}

func LoadAuthMap(name string) (AuthPermsLight, error) {
	fPermsLight, e := os.ReadFile(name)
	if e != nil {
		fmt.Printf("Error: %v\n", e)
		return nil, e
	}
	permsLight := AuthPermsLight{}
	err := json.Unmarshal(fPermsLight, &permsLight)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return nil, err
	}
	return permsLight, nil
}

func loadImqsAuth(name string) (error, map[int]string) {
	fPerm, e := os.ReadFile(name)
	if e != nil {
		fmt.Printf("Error: %v\n", e)
		return e, nil
	}
	perms := Permissions{}
	err := json.Unmarshal(fPerm, &perms)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return err, nil
	}

	permsMap := make(map[int]string)
	for _, p := range perms.Permissions.Dynamic {
		id, e := strconv.Atoi(p.Id)
		if e != nil {
			fmt.Printf("Error converting %s to int: %v\n", p.Id, e)
		}
		permsMap[id] = p.Name
	}
	return e, permsMap
}

func compareGroups(w *strings.Builder, sourceAuth *AuthClean, targetAuth *AuthClean, permsMap map[int]string) error {
	for _, g := range sourceAuth.Groups {
		found := false
		for _, g2 := range targetAuth.Groups {
			if g.Name == g2.Name {
				found = true
				e := comparePermissions(w, targetAuth.Source, sourceAuth.Source, g.Name, g.PermList, g2.PermList, permsMap)
				if e != nil {
					return e
				}
				e = comparePermissions(w, sourceAuth.Source, targetAuth.Source, g2.Name, g2.PermList, g.PermList, permsMap)
				if e != nil {
					return e
				}
			}
		}
		if !found {
			e := printDiffLine(w, g.Name, 0, "", fmt.Sprintf("Group not found in %s (from %s)\n", targetAuth.Source, sourceAuth.Source))
			if e != nil {
				return e
			}
		}
	}

	//now only do missing in group1 from group2
	for _, g := range targetAuth.Groups {
		found := false
		for _, g2 := range sourceAuth.Groups {
			if g.Name == g2.Name {
				found = true
				break
			}
		}
		if !found {
			e := printDiffLine(w, g.Name, 0, "", fmt.Sprintf("Group not found in %s (from %s)\n", sourceAuth.Source, targetAuth.Source))
			if e != nil {
				return e
			}
		}
	}
	return nil
}

func comparePermissions(w *strings.Builder, targetName string, sourceName string, groupName string, sourceList PermissionList, targetList PermissionList, permsMap map[int]string) error {
	for _, p := range sourceList {
		found := false
		for j := 0; j < len(targetList); j++ {
			if p == targetList[j] {
				found = true
				break
			}

		}
		if !found {
			e := printDiffLine(w, groupName, int(p), permsMap[int(p)], fmt.Sprintf("Not found in %s (from %s)\n", targetName, sourceName))
			if e != nil {
				return e
			}
		}
	}
	return nil
}

func printDiffLine(w *strings.Builder, groupName string, permissionNr int, PermissionName string, s string) error {
	_, e := fmt.Fprintf(w, "%v,%v,%v,%v", groupName, permissionNr, PermissionName, s)
	return e
}
func parseFile(tempFilename string) []*GroupClean {
	var groupCleanList []*GroupClean
	filename := tempFilename
	f, e := os.OpenFile(filename, os.O_RDONLY, 0)
	defer f.Close()

	if e != nil {
		fmt.Printf("Error: %v\n", e)
		os.Exit(1)
	}

	r := bufio.NewReader(f)
	rAll, e := io.ReadAll(r)
	if e != nil {
		fmt.Printf("Error: %v\n", e)
		os.Exit(1)
	}
	groupList := Group{}

	err := json.Unmarshal(rAll, &groupList)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	var fileStrings []string

	for _, group := range groupList.Groups {
		groupClean := GroupClean{
			Name: group.Name,
		}
		dec, e := parsePermListBase64(group.PermList)
		if e != nil {
			fmt.Printf("Error: %v\n", e)
			continue
		}
		sort.Slice(dec, func(i, j int) bool { return dec[i] < dec[j] })
		groupClean.PermList = dec
		groupCleanList = append(groupCleanList, &groupClean)
	}
	sort.Strings(fileStrings)

	sort.Slice(groupCleanList, func(i, j int) bool { return groupCleanList[i].Name < groupCleanList[j].Name })
	return groupCleanList
}

func printGroups(clean []*GroupClean, filename string, permsMap map[int]string) {
	// output to csv
	fw, e := os.OpenFile(strings.Replace(filename, ".json", ".csv", 1), os.O_CREATE|os.O_WRONLY, 0666)
	defer fw.Close()
	if e != nil {
		fmt.Printf("Error: %v\n", e)
		os.Exit(1)
	}

	w := bufio.NewWriter(fw)
	defer w.Flush()
	for _, s := range clean {
		for _, p := range s.PermList {
			fmt.Fprintf(w, "%s,%s,%v\n", s.Name, permsMap[int(p)], p)
		}
	}
}

func parsePermListBase64(bitsB64 string) (PermissionList, error) {
	if bytes, errB64 := base64.StdEncoding.DecodeString(bitsB64); errB64 == nil {
		permList := make(PermissionList, 0)
		if len(bytes)%2 != 0 {
			return nil, errors.New("len(authgroup.permlist) mod 2 != 0")
		}
		for i := 0; i < len(bytes); i += 2 {
			permList = append(permList, PermissionU16(bytes[i])<<8|PermissionU16(bytes[i+1]))
		}
		return permList, nil
	} else {
		return nil, errB64
	}
}
