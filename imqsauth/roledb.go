package imqsauth

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/IMQS/authaus"
	_ "github.com/bmizerany/pq"
	"sync"
)

var (
	ErrGroupNotExist = errors.New("Group does not exist")
	ErrGroupExists   = errors.New("Group already exists")
	ErrPermitInvalid = errors.New("Permit is not a sequence of 32-bit words")
)

// Any permission in the system is uniquely described by a 16-bit unsigned integer
type PermissionU16 uint16

// List of permissions
type PermissionList []PermissionU16

func (x PermissionList) Has(perm PermissionU16) bool {
	for _, bit := range x {
		if bit == perm {
			return true
		}
	}
	return false
}

// Our group IDs are unsigned 32-bit integers
type GroupIDU32 uint32

// This should possibly be moved into the core of authaus.
type RoleGroupDB interface {
	GetByName(name string) (*AuthGroup, error)
	GetByID(id GroupIDU32) (*AuthGroup, error)
	InsertGroup(group *AuthGroup) error
	UpdateGroup(group *AuthGroup) error
	Close()
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type AuthGroup struct {
	ID       GroupIDU32     // DB-generated id
	Name     string         // Administrators need this name to keep sense of things
	PermBits PermissionList // Application-defined permission bits (ie every value from 0..65535 pertains to one particular permission)
}

func (x *AuthGroup) encodePermBits() string {
	return base64.StdEncoding.EncodeToString(encodePermBits(x.PermBits))
}

func (x AuthGroup) Clone() *AuthGroup {
	clone := &AuthGroup{}
	*clone = x
	clone.PermBits = make(PermissionList, len(x.PermBits))
	copy(clone.PermBits, x.PermBits)
	return clone
}

func (x *AuthGroup) AddPermBit(permBit PermissionU16) {
	for _, bit := range x.PermBits {
		if bit == permBit {
			return
		}
	}
	x.PermBits = append(x.PermBits, permBit)
}

func (x *AuthGroup) RemovePermBit(permBit PermissionU16) {
	for index, bit := range x.PermBits {
		if bit == permBit {
			x.PermBits = append(x.PermBits[0:index], x.PermBits[index+1:]...)
			return
		}
	}
}

func (x *AuthGroup) HasBit(permBit PermissionU16) bool {
	for _, bit := range x.PermBits {
		if bit == permBit {
			return true
		}
	}
	return false
}

// Encodes a list of Group IDs into a Permit
func EncodePermit(groupIds []GroupIDU32) []byte {
	res := make([]byte, len(groupIds)*4)
	for i := 0; i < len(groupIds); i++ {
		res[i*4] = byte((groupIds[i] >> 24) & 0xff)
		res[i*4+1] = byte((groupIds[i] >> 16) & 0xff)
		res[i*4+2] = byte((groupIds[i] >> 8) & 0xff)
		res[i*4+3] = byte(groupIds[i] & 0xff)
	}
	return res
}

// Decodes a Permit into a list of Group IDs
func DecodePermit(permit []byte) ([]GroupIDU32, error) {
	if len(permit)%4 != 0 {
		return nil, ErrPermitInvalid
	}
	groups := make([]GroupIDU32, len(permit)/4)
	for i := 0; i < len(permit); i += 4 {
		groups[i>>2] = 0 |
			GroupIDU32(permit[i])<<24 |
			GroupIDU32(permit[i+1])<<16 |
			GroupIDU32(permit[i+2])<<8 |
			GroupIDU32(permit[i+3])
		//fmt.Printf("Groups[%v] = %v\n", i>>2, groups[i>>2])
	}
	return groups, nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type sqlGroupDB struct {
	db *sql.DB
}

// This goes from Permit -> Groups -> PermBits
// Permit has 0..n Groups
// Group has 0..n PermBits
// We produce a list of all unique PermBits that appear in any
// of the groups inside this permit. You can think of this as a binary OR operation.
func PermitResolveToList(permit []byte, db RoleGroupDB) (PermissionList, error) {
	bits := make(map[PermissionU16]bool, 0)
	if groupIDs, err := DecodePermit(permit); err == nil {
		for _, gid := range groupIDs {
			if group, egroup := db.GetByID(gid); egroup != nil {
				return nil, egroup
			} else {
				for _, bit := range group.PermBits {
					bits[bit] = true
				}
			}
		}
		list := make(PermissionList, 0)
		for bit, _ := range bits {
			list = append(list, bit)
		}
		return list, nil
	} else {
		return nil, err
	}
	// unreachable
	return nil, nil
}

// Converts group names to group IDs.
// From here you can use EncodePermit to get a blob that is ready for use
// as authaus.Permit.Roles
func GroupNamesToIDs(groups []string, db RoleGroupDB) ([]GroupIDU32, error) {
	ids := make([]GroupIDU32, len(groups))
	for i, gname := range groups {
		if group, err := db.GetByName(gname); err != nil {
			return nil, err
		} else {
			ids[i] = group.ID
		}
	}
	return ids, nil
}

func encodePermBits(permbits PermissionList) []byte {
	res := make([]byte, len(permbits)*2)
	for i := 0; i < len(permbits); i++ {
		res[i*2] = byte(permbits[i] >> 8)
		res[i*2+1] = byte(permbits[i])
	}
	return res
}

func readSingleGroup(row *sql.Row, errDetail string) (*AuthGroup, error) {
	group := &AuthGroup{}
	bitsb64 := ""
	if err := row.Scan(&group.ID, &group.Name, &bitsb64); err == nil {
		if bytes, e64 := base64.StdEncoding.DecodeString(bitsb64); e64 == nil {
			if len(bytes)%2 != 0 {
				return nil, errors.New("len(authgroup.permbits) mod 2 != 0")
			}
			for i := 0; i < len(bytes); i += 2 {
				group.PermBits = append(group.PermBits, PermissionU16(bytes[i])<<8|PermissionU16(bytes[i+1]))
			}
			return group, nil
		} else {
			return nil, e64
		}
	} else {
		if err == sql.ErrNoRows {
			return nil, errors.New(ErrGroupNotExist.Error() + ": " + errDetail)
		}
		return nil, err
	}
	// unreachable
	return nil, nil
}

func (x *sqlGroupDB) GetByName(name string) (*AuthGroup, error) {
	//fmt.Printf("Reading group %v\n", name)
	return readSingleGroup(x.db.QueryRow("SELECT id,name,permbits FROM authgroup WHERE name = $1", name), name)
}

func (x *sqlGroupDB) GetByID(id GroupIDU32) (*AuthGroup, error) {
	//fmt.Printf("Reading group %v\n", id)
	return readSingleGroup(x.db.QueryRow("SELECT id,name,permbits FROM authgroup WHERE id = $1", id), fmt.Sprintf("%v", id))
}

// Add a new group. If the function is successful, then 'group.ID' will be set to the inserted record's ID
func (x *sqlGroupDB) InsertGroup(group *AuthGroup) error {
	row := x.db.QueryRow("INSERT INTO authgroup (name, permbits) VALUES ($1, $2) RETURNING id", group.Name, group.encodePermBits())
	var lastId GroupIDU32
	if err := row.Scan(&lastId); err == nil {
		group.ID = lastId
		return nil
	} else {
		return err
	}

	/*
		if res, err := x.db.Exec("INSERT INTO authgroup (name, permbits) VALUES ($1, $2) RETURNING id", group.Name, group.encodePermBits()); err == nil {
			fmt.Printf("OK\n")
			if lastId, e2 := res.LastInsertId(); e2 == nil {
				group.ID = GroupIDU32(lastId)
				fmt.Printf("good: %v\n", group.ID)
				return nil
			} else {
				fmt.Printf("e2: %v\n", e2)
				return e2
			}
		} else {
			fmt.Printf("Error\n")
			if strings.Index(err.Error(), "already exists") != -1 {
				return ErrGroupExists
			}
			return err
		}*/
	// unreachable
	return nil
}

// Update an existing group (by ID)
func (x *sqlGroupDB) UpdateGroup(group *AuthGroup) error {
	if group.ID == 0 {
		return ErrGroupNotExist
	}
	if _, err := x.db.Exec("UPDATE authgroup SET name=$1, permbits=$2 WHERE id=$3", group.Name, group.encodePermBits(), group.ID); err == nil {
		return nil
	} else {
		return err
	}
	// unreachable
	return nil
}

func (x *sqlGroupDB) Close() {
	if x.db != nil {
		x.db.Close()
		x.db = nil
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/* Role Group cache
This cached all role groups from the backend database. We assume that this database will never be
particularly large, so we simply allow our cache to grow indefinitely.
All public functions are thread-safe.
*/
type RoleGroupCache struct {
	backend      RoleGroupDB
	groupsByID   map[GroupIDU32]*AuthGroup
	groupsByName map[string]*AuthGroup
	groupsLock   sync.RWMutex
}

func (x *RoleGroupCache) GetByName(name string) (*AuthGroup, error) {
	return x.get(true, name)
}

func (x *RoleGroupCache) GetByID(id GroupIDU32) (*AuthGroup, error) {
	return x.get(false, id)
}

func (x *RoleGroupCache) InsertGroup(group *AuthGroup) error {
	if err := x.backend.InsertGroup(group); err == nil {
		x.groupsLock.Lock()
		x.insertInCache(*group)
		x.groupsLock.Unlock()
		return nil
	} else {
		return err
	}
	// unreachable
	return nil
}

func (x *RoleGroupCache) UpdateGroup(group *AuthGroup) error {
	if err := x.backend.UpdateGroup(group); err == nil {
		x.groupsLock.Lock()
		x.insertInCache(*group)
		x.groupsLock.Unlock()
		return nil
	} else {
		return err
	}
	// unreachable
	return nil
}

func (x *RoleGroupCache) Close() {
	x.resetMaps()
	if x.backend != nil {
		x.backend.Close()
		x.backend = nil
	}
}

func (x *RoleGroupCache) get(byname bool, value interface{}) (*AuthGroup, error) {
	// Acquire from the cache
	x.groupsLock.RLock()
	var group *AuthGroup
	if byname {
		group, _ = x.groupsByName[value.(string)]
	} else {
		group, _ = x.groupsByID[value.(GroupIDU32)]
	}
	x.groupsLock.RUnlock()
	if group != nil {
		return group, nil
	}

	// Acquire from the backend
	x.groupsLock.Lock()
	var err error
	group, err = x.getFromBackend(byname, value)
	x.groupsLock.Unlock()
	return group, err
}

func (x *RoleGroupCache) resetMaps() {
	x.groupsByID = make(map[GroupIDU32]*AuthGroup)
	x.groupsByName = make(map[string]*AuthGroup)
}

// Assume that groupsLock.WRITE is held
func (x *RoleGroupCache) getFromBackend(byname bool, value interface{}) (*AuthGroup, error) {
	var group *AuthGroup
	var err error
	if byname {
		group, err = x.backend.GetByName(value.(string))
	} else {
		group, err = x.backend.GetByID(value.(GroupIDU32))
	}

	if err == nil {
		x.insertInCache(*group)
		return group, nil
	} else {
		return nil, err
	}

	// unreachable
	return nil, nil
}

// Assume that groupsLock.WRITE is held
func (x *RoleGroupCache) insertInCache(group AuthGroup) {
	gcopy := group.Clone()
	x.groupsByID[group.ID] = gcopy
	x.groupsByName[group.Name] = gcopy
}

func NewCachedRoleGroupDB(conx *authaus.DBConnection) (RoleGroupDB, error) {
	if backend, eBackend := NewRoleGroupDB(conx); eBackend != nil {
		return nil, eBackend
	} else {
		cached := &RoleGroupCache{}
		cached.resetMaps()
		cached.backend = backend
		return cached, nil
	}
	// unreachable
	return nil, nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func NewRoleGroupDB(conx *authaus.DBConnection) (RoleGroupDB, error) {
	var err error
	db := &sqlGroupDB{}
	if db.db, err = conx.Connect(); err != nil {
		return nil, err
	}
	return db, nil
}

// Create a Postgres DB schema necessary for our Groups database
func RoleGroupDB_Create(conx *authaus.DBConnection) error {
	versions := make([]string, 0)
	versions = append(versions, `
	CREATE TABLE authgroup (id SERIAL PRIMARY KEY, name VARCHAR, permbits VARCHAR);
	CREATE UNIQUE INDEX idx_authgroup_name ON authgroup (name);`)

	return authaus.MigrateSchema(conx, "authgroup", versions)
}
