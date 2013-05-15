package auth

import (
	"fmt"
	_ "github.com/bmizerany/pq"
)

type RoleDB struct {
	db *sql.DB
}

func (x *RoleDB) Close() {
	if x.db != nil {
		x.db.Close()
		x.db = nil
	}
}

func Connect(driver, host, dbname, username, password string, useSSL bool) (*RoleDB, error) {
	db := &RoleDB{}
	sslmode := "disable"
	if useSSL {
		sslmode = "require"
	}
	var err error
	db.db, err = sql.Open(driver, fmt.Sprintf("host=%v user=%v password=%v dbname=%v sslmode=%v", host, username, password, dbname, sslmode))
	if err != nil {
		return nil, err
	}
	return db, nil
}
