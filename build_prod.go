//go:build prod

package main

import (
	_ "embed"

	auth "github.com/IMQS/imqsauth/auth"
)

//go:embed server.bin
var pk []byte

//go:embed key.bin
var mask []byte

func init() {
	auth.SetLicenseKeys(pk, mask)
}
