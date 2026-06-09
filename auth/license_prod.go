//go:build prod

package imqsauth

import (
	"github.com/IMQS/licenseserver/client"
	"github.com/IMQS/licenseserver/lib"
)

var pk   []byte
var mask []byte

// SetLicenseKeys is called from package main's init() to supply the embedded
// key bytes without exposing them as fields on ImqsCentral.
func SetLicenseKeys(p, m []byte) {
	pk = p
	mask = m
}

var licenseClient *client.LicenseClient

func (x *ImqsCentral) initLicenseClient() error {
	serverPub, e := lib.UnmaskPublicKey(pk, mask)
	if e != nil {
		return e
	}
	licenseClient = &client.LicenseClient{}
	licenseClient.Init("./licenses_client", serverPub)
	licenseClient.LicenseServerURL = "https://deploy.imqs.co.za/licenses/"
	licenseClient.Logger = x.Central.Log
	lib.L = x.Central.Log
	licenseClient.RunClient()
	return nil
}

func isLicensed() bool {
	return licenseClient.IsLicensed("enterprise")
}
