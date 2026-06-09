//go:build dev

package imqsauth

// Dev mode: license client is not compiled in. All license checks pass unconditionally.

func (x *ImqsCentral) initLicenseClient() error {
	x.Central.Log.Warnf("DEV MODE: license checks are disabled (built with -tags dev)")
	return nil
}

func isLicensed() bool {
	return true
}

