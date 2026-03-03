//go:build !dev && !prod

package imqsauth

// Intentional compile error: a build tag must be specified explicitly.
// Use:
//   go build -tags dev .    (development — no license required, no key files needed)
//   go build -tags prod .   (production  — requires server.bin and key.bin)
var _ = ERROR_must_specify_a_build_tag__use_tags_dev_or_tags_prod

// Stubs to suppress cascading errors — the var above is the only intended message.
func SetLicenseKeys(p, m []byte)                { }
func (x *ImqsCentral) initLicenseClient() error { return nil }
func isLicensed() bool                          { return false }
