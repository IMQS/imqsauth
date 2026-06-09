//go:build dev

package main

// Dev mode: no embedded keys. License checks are skipped automatically
// when Pk/Mask are empty (see auth.ImqsCentral.RunHttp).
// Build with: go build -tags dev .
var pk []byte
var mask []byte

