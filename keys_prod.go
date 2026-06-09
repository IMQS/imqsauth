//go:build prod

package main

import _ "embed"

//go:embed server.bin
var pk []byte

//go:embed key.bin
var mask []byte

