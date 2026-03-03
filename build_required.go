//go:build !dev && !prod

package main

// Intentional compile error: a build tag must be specified explicitly.
// Use:
//   go build -tags dev .    (development - no license required)
//   go build -tags prod .   (production  - requires server.bin and key.bin)
var _ = ERROR_must_specify_a_build_tag__use_tags_dev_or_tags_prod
