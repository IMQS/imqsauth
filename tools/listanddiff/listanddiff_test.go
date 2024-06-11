package main

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

//type Perms map[string]string

func TestAuthMapLoad(t *testing.T) {
	fdata, e := os.ReadFile("authmap_test.json")
	if e != nil {
		t.Errorf("Error: %v\n", e)
		t.FailNow()
	}
	permsMap := AuthPermsLight{}

	e2 := json.Unmarshal(fdata, &permsMap)
	if e2 != nil {
		t.Errorf("Error: %v\n", e2)
		t.FailNow()
	}

	assert.Truef(t, len(permsMap) > 0, "Expected at least one permission in the map")
	assert.Equal(t, permsMap["100"], "pcssuperuser", "Expected permission 100 to be pcssuperuser")
}
