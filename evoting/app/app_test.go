package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dedis/cothority/evoting/lib"
)

func TestParseKey(t *testing.T) {
	_, err := parseKey("r")
	assert.NotNil(t, err)

	_, err = parseKey("")
	assert.NotNil(t, err)

	p1 := lib.Suite.Point().Pick(lib.Stream)
	p2, _ := parseKey(p1.String())
	assert.True(t, p1.Equal(p2))
}

func TestParseAdmins(t *testing.T) {
	admins, err := parseAdmins("")
	assert.Nil(t, admins, err)

	_, err = parseAdmins("1,2,a,3")
	assert.NotNil(t, err)

	admins, _ = parseAdmins("1,2,3")
	assert.Equal(t, []uint32{1, 2, 3}, admins)
}
