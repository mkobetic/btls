package records

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func assertEqualBytes(t *testing.T, a, b []byte) {
	assert.Equal(t, a, b, "Not Equal!\n%x\n%x", a, b)
}

func h2b(h string) []byte {
	b, _ := hex.DecodeString(h)
	return b
}
