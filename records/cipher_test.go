package records

import (
	"testing"
)

func TestCipher_NULL_NULL(t *testing.T) {
	suite := NewCipher(NULL_NULL, TLS10, nil, nil, nil)
	bytes := []byte("Hello World!")
	size, err := suite.Seal(bytes, bytes)
	if err != nil {
		t.Fatalf("Seal error: %s", err)
	}
	if size != 12 {
		t.Fatalf("Wrong Seal output size: %d", size)
	}
	size, err = suite.Open(bytes[:size], bytes)
	if err != nil {
		t.Fatalf("Open error: %s", err)
	}
	if size != 12 {
		t.Fatalf("Wrong Open output size: %d", size)
	}
	if string(bytes) != "Hello World!" {
		t.Fatalf("%s", bytes)
	}
}
