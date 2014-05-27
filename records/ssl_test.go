package records

import (
	"github.com/mkobetic/okapi"
	_ "github.com/mkobetic/okapi/libcrypto"
	"testing"
)

func Test_SSL30MAC_MD5(t *testing.T) {
	mac := NewSSL30MAC(okapi.MD5, []byte("mac secret"))
	mac.Write([]byte("hello"))
	digest := mac.Digest()
	assertEqualBytes(t, digest, h2b("aa"))
}
