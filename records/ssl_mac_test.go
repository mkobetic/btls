package records

import (
	"github.com/mkobetic/okapi"
	"testing"
)

func Test_SSL30MAC_MD5(t *testing.T) {
	key := []byte("mac secret")
	payload := []byte("hello")
	mac := NewSSL30MAC(okapi.MD5, key)
	defer mac.Close()
	mac.Write(payload)
	digest := mac.Digest()
	md5 := okapi.MD5.New()
	defer md5.Close()
	md5.Write(key)
	for i := 0; i < 6; i++ {
		md5.Write(PAD1)
	}
	md5.Write(payload)
	inner := md5.Digest()
	md5.Reset()
	md5.Write(key)
	for i := 0; i < 6; i++ {
		md5.Write(PAD2)
	}
	md5.Write(inner)
	expected := md5.Digest()
	assertEqualBytes(t, expected, digest)
}
