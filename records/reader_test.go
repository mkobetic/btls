package records

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"io"
	"testing"
)

func TestReader_Basic(t *testing.T) {
	b := bytes.NewBuffer(h2b("1503020007facadebeefdead"))
	r := NewReaderIO(b, nil)
	r.ContentType = alert
	out := make([]byte, 4)
	n, err := r.Read(out)
	assert.Nil(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, TLS11, r.recordVersion())
	assert.Equal(t, alert, r.recordContentType())
	assertEqualBytes(t, h2b("facadebe"), out)
	n, err = r.Read(out)
	assert.Equal(t, io.EOF, err)
	assert.Equal(t, 3, n)
	assert.Equal(t, TLS11, r.recordVersion())
	assert.Equal(t, alert, r.recordContentType())
	assertEqualBytes(t, h2b("efdead"), out[:n])
	err = r.Close()
	assert.Nil(t, err)
}

func TestReader_FragmentedRead(t *testing.T) {
	b := bytes.NewBuffer(
		h2b("1603000003facade" +
			"1603000002beef" +
			"1603000002dead"))
	r := NewReaderIO(b, nil)
	out := make([]byte, 4)
	n, err := r.Read(out)
	assert.Nil(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, SSL30, r.recordVersion())
	assert.Equal(t, handshake, r.recordContentType())
	assertEqualBytes(t, h2b("facadebe"), out)
	n, err = r.Read(out)
	assert.Equal(t, io.EOF, err)
	assert.Equal(t, 3, n)
	assert.Equal(t, SSL30, r.recordVersion())
	assert.Equal(t, handshake, r.recordContentType())
	assertEqualBytes(t, h2b("efdead"), out[:n])
	err = r.Close()
	assert.Nil(t, err)
}
