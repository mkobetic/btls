package records

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestWriter_Basic(t *testing.T) {
	b := bytes.NewBuffer(nil)
	w := NewWriter(b, nil)
	w.SetVersion(TLS11)
	assert.Equal(t, TLS11, w.Version())
	w.SetContentType(Alert)
	assert.Equal(t, Alert, w.ContentType())
	c, err := w.Write(h2b("facade"))
	assert.Nil(t, err)
	assert.Equal(t, 3, c)
	c, err = w.Write(h2b("beef"))
	assert.Nil(t, err)
	assert.Equal(t, 2, c)
	c, err = w.Write(h2b("dead"))
	assert.Nil(t, err)
	assert.Equal(t, 2, c)
	err = w.Close()
	assert.Nil(t, err)
	assertEqualBytes(t, b.Bytes(), h2b("1503020007facadebeefdead"))
}

func TestWriter_AutoFlushing(t *testing.T) {
	b := bytes.NewBuffer(nil)
	w := NewWriter(b, make([]byte, PayloadOffset+2+MinBufferTrailerSize))
	c, err := w.Write(h2b("facade"))
	assert.Nil(t, err)
	assert.Equal(t, 3, c)
	c, err = w.Write(h2b("beef"))
	assert.Nil(t, err)
	assert.Equal(t, 2, c)
	err = w.Close()
	assert.Nil(t, err)
	assertEqualBytes(t, b.Bytes(),
		h2b("1603000002faca"+
			"1603000002debe"+
			"1603000001ef"))
}

func TestWriter_ChangingContentTypeFlushes(t *testing.T) {
	b := bytes.NewBuffer(nil)
	w := NewWriter(b, nil)
	c, err := w.Write(h2b("facade"))
	assert.Nil(t, err)
	assert.Equal(t, 3, c)
	w.SetContentType(Alert)
	c, err = w.Write(h2b("beef"))
	assert.Nil(t, err)
	assert.Equal(t, 2, c)
	err = w.Close()
	assert.Nil(t, err)
	assertEqualBytes(t, b.Bytes(),
		h2b("1603000003facade"+
			"1503000002beef"))
}
