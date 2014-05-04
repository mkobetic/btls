package records

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestWriter_Basic(t *testing.T) {
	b := bytes.NewBuffer(nil)
	w := NewWriterIO(b, nil)
	w.SetVersion(TLS11)
	assert.Equal(t, TLS11, w.Version())
	w.SetContentType(alert)
	assert.Equal(t, alert, w.ContentType())
	c, err := w.Write(h2b("facade"))
	assert.Nil(t, err)
	assert.Equal(t, 3, c)
	c, err = w.Write(h2b("beef"))
	assert.Nil(t, err)
	assert.Equal(t, 2, c)
	c, err = w.Write(h2b("dead"))
	assert.Nil(t, err)
	assert.Equal(t, 2, c)
	err = w.Flush()
	assert.Nil(t, err)
	assertEqualBytes(t, b.Bytes(), h2b("1503020007facadebeefdead"))
}
