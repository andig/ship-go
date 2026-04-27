package mdns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseTXT(t *testing.T) {
	var txt []string

	result, ok := parseTxt(txt)
	assert.True(t, ok)
	assert.Equal(t, 0, len(result))

	txt = []string{"test"}
	result, ok = parseTxt(txt)
	assert.True(t, ok)
	assert.Equal(t, 0, len(result))

	txt = []string{"test=more"}
	result, ok = parseTxt(txt)
	assert.True(t, ok)
	assert.Equal(t, 1, len(result))

	txt = []string{"test=more", "test2=more2"}
	result, ok = parseTxt(txt)
	assert.True(t, ok)
	assert.Equal(t, 2, len(result))

	// Test duplicate keys
	txt = []string{"test=more", "test=again"}
	result, ok = parseTxt(txt)
	assert.False(t, ok)
	assert.Equal(t, 0, len(result))
}
