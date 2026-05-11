package mdns

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateTxtversOrder(t *testing.T) {
	// Positive: empty slice — no leading entry to validate
	assert.True(t, validateTxtversOrder([]string{}))

	// Positive: txtvers=1 is the only entry
	assert.True(t, validateTxtversOrder([]string{"txtvers=1"}))

	// Positive: txtvers=1 leads a full record
	assert.True(t, validateTxtversOrder([]string{"txtvers=1", "ski=abc123", "id=test"}))

	// Negative: txtvers=1 is present but not first
	assert.False(t, validateTxtversOrder([]string{"ski=abc123", "txtvers=1"}))

	// Negative: txtvers=1 is in the middle
	assert.False(t, validateTxtversOrder([]string{"id=test", "txtvers=1", "ski=abc"}))

	// Negative: txtvers=1 is absent entirely
	assert.False(t, validateTxtversOrder([]string{"ski=abc123", "id=test"}))

	// Negative: wrong version value leads the record
	assert.False(t, validateTxtversOrder([]string{"txtvers=2", "ski=abc123"}))
}

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
