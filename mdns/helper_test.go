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

	// Positive: RFC 6763 §6.4 — key comparison is case-insensitive
	assert.True(t, validateTxtversOrder([]string{"TXTVERS=1", "ski=abc123"}))
	assert.True(t, validateTxtversOrder([]string{"TxtVers=1"}))
	assert.True(t, validateTxtversOrder([]string{"Txtvers=1", "id=test"}))

	// Negative: txtvers=1 is present but not first
	assert.False(t, validateTxtversOrder([]string{"ski=abc123", "txtvers=1"}))

	// Negative: txtvers=1 is in the middle
	assert.False(t, validateTxtversOrder([]string{"id=test", "txtvers=1", "ski=abc"}))

	// Negative: txtvers=1 is absent entirely
	assert.False(t, validateTxtversOrder([]string{"ski=abc123", "id=test"}))

	// Negative: wrong version value leads the record (value compare is exact)
	assert.False(t, validateTxtversOrder([]string{"txtvers=2", "ski=abc123"}))

	// Negative: malformed leading entry has no '=' separator
	assert.False(t, validateTxtversOrder([]string{"txtvers"}))
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

	// RFC 6763 §6.4 — keys are case-insensitive and folded to lowercase on storage
	txt = []string{"TrustNonce=ABC123", "ForId=devA"}
	result, ok = parseTxt(txt)
	assert.True(t, ok)
	assert.Equal(t, 2, len(result))
	assert.Equal(t, "ABC123", result["trustnonce"])
	assert.Equal(t, "devA", result["forid"])
	// Values must not be folded — uppercase hex content is preserved
	assert.NotContains(t, result, "TrustNonce")

	// RFC 6763 §6.4 — case-variant duplicates trip dedup (closes TC_SPS_TXT_007 evasion)
	txt = []string{"trustPar=A", "TRUSTPAR=B"}
	result, ok = parseTxt(txt)
	assert.False(t, ok)
	assert.Equal(t, 0, len(result))

	// Values containing '=' are parsed correctly (only the first '=' separates key and value)
	txt = []string{"key=value=with=equals"}
	result, ok = parseTxt(txt)
	assert.True(t, ok)
	assert.Equal(t, "value=with=equals", result["key"])
}
