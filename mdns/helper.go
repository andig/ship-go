package mdns

import (
	"strings"
)

// validateTxtversOrder returns true if txt is empty or the first entry is "txtvers=1".
func validateTxtversOrder(txt []string) bool {
	if len(txt) == 0 {
		return true
	}
	return txt[0] == "txtvers=1"
}

// parse mDNS text fields
func parseTxt(txt []string) (txtMap map[string]string, uniqueKeys bool) {
	result := make(map[string]string)

	for _, item := range txt {
		s := strings.Split(item, "=")
		if len(s) != 2 {
			continue
		}
		// If the key is duplicated, return false for key uniqueness
		if _, exists := result[s[0]]; exists {
			return nil, false
		}
		result[s[0]] = s[1]
	}

	return result, true
}
