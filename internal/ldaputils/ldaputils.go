package ldaputils

import (
	"regexp"
	"strings"
)

// NormalizeEntry returns entry in lowercase without spaces after comma
// e.g. DC=test, dc=EXAMPLE,  dc=com -> dc=test,dc=example,dc=com
func NormalizeEntry(s string) string {
	s = strings.ToLower(s)
	re := regexp.MustCompile(`(,[\s]+)`)
	return re.ReplaceAllString(s, ",")
}
