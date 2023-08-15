package ldap

import (
	"reflect"
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

// isCorrectDn checks dn syntax
func isCorrectDn(s string) bool {
	var allowedAttrs = []string{"cn", "uid", "ou", "dc"}

	for _, sub := range strings.Split(s, ",") {
		var found bool

		attrName, _, found := strings.Cut(sub, "=")
		if !found {
			return false
		}
		for _, attr := range allowedAttrs {
			if attrName == attr {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// getEntryAttrValueSuffix returns entry attribute, its value and suffix
// e.g. for entry cn=admin,ou=users,dc=example,dc=com it would return ['cn', 'admin', 'ou=users,dc=example,dc=com']
func getEntryAttrValueSuffix(entry string) (attr, value, suffix string) {
	var attrValue string
	attrValue, suffix, _ = strings.Cut(entry, ",")
	attr, value, _ = strings.Cut(attrValue, "=")
	return
}

// tagValueContains returns true if StructTag's 'tag' key 'tagName' contains value 'tagValue'
func tagValueContains(tag reflect.StructTag, tagName, tagValue string) bool {
	val, ok := tag.Lookup(tagName)
	if !ok {
		return false
	}
	var found bool
	for _, s := range strings.Split(val, ",") {
		if s != tagValue {
			continue
		}
		found = true
		break
	}
	return found
}
