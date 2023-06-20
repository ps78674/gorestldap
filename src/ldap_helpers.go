package main

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
	ldap "github.com/ps78674/goldap/message"
)

type LDAPError struct {
	ResultCode int
	error
}

var allowedDNAttrs = []string{"cn", "uid", "ou", "dc"}

var (
	errLDAPNoAttr error = LDAPError{
		ldap.ResultCodeUndefinedAttributeType,
		errors.New("target entry does not have requested attribute"),
	}

	errLDAPMultiValue error = LDAPError{
		ldap.ResultCodeInvalidAttributeSyntax,
		errors.New("attempt to set multiple values on single value attribute"),
	}
)

// newEntryUUID creates uuid5 from NameSpaceOID and entry name
func newEntryUUID(name string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(name)).String()
}

// normalizeEntry returns entry in lowercase without spaces after comma
// e.g. DC=test, dc=EXAMPLE,  dc=com -> dc=test,dc=example,dc=com
func normalizeEntry(s string) string {
	s = strings.ToLower(s)
	re := regexp.MustCompile(`(,[\s]+)`)
	return re.ReplaceAllString(s, ",")
}

// isCorrectDn checks dn syntax
func isCorrectDn(s string) bool {
	subs := strings.Split(s, ",")
	for i := range subs {
		attrName, _, found := strings.Cut(subs[i], "=")
		if !found {
			return false
		}
		for i := range allowedDNAttrs {
			if attrName == allowedDNAttrs[i] {
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
	subs := strings.Split(val, ",")
	for i := range subs {
		if tagValue == subs[i] {
			return true
		}
	}
	return false
}

// applySearchFilter returns true if object 'o' fits filter 'f'
func applySearchFilter(o interface{}, f ldap.Filter) (bool, error) {
	switch filter := f.(type) {
	case ldap.FilterEqualityMatch:
		attrName := string(filter.AttributeDesc())
		attrValue := string(filter.AssertionValue())

		if strings.ToLower(attrName) == "entrydn" {
			entry := normalizeEntry(string(filter.AssertionValue()))
			attrName, attrValue, _ = getEntryAttrValueSuffix(entry)
		}

		field, found := reflect.TypeOf(o).FieldByNameFunc(func(s string) bool { return strings.EqualFold(s, attrName) })
		if !found {
			return false, nil
		}

		fieldValue := reflect.ValueOf(o).FieldByName(field.Name)
		if !fieldValue.IsValid() {
			return false, nil
		}

		switch val := fieldValue.Interface().(type) {
		case uint:
			if fmt.Sprint(val) == attrValue {
				return true, nil
			}
		case string:
			if !tagValueContains(field.Tag, "ldap", "case_sensitive_value") {
				val = strings.ToLower(val)
				attrValue = strings.ToLower(attrValue)
			}
			if val == attrValue {
				return true, nil
			}
		case []string:
			for _, v := range val {
				if !tagValueContains(field.Tag, "ldap", "case_sensitive_value") {
					v = strings.ToLower(v)
					attrValue = strings.ToLower(attrValue)
				}
				if v == attrValue {
					return true, nil
				}
			}
		}
	case ldap.FilterAnd:
		for i := range filter {
			ok, err := applySearchFilter(o, filter[i])
			if !ok || err != nil {
				return ok, err
			}
		}
		return true, nil
	case ldap.FilterOr:
		var anyOk bool

		for i := range filter {
			ok, err := applySearchFilter(o, filter[i])
			if err != nil {
				return false, err
			}
			if ok {
				anyOk = true
			}
		}

		if anyOk {
			return true, nil
		}
	case ldap.FilterPresent:
		attrName := fmt.Sprintf("%v", filter)
		if strings.ToLower(attrName) == "entrydn" {
			return true, nil
		}

		field, found := reflect.TypeOf(o).FieldByNameFunc(func(s string) bool { return strings.EqualFold(s, attrName) })
		if !found {
			return false, nil
		}

		tagValue := field.Tag.Get("json")
		tagValue, _, _ = strings.Cut(tagValue, ",")
		if strings.EqualFold(attrName, tagValue) {
			return true, nil
		}
	case ldap.FilterSubstrings:
		attrName := string(filter.Type_())
		attrValues := filter.Substrings()

		field, found := reflect.TypeOf(o).FieldByNameFunc(func(s string) bool { return strings.EqualFold(s, attrName) })
		if !found {
			return false, nil
		}

		fieldValue := reflect.ValueOf(o).FieldByName(field.Name)
		if !fieldValue.IsValid() {
			return false, nil
		}

		for i := range attrValues {
			substringInitial, _ := attrValues[i].(ldap.SubstringInitial)
			attrValue := string(substringInitial)
			switch val := fieldValue.Interface().(type) {
			case uint:
				if strings.HasPrefix(fmt.Sprint(val), attrValue) {
					return true, nil
				}
			case string:
				if !tagValueContains(field.Tag, "ldap", "case_sensitive_value") {
					val = strings.ToLower(val)
					attrValue = strings.ToLower(attrValue)
				}
				if strings.HasPrefix(val, attrValue) {
					return true, nil
				}
			case []string:
				for _, v := range val {
					if !tagValueContains(field.Tag, "ldap", "case_sensitive_value") {
						v = strings.ToLower(v)
						attrValue = strings.ToLower(attrValue)
					}
					if strings.HasPrefix(v, attrValue) {
						return true, nil
					}
				}
			}
		}
	default:
		return false, fmt.Errorf("unsupported filter type '%T'", f)
	}

	return false, nil
}

// newLDAPAttributeValues creates ldap attributes from an interface
func newLDAPAttributeValues(in interface{}) (out []ldap.AttributeValue) {
	switch in := in.(type) {
	case uint:
		out = append(out, ldap.AttributeValue(fmt.Sprint(in)))
	case string:
		out = append(out, ldap.AttributeValue(in))
	case []string:
		for i := range in {
			out = append(out, ldap.AttributeValue(in[i]))
		}
	}
	return
}

// createSearchEntry creates ldap.SearchResultEntry from 'o' with attributes 'attrs' and name 'entryName'
func createSearchEntry(o interface{}, attrs []string, entryName string) (e ldap.SearchResultEntry) {
	// set entry name
	e.SetObjectName(entryName)

	// if no attrs set -> use * (all)
	if len(attrs) == 0 {
		attrs = append(attrs, "*")
	}

	for i := range attrs {
		switch attr := strings.ToLower(attrs[i]); attr {
		case "entrydn":
			e.AddAttribute("entryDN", ldap.AttributeValue(entryName))
		case "+": // operational only
			e.AddAttribute("entryDN", ldap.AttributeValue(entryName))
			rValue := reflect.ValueOf(o)
			for i := 0; i < rValue.NumField(); i++ {
				field := rValue.Type().Field(i)
				if tagValueContains(field.Tag, "ldap", "skip") {
					continue
				}
				if !tagValueContains(field.Tag, "ldap", "operational") {
					continue
				}
				tagValue := field.Tag.Get("json")
				attrName, _, _ := strings.Cut(tagValue, ",")
				e.AddAttribute(ldap.AttributeDescription(attrName), newLDAPAttributeValues(rValue.Field(i).Interface())...)
			}
		case "*": // all except operational
			rValue := reflect.ValueOf(o)
			for i := 0; i < rValue.NumField(); i++ {
				field := rValue.Type().Field(i)
				if tagValueContains(field.Tag, "ldap", "skip") {
					continue
				}
				if tagValueContains(field.Tag, "ldap", "operational") {
					continue
				}
				tagValue := field.Tag.Get("json")
				attrName, _, _ := strings.Cut(tagValue, ",")
				e.AddAttribute(ldap.AttributeDescription(attrName), newLDAPAttributeValues(rValue.Field(i).Interface())...)
			}
		default:
			field, found := reflect.TypeOf(o).FieldByNameFunc(func(n string) bool { return strings.EqualFold(n, attr) })
			if !found {
				continue
			}
			if tagValueContains(field.Tag, "ldap", "skip") {
				continue
			}
			fieldValue := reflect.ValueOf(o).FieldByName(field.Name)
			if fieldValue.IsValid() {
				e.AddAttribute(ldap.AttributeDescription(attrs[i]), newLDAPAttributeValues(fieldValue.Interface())...)
			}
		}
	}

	return
}

// doCompare checks if object 'o' have attr 'attrName' with value 'attrValue'
func doCompare(o interface{}, attrName string, attrValue string) (bool, error) {
	field, found := reflect.TypeOf(o).FieldByNameFunc(func(s string) bool { return strings.EqualFold(s, attrName) })
	if !found {
		return false, errLDAPNoAttr
	}
	if tagValueContains(field.Tag, "ldap", "skip") {
		return false, errLDAPNoAttr
	}

	fieldValue := reflect.ValueOf(o).FieldByName(field.Name)
	if !fieldValue.IsValid() {
		return false, errLDAPNoAttr
	}

	switch val := fieldValue.Interface().(type) {
	case uint:
		if fmt.Sprint(val) == attrValue {
			return true, nil
		}
	case string:
		if !tagValueContains(field.Tag, "ldap", "case_sensitive_value") {
			val = strings.ToLower(val)
			attrValue = strings.ToLower(attrValue)
		}
		if val == attrValue {
			return true, nil
		}
	case []string:
		for _, v := range val {
			if !tagValueContains(field.Tag, "ldap", "case_sensitive_value") {
				v = strings.ToLower(v)
				attrValue = strings.ToLower(attrValue)
			}
			if v == attrValue {
				return true, nil
			}
		}
	}

	return false, nil
}

// doModify update object's 'o' attr 'attrName' with value 'attrValue'
func doModify(o interface{}, attrName string, values []ldap.AttributeValue) error {
	root := reflect.ValueOf(o).Elem()
	obj := root.Elem()
	objType := obj.Type()

	field, found := objType.FieldByNameFunc(func(s string) bool { return strings.EqualFold(s, attrName) })
	if !found {
		return errLDAPNoAttr
	}
	if tagValueContains(field.Tag, "ldap", "skip") {
		return errLDAPNoAttr
	}

	objCopy := reflect.New(objType).Elem()
	objCopy.Set(obj)

	fieldValue := objCopy.FieldByName(field.Name)
	if !fieldValue.IsValid() {
		return errLDAPNoAttr
	}

	switch fieldValue.Interface().(type) {
	case uint:
		if len(values) > 1 {
			return errLDAPMultiValue
		}
		_uint, err := strconv.ParseUint(string(values[0]), 10, 32)
		if err != nil {
			return LDAPError{
				ldap.ResultCodeUndefinedAttributeType,
				fmt.Errorf("wrong attribute value: %s", err),
			}
		}
		fieldValue.SetUint(_uint)
	case string:
		if len(values) > 1 {
			return errLDAPMultiValue
		}
		fieldValue.SetString(string(values[0]))
	case []string:
		for i := range values {
			fieldValue.SetString(string(values[i]))
		}
	}

	root.Set(objCopy)

	return nil
}
