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
	var allowedAttrs = []string{"cn", "uid", "ou", "dc"}

	for _, sub := range strings.Split(s, ",") {
		var found bool
		attrValuePair := strings.SplitN(sub, "=", 2)
		if len(attrValuePair) < 2 {
			return false
		}
		for _, attr := range allowedAttrs {
			if attrValuePair[0] == attr {
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

// getEntryAttrNameSuffix returns entry attribute, name and suffix
// e.g. for entry cn=admin,ou=users,dc=example,dc=com it would return ['cn', 'admin', 'ou=users,dc=example,dc=com']
func getEntryAttrNameSuffix(entry string) (attr, name, suffix string) {
	entrySuffixPair := strings.SplitN(entry, ",", 2)
	attrValuePair := strings.SplitN(entrySuffixPair[0], "=", 2)
	attr = attrValuePair[0]
	if len(attrValuePair) == 2 {
		name = attrValuePair[1]
	}
	if len(entrySuffixPair) == 2 {
		suffix = entrySuffixPair[1]
	}
	return
}

// applySearchFilter returns true if object 'o' fits filter 'f'
func applySearchFilter(o interface{}, f ldap.Filter) (bool, error) {
	switch filter := f.(type) {
	case ldap.FilterEqualityMatch:
		attrName := string(filter.AttributeDesc())
		attrValue := string(filter.AssertionValue())

		if strings.ToLower(attrName) == "entrydn" {
			entry := normalizeEntry(string(filter.AssertionValue()))
			if strings.HasSuffix(entry, cfg.BaseDN) {
				attrName, attrValue, _ = getEntryAttrNameSuffix(entry)
			}
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
			if _, ok := field.Tag.Lookup("ldap_case_sensitive_value"); !ok {
				val = strings.ToLower(val)
				attrValue = strings.ToLower(attrValue)
			}
			if val == attrValue {
				return true, nil
			}
		case []string:
			for _, v := range val {
				if _, ok := field.Tag.Lookup("ldap_case_sensitive_value"); !ok {
					v = strings.ToLower(v)
					attrValue = strings.ToLower(attrValue)
				}
				if v == attrValue {
					return true, nil
				}
			}
		}
	case ldap.FilterAnd:
		for _, _filter := range filter {
			ok, err := applySearchFilter(o, _filter)
			if !ok || err != nil {
				return ok, err
			}
		}
		return true, nil
	case ldap.FilterOr:
		var anyOk bool

		for _, _filter := range filter {
			ok, err := applySearchFilter(o, _filter)
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
		// TODO: entryDN not used for DSE entry
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

		for _, _attrValue := range attrValues {
			substringInitial, _ := _attrValue.(ldap.SubstringInitial)
			attrValue := string(substringInitial)
			switch val := fieldValue.Interface().(type) {
			case uint:
				if strings.HasPrefix(fmt.Sprint(val), attrValue) {
					return true, nil
				}
			case string:
				if _, ok := field.Tag.Lookup("ldap_case_sensitive_value"); !ok {
					val = strings.ToLower(val)
					attrValue = strings.ToLower(attrValue)
				}
				if strings.HasPrefix(val, attrValue) {
					return true, nil
				}
			case []string:
				for _, v := range val {
					if _, ok := field.Tag.Lookup("ldap_case_sensitive_value"); !ok {
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
		for _, v := range in {
			out = append(out, ldap.AttributeValue(v))
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

	for _, a := range attrs {
		switch attr := strings.ToLower(a); attr {
		case "entrydn":
			e.AddAttribute("entryDN", ldap.AttributeValue(entryName))
		case "+": // operational only
			e.AddAttribute("entryDN", ldap.AttributeValue(entryName))
			rValue := reflect.ValueOf(o)
			for i := 0; i < rValue.NumField(); i++ {
				field := rValue.Type().Field(i)
				if _, ok := field.Tag.Lookup("ldap_skip"); ok {
					continue
				}
				if _, ok := field.Tag.Lookup("ldap_operational"); !ok {
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
				if _, ok := field.Tag.Lookup("ldap_skip"); ok {
					continue
				}
				if _, ok := field.Tag.Lookup("ldap_operational"); ok {
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
			// TODO: lookupTagValue(tag, tagName, tagValue)
			if _, ok := field.Tag.Lookup("ldap_skip"); ok {
				continue
			}
			fieldValue := reflect.ValueOf(o).FieldByName(field.Name)
			if fieldValue.IsValid() {
				e.AddAttribute(ldap.AttributeDescription(a), newLDAPAttributeValues(fieldValue.Interface())...)
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
	if _, ok := field.Tag.Lookup("ldap_skip"); ok {
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
		if _, ok := field.Tag.Lookup("ldap_case_sensitive_value"); !ok {
			val = strings.ToLower(val)
			attrValue = strings.ToLower(attrValue)
		}
		if val == attrValue {
			return true, nil
		}
	case []string:
		for _, v := range val {
			if _, ok := field.Tag.Lookup("ldap_case_sensitive_value"); !ok {
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
	if _, ok := field.Tag.Lookup("ldap_skip"); ok {
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
		for _, v := range values {
			fieldValue.SetString(string(v))
		}
	}

	root.Set(objCopy)

	return nil
}
