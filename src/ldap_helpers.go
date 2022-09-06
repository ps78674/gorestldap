package main

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

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
	switch f.(type) {
	case ldap.FilterEqualityMatch:
		filter := f.(ldap.FilterEqualityMatch)
		attrName := string(filter.AttributeDesc())
		attrValue := normalizeEntry(string(filter.AssertionValue()))

		if attrName == "entrydn" && strings.HasSuffix(attrValue, cfg.BaseDN) {
			attrValuePair := strings.SplitN(attrValue, ",", 2)
			attrValuePair = strings.SplitN(attrValuePair[0], "=", 2)
			attrName = attrValuePair[0]
			attrValue = attrValuePair[1]
		}

		fieldValue := reflect.ValueOf(o).FieldByNameFunc(func(s string) bool { return strings.EqualFold(s, attrName) })
		if fieldValue.IsValid() {
			fieldType, _ := reflect.TypeOf(o).FieldByNameFunc(func(s string) bool { return strings.EqualFold(s, attrName) })
			switch val := fieldValue.Interface().(type) {
			case uint:
				if fmt.Sprint(val) == attrValue {
					return true, nil
				}
			case string:
				if _, ok := fieldType.Tag.Lookup("ldap_case_sensitive_value"); !ok {
					val = strings.ToLower(val)
					attrValue = strings.ToLower(attrValue)
				}
				if val == attrValue {
					return true, nil
				}
			case []string:
				for _, v := range val {
					if _, ok := fieldType.Tag.Lookup("ldap_case_sensitive_value"); !ok {
						v = strings.ToLower(v)
						attrValue = strings.ToLower(attrValue)
					}
					if v == attrValue {
						return true, nil
					}
				}
			}
		}
	case ldap.FilterAnd:
		for _, filter := range f.(ldap.FilterAnd) {
			ok, err := applySearchFilter(o, filter)
			if !ok || err != nil {
				return ok, err
			}
		}
		return true, nil
	case ldap.FilterOr:
		var anyOk bool

		for _, filter := range f.(ldap.FilterOr) {
			ok, err := applySearchFilter(o, filter)
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
		attrName := fmt.Sprintf("%v", f)
		if strings.ToLower(attrName) == "entrydn" {
			return true, nil
		}
		fieldType, found := reflect.TypeOf(o).FieldByNameFunc(func(s string) bool { return strings.EqualFold(s, attrName) })
		if found && strings.EqualFold(fieldType.Name, attrName) {
			return true, nil
		}
	case ldap.FilterSubstrings:
		filter := f.(ldap.FilterSubstrings)
		attrName := string(filter.Type_())
		attrValues := filter.Substrings()

		fieldValue := reflect.ValueOf(o).FieldByNameFunc(func(s string) bool { return strings.EqualFold(s, attrName) })
		if fieldValue.IsValid() {
			fieldType, _ := reflect.TypeOf(o).FieldByNameFunc(func(s string) bool { return strings.EqualFold(s, attrName) })
			for _, _attrValue := range attrValues {
				si, _ := _attrValue.(ldap.SubstringInitial)
				attrValue := string(si)
				switch val := fieldValue.Interface().(type) {
				case uint:
					if strings.HasPrefix(fmt.Sprint(val), attrValue) {
						return true, nil
					}
				case string:
					if _, ok := fieldType.Tag.Lookup("ldap_case_sensitive_value"); !ok {
						val = strings.ToLower(val)
						attrValue = strings.ToLower(attrValue)
					}
					if strings.HasPrefix(val, attrValue) {
						return true, nil
					}
				case []string:
					for _, v := range val {
						if _, ok := fieldType.Tag.Lookup("ldap_case_sensitive_value"); !ok {
							v = strings.ToLower(v)
							attrValue = strings.ToLower(attrValue)
						}
						if strings.HasPrefix(v, attrValue) {
							return true, nil
						}
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
func createSearchEntry(o interface{}, attrs ldap.AttributeSelection, entryName string) (e ldap.SearchResultEntry) {
	// set entry name
	e.SetObjectName(entryName)

	// if no attrs set -> use * (all)
	if len(attrs) == 0 {
		attrs = append(attrs, "*")
	}

	for _, a := range attrs {
		switch attr := strings.ToLower(string(a)); attr {
		case "entrydn":
			e.AddAttribute("entryDN", ldap.AttributeValue(entryName))
		case "+": // operational only
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
			field, ok := reflect.TypeOf(o).FieldByNameFunc(func(n string) bool { return strings.EqualFold(n, attr) })
			if !ok {
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
	fieldValue := reflect.ValueOf(o).FieldByNameFunc(func(s string) bool { return strings.EqualFold(s, attrName) })
	if !fieldValue.IsValid() {
		return false, errLDAPNoAttr
	}

	fieldType, _ := reflect.TypeOf(o).FieldByNameFunc(func(s string) bool { return strings.EqualFold(s, attrName) })
	if _, ok := fieldType.Tag.Lookup("ldap_skip"); ok {
		return false, errLDAPNoAttr
	}

	switch val := fieldValue.Interface().(type) {
	case uint:
		if fmt.Sprint(val) == attrValue {
			return true, nil
		}
	case string:
		if _, ok := fieldType.Tag.Lookup("ldap_case_sensitive_value"); !ok {
			val = strings.ToLower(val)
			attrValue = strings.ToLower(attrValue)
		}
		if val == attrValue {
			return true, nil
		}
	case []string:
		for _, v := range val {
			if _, ok := fieldType.Tag.Lookup("ldap_case_sensitive_value"); !ok {
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
	objCopy := reflect.New(objType).Elem()
	objCopy.Set(obj)

	fieldValue := objCopy.FieldByNameFunc(func(s string) bool { return strings.EqualFold(s, attrName) })
	if !fieldValue.IsValid() {
		return errLDAPNoAttr
	}

	fieldType, _ := objType.FieldByNameFunc(func(s string) bool { return strings.EqualFold(s, attrName) })
	if _, ok := fieldType.Tag.Lookup("ldap_skip"); ok {
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
