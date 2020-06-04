package main

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	ldap "github.com/ps78674/goldap/message"
)

// apply search filter for each object
func applySearchFilter(o interface{}, f ldap.Filter) (bool, error) {
	switch fmt.Sprintf("%T", f) {
	case "message.FilterEqualityMatch":
		attrName := strings.ToLower(reflect.ValueOf(f).Field(0).String()) // CN|cn -> compare in lowercase
		attrValue := reflect.ValueOf(f).Field(1).String()

		rValue := reflect.ValueOf(o)
		for i := 0; i < rValue.Type().NumField(); i++ {
			if attrName == "objectclass" && fmt.Sprintf("%T", o) == "main.restUserAttrs" {
				switch attrValue {
				case "posixAccount", "shadowAccount", "organizationalPerson", "inetOrgPerson", "person":
					return true, nil
				}
			}
			if attrName == "objectclass" && fmt.Sprintf("%T", o) == "main.restGroupAttrs" {
				switch attrValue {
				case "posixGroup":
					return true, nil
				}
			}

			if strings.ToLower(rValue.Type().Field(i).Tag.Get("json")) == attrName {
				for j := 0; j < rValue.Field(i).Len(); j++ {
					if rValue.Field(i).Index(j).String() == attrValue {
						return true, nil
					}
				}
			}
		}
	case "message.FilterAnd":
		items := reflect.ValueOf(f)
		for i := 0; i < items.Len(); i++ {
			filter := items.Index(i).Interface().(ldap.Filter)

			ok, err := applySearchFilter(o, filter)
			if err != nil {
				return false, err
			}

			if !ok {
				return false, nil
			}
		}
		return true, nil
	case "message.FilterOr":
		anyOk := false

		items := reflect.ValueOf(f)
		for i := 0; i < items.Len(); i++ {
			filter := items.Index(i).Interface().(ldap.Filter)

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
	case "message.FilterPresent":
		rValue := reflect.ValueOf(o)
		for i := 0; i < rValue.Type().NumField(); i++ {
			if strings.ToLower(reflect.ValueOf(f).String()) == "objectclass" ||
				(strings.ToLower(rValue.Type().Field(i).Tag.Get("json")) == strings.ToLower(reflect.ValueOf(f).String()) && rValue.Field(i).Len() > 0) {
				return true, nil
			}
		}
	default:
		return false, fmt.Errorf("unsupported filter type '%T'", f)
	}

	return false, nil
}

// actual compare
func doCompare(o interface{}, attrName string, attrValue string) bool {
	rValue := reflect.ValueOf(o)
	for i := 0; i < rValue.Type().NumField(); i++ {
		if strings.ToLower(rValue.Type().Field(i).Tag.Get("json")) == strings.ToLower(attrName) {
			for j := 0; j < rValue.Field(i).Len(); j++ {
				if rValue.Field(i).Index(j).String() == attrValue {
					return true
				}
			}
		}
	}

	return false
}

// create slice of ldap attributes
func newLDAPAttributeValues(values []string) (out []ldap.AttributeValue) {
	for _, v := range values {
		out = append(out, ldap.AttributeValue(v))
	}
	return
}

// trim spaces for entries (dc=test, dc.example,  dc=org -> dc=test,dc.example,dc=org)
func trimSpacesAfterComma(s string) string {
	re := regexp.MustCompile("(,[\\s]+)")
	return re.ReplaceAllString(s, ",")
}
