package main

import (
	"fmt"
	"reflect"
	"strings"

	ldap "github.com/ps78674/goldap/message"
)

// apply search filter
func applySearchFilter(o interface{}, f ldap.Filter) (bool, error) {
	switch fmt.Sprintf("%T", f) {
	case "message.FilterEqualityMatch":
		attrName := strings.ToLower(reflect.ValueOf(f).Field(0).String())
		attrValue := strings.ToLower(reflect.ValueOf(f).Field(1).String())

		rValue := reflect.ValueOf(o)
		for i := 0; i < rValue.Type().NumField(); i++ {
			if attrName == "objectclass" && fmt.Sprintf("%T", o) == "main.restUserAttrs" {
				switch attrValue {
				case "posixaccount", "shadowaccount", "organizationalPerson", "inetOrgPerson", "person":
					return true, nil
				}
			}
			if attrName == "objectclass" && fmt.Sprintf("%T", o) == "main.restGroupAttrs" {
				switch attrValue {
				case "posixgroup":
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

func newLDAPAttributeValues(values []string) (out []ldap.AttributeValue) {
	for _, v := range values {
		out = append(out, ldap.AttributeValue(v))
	}
	return
}
