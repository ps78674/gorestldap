package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	ldap "github.com/ps78674/goldap/message"
)

type passwordData struct {
	CN           string `json:"cn"`
	UserPassword string `json:"userPassword"`
}

type attrValues struct {
	Attr   string
	Values interface{}
}

// apply search filter for each object
func applySearchFilter(o interface{}, f ldap.Filter) (bool, error) {
	switch f.(type) {
	case ldap.FilterEqualityMatch:
		attrName := strings.ToLower(reflect.ValueOf(f).Field(0).String()) // CN|cn -> compare in lowercase
		attrValue := reflect.ValueOf(f).Field(1).String()

		rValue := reflect.ValueOf(o)
		for i := 0; i < rValue.Type().NumField(); i++ {
			if attrName == "objectclass" && reflect.TypeOf(o).String() == "main.restUser" {
				switch strings.ToLower(attrValue) {
				case "top", "posixaccount", "shadowaccount", "organizationalperson", "inetorgperson", "person":
					return true, nil
				}
			}
			if attrName == "objectclass" && reflect.TypeOf(o).String() == "main.restGroup" {
				switch strings.ToLower(attrValue) {
				case "top", "posixgroup":
					return true, nil
				}
			}
			if attrName == "entrydn" && strings.HasSuffix(attrValue, baseDN) {
				newValues := strings.SplitN(strings.TrimSuffix(attrValue, fmt.Sprintf(",%s", baseDN)), "=", 2)
				attrName = newValues[0]
				attrValue = newValues[1]
			}
			if strings.ToLower(rValue.Type().Field(i).Name) != attrName {
				continue
			}
			switch rValue.Field(i).Interface().(type) {
			case string:
				restValue := rValue.Field(i).String()
				// compare values case insensitive for all attrs except userPassword
				if attrName != "userpassword" {
					restValue = strings.ToLower(restValue)
					attrValue = strings.ToLower(attrValue)
				}
				if restValue == attrValue {
					return true, nil
				}
			case []string:
				for j := 0; j < rValue.Field(i).Len(); j++ {
					restValue := rValue.Field(i).Index(j).String()
					if restValue == attrValue {
						return true, nil
					}
				}
			}
		}
	case ldap.FilterAnd:
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
	case ldap.FilterOr:
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
	case ldap.FilterPresent:
		rValue := reflect.ValueOf(o)
		for i := 0; i < rValue.Type().NumField(); i++ {
			if strings.ToLower(reflect.ValueOf(f).String()) == "objectclass" || strings.ToLower(reflect.ValueOf(f).String()) == "entrydn" ||
				(strings.ToLower(rValue.Type().Field(i).Name) == strings.ToLower(reflect.ValueOf(f).String()) && rValue.Field(i).Len() > 0) {
				return true, nil
			}
		}
	case ldap.FilterSubstrings:
		attrName := strings.ToLower(reflect.ValueOf(f).Field(0).String()) // CN|cn -> compare in lowercase
		attrValues := reflect.ValueOf(f).Field(1)

		rValue := reflect.ValueOf(o)
		for i := 0; i < rValue.Type().NumField(); i++ {
			if strings.ToLower(rValue.Type().Field(i).Name) != attrName {
				continue
			}

			for j := 0; j < attrValues.Len(); j++ {
				attrValue := attrValues.Index(j).Elem().String()
				switch rValue.Field(i).Interface().(type) {
				case string:
					restValue := rValue.Field(i).String()
					// compare values case insensitive for all attrs except userPassword
					if attrName != "userpassword" {
						restValue = strings.ToLower(restValue)
						attrValue = strings.ToLower(attrValue)
					}
					if strings.HasPrefix(restValue, attrValue) {
						return true, nil
					}
				case []string:
					for k := 0; k < rValue.Field(i).Len(); k++ {
						restValue := rValue.Field(i).Index(k).String()
						if strings.HasPrefix(restValue, attrValue) {
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

// actual compare
func doCompare(o interface{}, attrName string, attrValue string) bool {
	attrName = strings.ToLower(attrName)

	rValue := reflect.ValueOf(o)
	for i := 0; i < rValue.Type().NumField(); i++ {
		if strings.ToLower(rValue.Type().Field(i).Name) != attrName {
			continue
		}
		switch rValue.Field(i).Interface().(type) {
		case string:
			// compare values case insensitive for all attrs except userPassword
			restValue := rValue.Field(i).String()
			if attrName != "userpassword" {
				restValue = strings.ToLower(restValue)
				attrValue = strings.ToLower(attrValue)
			}
			if restValue == attrValue {
				return true
			}
		case []string:
			for j := 0; j < rValue.Field(i).Len(); j++ {
				restValue := rValue.Field(i).Index(j).String()
				if restValue == attrValue {
					return true
				}
			}
		}
	}

	return false
}

// create slice of ldap attributes
func newLDAPAttributeValues(in interface{}) (out []ldap.AttributeValue) {
	switch in.(type) {
	case []string:
		for _, v := range in.([]string) {
			out = append(out, ldap.AttributeValue(v))
		}
	case string:
		out = append(out, ldap.AttributeValue(in.(string)))
	}

	return
}

// trim spaces for entries (dc=test, dc.example,  dc=org -> dc=test,dc.example,dc=org)
func trimSpacesAfterComma(s string) string {
	re := regexp.MustCompile("(,[\\s]+)")
	return re.ReplaceAllString(s, ",")
}

// modify password via api
func doModify(cn string, pw string) error {
	b, err := json.Marshal(passwordData{CN: cn, UserPassword: pw})
	if err != nil {
		return err
	}

	reqURL := fmt.Sprintf("%s%s", restURL, urlLDAPUsers)
	nb, err := doRequest(reqURL, b)
	if err != nil {
		return err
	}

	if bytes.Compare(b, nb) != 0 {
		return fmt.Errorf("%s", nb)
	}

	return nil
}

// get all attributes
func getAllAttrsAndValues(o interface{}, operationalOnly bool) (ret []attrValues) {
	rValue := reflect.ValueOf(o)
	for i := 0; i < rValue.NumField(); i++ {
		if rValue.Type().Field(i).Tag.Get("skip") == "yes" {
			continue
		}
		if operationalOnly && rValue.Type().Field(i).Tag.Get("hidden") != "yes" {
			continue
		}
		if !operationalOnly && rValue.Type().Field(i).Tag.Get("hidden") == "yes" {
			continue
		}

		attr := rValue.Type().Field(i).Tag.Get("json")
		if attr == "" {
			attr = rValue.Type().Field(i).Name
		}

		values := rValue.Field(i).Interface()

		ret = append(ret, attrValues{Attr: attr, Values: values})
	}

	return ret
}

// get struct field values by field name
func getAttrValues(o interface{}, fieldName string) (len int, values interface{}) {
	field, _ := reflect.TypeOf(o).FieldByNameFunc(func(n string) bool { return strings.ToLower(n) == fieldName })
	if field.Tag.Get("skip") == "yes" {
		return
	}

	rValue := reflect.ValueOf(o).FieldByName(field.Name)
	if rValue.IsValid() {
		len = rValue.Len()
		values = rValue.Interface()
	}

	return
}

func createSearchResultEntry(o interface{}, attrs ldap.AttributeSelection, entryName string) (e ldap.SearchResultEntry) {
	// set entry name
	e.SetObjectName(entryName)

	// // if no specific attributes requested -> add all attributes
	if len(attrs) == 0 {
		for _, v := range getAllAttrsAndValues(o, false) {
			e.AddAttribute(ldap.AttributeDescription(v.Attr), newLDAPAttributeValues(v.Values)...)
		}
	}

	// if some attributes requested -> add only those attributes
	if len(attrs) > 0 {
		for _, a := range attrs {
			switch attr := strings.ToLower(string(a)); attr {
			case "entrydn":
				e.AddAttribute("entryDN", ldap.AttributeValue(entryName))
			case "+":
				for _, v := range getAllAttrsAndValues(o, true) {
					e.AddAttribute(ldap.AttributeDescription(v.Attr), newLDAPAttributeValues(v.Values)...)
				}
			case "*":
				for _, v := range getAllAttrsAndValues(o, false) {
					e.AddAttribute(ldap.AttributeDescription(v.Attr), newLDAPAttributeValues(v.Values)...)
				}
			default:
				len, values := getAttrValues(o, attr)
				if len > 0 {
					e.AddAttribute(ldap.AttributeDescription(a), newLDAPAttributeValues(values)...)
				}
			}
		}
	}

	return
}

func getEntryAttrAndName(e string) (attr string, name string) {
	trimmed := strings.TrimSuffix(e, ","+baseDN)

	// entry == baseDN
	if trimmed == e {
		return
	}

	splitted := strings.SplitN(trimmed, "=", 2)
	attr = splitted[0]
	name = splitted[1]

	return
}
