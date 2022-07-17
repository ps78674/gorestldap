package main

import (
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
		filter := f.(ldap.FilterEqualityMatch)
		attrName := strings.ToLower(string(filter.AttributeDesc())) // CN|cn -> compare in lowercase
		attrValue := string(filter.AssertionValue())

		rValue := reflect.ValueOf(o)
		for i := 0; i < rValue.Type().NumField(); i++ {
			if attrName == "entrydn" && strings.HasSuffix(attrValue, cfg.BaseDN) {
				newValues := strings.SplitN(strings.TrimSuffix(attrValue, ","+cfg.BaseDN), "=", 2)
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
					if _, ok := rValue.Type().Field(i).Tag.Lookup("lower"); ok {
						attrValue = strings.ToLower(attrValue)
						restValue = strings.ToLower(restValue)
					}
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
				(strings.EqualFold(rValue.Type().Field(i).Name, reflect.ValueOf(f).String()) && rValue.Field(i).Len() > 0) {
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
						if _, ok := rValue.Type().Field(i).Tag.Lookup("lower"); ok {
							attrValue = strings.ToLower(attrValue)
							restValue = strings.ToLower(restValue)
						}
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
	rValue := reflect.ValueOf(o)
	for i := 0; i < rValue.Type().NumField(); i++ {
		if !strings.EqualFold(rValue.Type().Field(i).Name, attrName) {
			continue
		}
		switch rValue.Field(i).Interface().(type) {
		case string:
			objValue := rValue.Field(i).String()
			if _, ok := rValue.Type().Field(i).Tag.Lookup("ldap_compare_cs"); !ok {
				objValue = strings.ToLower(objValue)
				attrValue = strings.ToLower(attrValue)
			}
			if objValue == attrValue {
				return true
			}
		case []string:
			for j := 0; j < rValue.Field(i).Len(); j++ {
				objValue := rValue.Field(i).Index(j).String()
				if _, ok := rValue.Type().Field(i).Tag.Lookup("ldap_compare_cs"); !ok {
					objValue = strings.ToLower(objValue)
					attrValue = strings.ToLower(attrValue)
				}
				if objValue == attrValue {
					return true
				}
			}
		}
	}

	return false
}

// create slice of ldap attributes
func newLDAPAttributeValues(in interface{}) (out []ldap.AttributeValue) {
	switch in := in.(type) {
	case []string:
		for _, v := range in {
			out = append(out, ldap.AttributeValue(v))
		}
	case string:
		out = append(out, ldap.AttributeValue(in))
	}

	return
}

// normalizeEntry returns entry in lowercase without spaces after comma
// e.g. DC=test, dc=EXAMPLE,  dc=com -> dc=test,dc=example,dc=com
func normalizeEntry(s string) string {
	s = strings.ToLower(s)
	re := regexp.MustCompile(`(,[\s]+)`)
	return re.ReplaceAllString(s, ",")
}

// modify password via api
func doModify(cn string, pw string) error {
	// b, err := json.Marshal(passwordData{CN: cn, UserPassword: pw})
	// if err != nil {
	// 	return err
	// }

	// reqURL := fmt.Sprintf("%s%s", cfg.URL, urlLDAPUsers)
	// nb, err := doRequest(reqURL, b)
	// if err != nil {
	// 	return err
	// }

	// if !bytes.Equal(b, nb) {
	// 	return fmt.Errorf("%s", nb)
	// }

	return nil
}

// get all attributes
func getAllAttrsAndValues(o interface{}, operationalOnly bool) (ret []attrValues) {
	rValue := reflect.ValueOf(o)
	for i := 0; i < rValue.NumField(); i++ {
		if _, ok := rValue.Type().Field(i).Tag.Lookup("ldap_skip"); ok {
			continue
		}
		if _, ok := rValue.Type().Field(i).Tag.Lookup("ldap_operational"); (!ok && operationalOnly) || (ok && !operationalOnly) {
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
func getAttrValues(o interface{}, fieldName string) (values interface{}) {
	field, _ := reflect.TypeOf(o).FieldByNameFunc(func(n string) bool { return strings.EqualFold(n, fieldName) })
	if _, ok := field.Tag.Lookup("ldap_skip"); ok {
		return
	}

	rValue := reflect.ValueOf(o).FieldByName(field.Name)
	if rValue.IsValid() {
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
				values := getAttrValues(o, attr)
				if values != nil {
					e.AddAttribute(ldap.AttributeDescription(a), newLDAPAttributeValues(values)...)
				}
			}
		}
	}

	return
}

func getEntryAttrAndName(e string) (attr string, name string) {
	str := strings.SplitN(e, ",", 2)[0]

	splitted := strings.SplitN(str, "=", 2)
	attr = splitted[0]
	name = splitted[1]

	return
}
