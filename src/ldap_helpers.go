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
			if _, ok := rValue.Type().Field(i).Tag.Lookup("ldap_case_sensitive_value"); !ok {
				objValue = strings.ToLower(objValue)
				attrValue = strings.ToLower(attrValue)
			}
			if objValue == attrValue {
				return true
			}
		case []string:
			for j := 0; j < rValue.Field(i).Len(); j++ {
				objValue := rValue.Field(i).Index(j).String()
				if _, ok := rValue.Type().Field(i).Tag.Lookup("ldap_case_sensitive_value"); !ok {
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
