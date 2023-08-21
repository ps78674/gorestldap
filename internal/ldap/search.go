package ldap

import (
	"fmt"
	"reflect"
	"strings"

	ldap "github.com/ps78674/goldap/message"
	"github.com/ps78674/gorestldap/internal/config"
	"github.com/ps78674/gorestldap/internal/data"
	"github.com/ps78674/gorestldap/internal/ldaputils"
	ldapserver "github.com/ps78674/ldapserver"
	"github.com/sirupsen/logrus"
)

func handleSearchDSE(w ldapserver.ResponseWriter, m *ldapserver.Message, baseDN string, logger *logrus.Logger) {
	r := m.GetSearchRequest()

	logger.Infof("client [%d]: search base='%s' scope=%d filter='%s'", m.Client.Numero(), r.BaseObject(), r.Scope(), r.FilterString())

	searchAttrs := []string{}
	for _, attr := range r.Attributes() {
		searchAttrs = append(searchAttrs, string(attr))
	}

	logger.Infof("client [%d]: search attr=%s", m.Client.Numero(), strings.Join(searchAttrs, " "))

	rootDSE := data.DSE{
		ObjectClass:          []string{"top", "LDAProotDSE"},
		VendorVersion:        config.VersionString,
		SupportedLDAPVersion: 3,
		SupportedControl:     []string{string(ldap.PagedResultsControlOID)},
		NamingContexts:       []string{baseDN},
	}

	e := createSearchEntry(rootDSE, searchAttrs, "")

	w.Write(e)
	w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))

	logger.Infof("client [%d]: search result=OK nentries=1", m.Client.Numero())
}

func handleSearch(w ldapserver.ResponseWriter, m *ldapserver.Message, entries *data.Entries, baseDN, usersOUName, groupsOUName string, respectCritical bool, logger *logrus.Logger) {
	entries.RLock()
	defer entries.RUnlock()

	r := m.GetSearchRequest()

	logger.Infof("client [%d]: search base='%s' scope=%d filter='%s'", m.Client.Numero(), r.BaseObject(), r.Scope(), r.FilterString())

	searchAttrs := []string{}
	for _, attr := range r.Attributes() {
		searchAttrs = append(searchAttrs, string(attr))
	}

	logger.Infof("client [%d]: search attr=%s", m.Client.Numero(), strings.Join(searchAttrs, " "))

	// check requested controls
	var controls []string
	var simplePagedResultsControl ldap.SimplePagedResultsControl
	var gotUCControl bool
	if m.Controls() != nil {
		for _, c := range *m.Controls() {
			switch c.ControlType() {
			// 1.2.840.113556.1.4.319 (pagedSearch)
			case ldap.PagedResultsControlOID:
				controls = append(controls, c.ControlType().String())
				c, err := ldap.ReadPagedResultsControl(c.ControlValue())
				if err != nil {
					logger.Errorf("client [%d]: error decoding pagedResultsControl: %s", m.Client.Numero(), err)
				}
				simplePagedResultsControl = c
			default:
				if c.Criticality().Bool() {
					controls = append(controls, c.ControlType().String()+"(U,C)")
					gotUCControl = true
				} else {
					controls = append(controls, c.ControlType().String()+"(U)")
				}
			}
		}
	}

	logger.Infof("client [%d]: search ctrl=%s", m.Client.Numero(), strings.Join(controls, " "))

	// check for unsupported critical controls
	if gotUCControl && respectCritical {
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnavailableCriticalExtension)
		w.Write(res)

		logger.Errorf("client [%d]: search error: got unsupported critical controls, aborting", m.Client.Numero())
		return
	}

	logger.Infof("client [%d]: search sizelimit=%d pagesize=%d", m.Client.Numero(), r.SizeLimit(), simplePagedResultsControl.PageSize())

	// handle stop signal
	select {
	case <-m.Done:
		logger.Infof("client [%d]: leaving handleSearch...", m.Client.Numero())
		return
	default:
	}

	// setup baseObject
	var baseObject string
	if len(r.BaseObject()) == 0 {
		baseObject = baseDN
	} else {
		baseObject = ldaputils.NormalizeEntry(string(r.BaseObject()))
	}

	// get ACLs & search control
	acl := clientACL{}
	searchControl := clientSearchControl{}
	if addData := m.Client.GetAddData(); addData != nil {
		acl = addData.(additionalData).acl
		searchControl = addData.(additionalData).sc
	}

	// non admin user allowed to search only over his entry
	if !acl.search && baseObject != acl.bindEntry {
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultNoSuchObject)
		w.Write(res)

		logger.Warnf("client [%d]: search insufficient access", m.Client.Numero())
		return
	}

	entriesWritten := 0
	sizeLimitReached := false

	// check if more entries is available
	lastIteration := false

	// how much entries is left
	left := simplePagedResultsControl.PageSize().Int()
	if left == 0 {
		// 3 = domain + users ou + groups ou
		left = 3 + len(entries.Users) + len(entries.Groups)
	}

	// if domain processed -> go to users
	if searchControl.domainDone {
		goto ous
	}

	// got match
	if baseObject == baseDN {
		// if searchScope == {base, sub} -> add domain entry
		if r.Scope() == ldap.SearchRequestScopeBaseObject || r.Scope() == ldap.SearchRequestScopeSubtree {
			ok, err := applySearchFilter(entries.Domain, r.Filter())
			if err != nil {
				res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
				res.SetDiagnosticMessage(err.Error())
				w.Write(res)

				logger.Errorf("client [%d]: search error: %s", m.Client.Numero(), err)
				return
			}

			if r.SizeLimit().Int() > 0 && searchControl.sent == r.SizeLimit().Int() {
				sizeLimitReached = true
				goto end
			} else if ok {
				e := createSearchEntry(entries.Domain, searchAttrs, baseDN)
				w.Write(e)

				searchControl.sent++
				entriesWritten++
				left--

				// base object found & written -> should not search more
				if r.Scope() == ldap.SearchRequestScopeBaseObject {
					goto end
				}
			}
		}

		// should search only one level down, over OUs
		if r.Scope() == ldap.SearchRequestScopeOneLevel {
			searchControl.usersDone = true
			searchControl.groupsDone = true
		}
	}

	// domain processed
	searchControl.domainDone = true

ous:
	// if ous processed -> go to users
	if searchControl.ousDone {
		goto users
	}

	for i := searchControl.count; i < len(entries.OUs); i++ {
		// handle stop signal
		select {
		case <-m.Done:
			logger.Infof("client [%d]: leaving handleSearch...", m.Client.Numero())
			return
		default:
		}

		if left == 0 && !lastIteration {
			lastIteration = true
		}

		if !lastIteration {
			searchControl.count++
		}

		entryName := fmt.Sprintf("ou=%s,%s", entries.OUs[i].OU, baseDN)

		// entry does not belong to base object
		if !strings.HasSuffix(entryName, baseObject) {
			continue
		}

		// entry != baseobject & scope == base requested
		if r.Scope() == ldap.SearchRequestScopeBaseObject && entryName != baseObject {
			continue
		}

		// search sublevel based on ou name (users or groups)
		if entryName == baseObject && (r.Scope() == ldap.SearchRequestScopeOneLevel || r.Scope() == ldap.SearchRequestScopeChildren) {
			searchControl.count = 0
			switch entries.OUs[i].OU {
			case usersOUName:
				searchControl.groupsDone = true
				goto users
			case groupsOUName:
				searchControl.usersDone = true
				goto groups
			}
		}

		// if size limit reached -> go to response
		if r.SizeLimit().Int() > 0 && searchControl.sent == r.SizeLimit().Int() {
			sizeLimitReached = true
			goto end
		}

		// apply search filter for each ou
		ok, err := applySearchFilter(entries.OUs[i], r.Filter())
		if err != nil {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(err.Error())
			w.Write(res)

			logger.Errorf("client [%d]: search error: %s", m.Client.Numero(), err)
			return
		}

		// if filter not applied -> skip ou
		if !ok {
			continue
		}

		if lastIteration {
			goto end
		}

		e := createSearchEntry(entries.OUs[i], searchAttrs, entryName)
		w.Write(e)

		searchControl.sent++
		entriesWritten++
		left--

		// base object found & written -> should not search more
		if r.Scope() == ldap.SearchRequestScopeBaseObject {
			goto end
		}
	}

	// ous processed
	searchControl.count = 0
	searchControl.ousDone = true

users:
	// if users processed -> go to groups
	if searchControl.usersDone {
		goto groups
	}

	for i := searchControl.count; i < len(entries.Users); i++ {
		// handle stop signal
		select {
		case <-m.Done:
			logger.Infof("client [%d]: leaving handleSearch...", m.Client.Numero())
			return
		default:
		}

		if left == 0 && !lastIteration {
			lastIteration = true
		}

		if !lastIteration {
			searchControl.count++
		}

		entryName := fmt.Sprintf("cn=%s,ou=%s,%s", entries.Users[i].CN, usersOUName, baseDN)

		// entry does not belong to base object
		if !strings.HasSuffix(entryName, baseObject) {
			continue
		}

		// entry != baseobject & scope == base requested
		if r.Scope() == ldap.SearchRequestScopeBaseObject && entryName != baseObject {
			continue
		}

		// user does not have sublevel, END
		if entryName == baseObject && (r.Scope() == ldap.SearchRequestScopeOneLevel || r.Scope() == ldap.SearchRequestScopeChildren) {
			searchControl.usersDone = true
			searchControl.groupsDone = true
			goto end
		}

		// if size limit reached -> go to response
		if r.SizeLimit().Int() > 0 && searchControl.sent == r.SizeLimit().Int() {
			sizeLimitReached = true
			goto end
		}

		// apply search filter for each user
		ok, err := applySearchFilter(entries.Users[i], r.Filter())
		if err != nil {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(err.Error())
			w.Write(res)

			logger.Errorf("client [%d]: search error: %s", m.Client.Numero(), err)
			return
		}

		// if filter not applied -> skip user
		if !ok {
			continue
		}

		if lastIteration {
			goto end
		}

		e := createSearchEntry(entries.Users[i], searchAttrs, entryName)
		w.Write(e)

		searchControl.sent++
		entriesWritten++
		left--

		// base object found & written -> should not search more
		if r.Scope() == ldap.SearchRequestScopeBaseObject {
			goto end
		}
	}

	// users processed
	searchControl.count = 0
	searchControl.usersDone = true

groups:
	// if groups processed -> go to end
	if searchControl.groupsDone {
		goto end
	}

	for i := searchControl.count; i < len(entries.Groups); i++ {
		// handle stop signal
		select {
		case <-m.Done:
			logger.Infof("client [%d]: leaving handleSearch...", m.Client.Numero())
			return
		default:
		}

		if left == 0 && !lastIteration {
			lastIteration = true
		}

		if !lastIteration {
			searchControl.count++
		}

		entryName := fmt.Sprintf("cn=%s,ou=%s,%s", entries.Groups[i].CN, groupsOUName, baseDN)

		// entry does not belong to base object
		if !strings.HasSuffix(entryName, baseObject) {
			continue
		}

		// entry != baseobject & scope == base requested
		if r.Scope() == ldap.SearchRequestScopeBaseObject && entryName != baseObject {
			continue
		}

		// user does not have sublevel, END
		if entryName == baseObject && (r.Scope() == ldap.SearchRequestScopeOneLevel || r.Scope() == ldap.SearchRequestScopeChildren) {
			searchControl.usersDone = true
			searchControl.groupsDone = true
			goto end
		}

		// if size limit reached -> brake loop
		if r.SizeLimit().Int() > 0 && searchControl.sent == r.SizeLimit().Int() {
			sizeLimitReached = true
			goto end
		}

		// apply search filter for each group
		ok, err := applySearchFilter(entries.Groups[i], r.Filter())
		if err != nil {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(err.Error())
			w.Write(res)

			logger.Errorf("client [%d]: search error: %s", m.Client.Numero(), err)
			return
		}

		// if filter not applied -> skip group
		if !ok {
			continue
		}

		if lastIteration {
			goto end
		}

		e := createSearchEntry(entries.Groups[i], searchAttrs, entryName)
		w.Write(e)

		searchControl.sent++
		entriesWritten++
		left--

		// base object found & written -> should not search more
		if r.Scope() == ldap.SearchRequestScopeBaseObject {
			goto end
		}
	}

	// groups processed
	searchControl.count = 0
	searchControl.groupsDone = true

end:
	newControls := ldap.Controls{}
	if simplePagedResultsControl.PageSize().Int() > 0 {
		cpCookie := ldap.OCTETSTRING(config.ProgramName)

		// end search
		if (searchControl.domainDone && searchControl.ousDone && searchControl.usersDone && searchControl.groupsDone) || sizeLimitReached {
			cpCookie = ldap.OCTETSTRING("")
			// end search -> cleanup search control
			searchControl = clientSearchControl{}
		}

		// encode new paged results control
		v, err := ldap.WritePagedResultsControl(ldap.INTEGER(0), cpCookie)
		if err != nil {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultProtocolError)
			w.Write(res)

			logger.Errorf("client [%d]: search error: error encoding pagedResultsControl: %s", m.Client.Numero(), err)
			return
		}

		c := ldap.NewControl(ldap.PagedResultsControlOID, ldap.BOOLEAN(true), *v)
		newControls = append(newControls, c)
	} else {
		// end search -> cleanup search control
		searchControl = clientSearchControl{}
	}

	// update additional data with new search control
	m.Client.SetAddData(additionalData{acl: acl, sc: searchControl})

	resultCode := ldapserver.LDAPResultSuccess
	if sizeLimitReached {
		resultCode = ldapserver.LDAPResultSizeLimitExceeded
	}

	res := ldapserver.NewSearchResultDoneResponse(resultCode)
	responseMessage := ldap.NewLDAPMessageWithProtocolOp(res)

	ldap.SetMessageControls(responseMessage, newControls)
	w.WriteMessage(responseMessage)

	logger.Infof("client [%d]: search result=OK nentries=%d", m.Client.Numero(), entriesWritten)
}

// applySearchFilter returns true if object 'o' fits filter 'f'
func applySearchFilter(o interface{}, f ldap.Filter) (bool, error) {
	switch filter := f.(type) {
	case ldap.FilterEqualityMatch:
		attrName := string(filter.AttributeDesc())
		attrValue := string(filter.AssertionValue())

		if strings.ToLower(attrName) == "entrydn" {
			entry := ldaputils.NormalizeEntry(string(filter.AssertionValue()))
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
				e.AddAttribute(ldap.AttributeDescription(a), newLDAPAttributeValues(fieldValue.Interface())...)
			}
		}
	}

	return
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
