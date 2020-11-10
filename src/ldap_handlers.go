package main

import (
	"fmt"
	"log"
	"strings"

	ldap "github.com/ps78674/goldap/message"
	ldapserver "github.com/ps78674/ldapserver"
)

// handle bind
func handleBind(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	r := m.GetBindRequest()
	log.Printf("client [%d]: bind dn=\"%s\"", m.Client.Numero, r.Name())

	// only simple authentiacion supported
	if r.AuthenticationChoice() != "simple" {
		diagMessage := fmt.Sprintf("authentication method %s is not supported", r.AuthenticationChoice())
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultAuthMethodNotSupported)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: bind error: %s", m.Client.Numero, diagMessage)
		return
	}

	// entry must look like cn=<COMMON_NAME>,dc=base,dc=dn or uid=<COMMON_NAME>,dc=base,dc=dn
	// TODO: change diag message
	bindEntry := trimSpacesAfterComma(string(r.Name()))
	bindEntryAttr, bindEntryName := getEntryAttrAndName(bindEntry)
	if !strings.HasSuffix(bindEntry, baseDN) || (bindEntryAttr != "cn" && bindEntryAttr != "uid") {
		diagMessage := fmt.Sprintf("wrong dn \"%s\"", r.Name())
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidDNSyntax)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: bind error: %s", m.Client.Numero, diagMessage)
		return
	}

	userData := user{}
	for _, u := range entries.Users {
		// compare in lowercase makes bind dn case insensitive
		if strings.ToLower(u.CN) == strings.ToLower(bindEntryName) {
			userData = u
			break
		}
	}

	// user not found
	if len(userData.CN) == 0 {
		diagMessage := fmt.Sprintf("dn \"%s\" not found", r.Name())
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: bind error: %s", m.Client.Numero, diagMessage)
		return
	}

	// empty password in API
	if len(userData.UserPassword) == 0 {
		diagMessage := fmt.Sprintf("got empty password from API for dn \"%s\"", r.Name())
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: bind error: %s", m.Client.Numero, diagMessage)
		return
	}

	ok, err := validatePassword(r.AuthenticationSimple().String(), userData.UserPassword)
	if !ok {
		diagMessage := fmt.Sprintf("wrong password for dn \"%s\"", r.Name())

		if err != nil {
			diagMessage = fmt.Sprintf("%s: %s", diagMessage, err)
		}

		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: bind error: %s", m.Client.Numero, diagMessage)
		return
	}

	// TODO: different json attributes for search / compare / modify ??
	acl := ldapserver.ClientACL{
		BindEntry: userData.CN,
	}

	if userData.LDAPAdmin {
		acl = ldapserver.ClientACL{
			Search:  true,
			Compare: true,
			Modify:  true,
		}
	}

	m.Client.SetACL(acl)

	res := ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess)
	w.Write(res)

	log.Printf("client [%d]: bind result=OK", m.Client.Numero)
}

// search DSE
func handleSearchDSE(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	r := m.GetSearchRequest()

	// attrs := []string{}
	// for _, attr := range r.Attributes() {
	// 	attrs = append(attrs, string(attr))
	// }

	log.Printf("client [%d]: search base=\"%s\" scope=%d filter=\"%s\"", m.Client.Numero, r.BaseObject(), r.Scope(), r.FilterString())

	// TODO: handle search attributes??
	// log.Printf("client [%d]: search attr=%s", m.Client.Numero, strings.Join(attrs, " "))

	e := ldapserver.NewSearchResultEntry("")
	e.AddAttribute("vendorVersion", ldap.AttributeValue(versionString))
	e.AddAttribute("objectClass", "top", "LDAProotDSE")
	e.AddAttribute("supportedLDAPVersion", "3")
	e.AddAttribute("supportedControl", ldap.AttributeValue(ldap.PagedResultsControlOID))
	e.AddAttribute("namingContexts", ldap.AttributeValue(baseDN))
	// e.AddAttribute("supportedSASLMechanisms", "")

	w.Write(e)
	w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))

	log.Printf("client [%d]: search result=OK nentries=1", m.Client.Numero)
}

// handle search
func handleSearch(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	// handle stop signal - see main.go
	stop := false
	go func() {
		<-m.Done
		log.Printf("client [%d]: leaving handleSearch...", m.Client.Numero)
		stop = true
	}()

	r := m.GetSearchRequest()

	attrs := []string{}
	for _, attr := range r.Attributes() {
		attrs = append(attrs, string(attr))
	}

	log.Printf("client [%d]: search base=\"%s\" scope=%d filter=\"%s\"", m.Client.Numero, r.BaseObject(), r.Scope(), r.FilterString())
	log.Printf("client [%d]: search attr=%s", m.Client.Numero, strings.Join(attrs, " "))

	// get 1.2.840.113556.1.4.319 from requested controls
	var controls []string
	var simplePagedResultsControl ldap.SimplePagedResultsControl
	if m.Controls() != nil {
		for _, c := range *m.Controls() {
			switch c.ControlType() {
			case ldap.PagedResultsControlOID:
				controls = append(controls, c.ControlType().String())
				c, err := ldap.ReadPagedResultsControl(c.ControlValue())
				if err != nil {
					log.Printf("client [%d]: error decoding pagedResultsControl: %s", m.Client.Numero, err)
				}
				simplePagedResultsControl = c
			default:
				if c.Criticality().Bool() {
					controls = append(controls, c.ControlType().String()+"(U,C)")
				} else {
					controls = append(controls, c.ControlType().String()+"(U)")
				}
				// Handle control criticality
				// if c.Criticality().Bool() && stopOnUnsupportedCriticalControl {
				// 	diagMessage := fmt.Sprintf("unsupported critical control %s", c.ControlType().String())
				// 	res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnavailableCriticalExtension)
				// 	res.SetDiagnosticMessage(diagMessage)
				// 	w.Write(res)

				// 	log.Printf("client [%d]: search error: %s", m.Client.Numero, diagMessage)
				// 	return
				// }
			}
		}
	}

	log.Printf("client [%d]: search ctrl=%s", m.Client.Numero, strings.Join(controls, " "))
	log.Printf("client [%d]: search sizelimit=%d pagesize=%d", m.Client.Numero, r.SizeLimit(), simplePagedResultsControl.PageSize())

	// base object must be dc=base,dc=dn or cn=<COMMON_NAME>,dc=base,dc=dn
	// TODO: change diag message
	baseObject := trimSpacesAfterComma(string(r.BaseObject()))
	baseObjectAttr, baseObjectName := getEntryAttrAndName(baseObject)
	if baseObject != baseDN && baseObjectAttr != "cn" {
		diagMessage := fmt.Sprintf("wrong base object \"%s\": wrong dn", r.BaseObject())
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultInvalidDNSyntax)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: search error: %s", m.Client.Numero, diagMessage)
		return
	}

	// non admin user allowed to search only over his entry
	if !m.Client.ACL.Search && (baseObjectAttr != "cn" || (baseObjectAttr == "cn" && baseObjectName != m.Client.ACL.BindEntry)) {
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultNoSuchObject)
		w.Write(res)

		log.Printf("client [%d]: search error: insufficient access", m.Client.Numero)
		return
	}

	sizeCounter := 0
	sizeLimitReached := false
	var searchEntries []ldap.SearchResultEntry

	// if baseObject == baseDN AND searchScope == {1, 2} -> add domain entry
	if baseObject == baseDN && r.Scope() != ldap.SearchRequestScopeOneLevel && r.Scope() != ldap.SearchRequestScopeChildren {
		ok, err := applySearchFilter(entries.Domain, r.Filter())
		if err != nil {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(err.Error())
			w.Write(res)

			log.Printf("client [%d]: search error: %s", m.Client.Numero, err)
			return
		}

		if r.SizeLimit().Int() > 0 && sizeCounter >= r.SizeLimit().Int() {
			sizeLimitReached = true
		} else if ok {
			// create search result entry
			e := createSearchResultEntry(entries.Domain, r.Attributes(), baseDN)
			searchEntries = append(searchEntries, e)
			sizeCounter++
		}
	}

	for _, user := range entries.Users {
		if stop {
			return
		}

		// if entry not end with baseDN OR (baseObject == entry AND searchScope == 1) -> skip
		entryName := fmt.Sprintf("cn=%s,%s", user.CN, baseDN)
		if !strings.HasSuffix(entryName, baseObject) || entryName == baseObject &&
			(r.Scope() == ldap.SearchRequestScopeOneLevel || r.Scope() == ldap.SearchRequestScopeChildren) {
			continue
		}

		// apply search filter for each user
		ok, err := applySearchFilter(user, r.Filter())
		if err != nil {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(err.Error())
			w.Write(res)

			log.Printf("client [%d]: search error: %s", m.Client.Numero, err)
			return
		}

		// if filter not applied -> skip user
		if !ok {
			continue
		}

		// if size limit reached -> brake loop
		if r.SizeLimit().Int() > 0 && sizeCounter >= r.SizeLimit().Int() {
			sizeLimitReached = true
			break
		}

		// create search result entry
		e := createSearchResultEntry(user, r.Attributes(), entryName)
		searchEntries = append(searchEntries, e)
		sizeCounter++
	}

	for _, group := range entries.Groups {
		if stop {
			return
		}

		// if entry not end with baseDN OR (baseObject == entry AND searchScope == 1) -> skip
		entryName := fmt.Sprintf("cn=%s,%s", group.CN, baseDN)
		if !strings.HasSuffix(entryName, baseObject) || entryName == baseObject &&
			(r.Scope() == ldap.SearchRequestScopeOneLevel || r.Scope() == ldap.SearchRequestScopeChildren) {
			continue
		}

		// apply search filter for each group
		ok, err := applySearchFilter(group, r.Filter())
		if err != nil {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(err.Error())
			w.Write(res)

			log.Printf("client [%d]: search error: %s", m.Client.Numero, err)
			return
		}

		// if filter not applied -> skip group
		if !ok {
			continue
		}

		// if size limit reached -> brake loop
		if r.SizeLimit().Int() > 0 && sizeCounter >= r.SizeLimit().Int() {
			sizeLimitReached = true
			break
		}

		// create search result entry
		e := createSearchResultEntry(group, r.Attributes(), entryName)
		searchEntries = append(searchEntries, e)
		sizeCounter++
	}

	// FIXME: if nothing found -> ldapserver.LDAPResultNoSuchObject ??
	if len(searchEntries) == 0 {
		w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))

		log.Printf("client [%d]: search result=OK nentries=0", m.Client.Numero)
		return
	}

	newControls := ldap.Controls{}
	entriesWritten := 0

	// if paging requested -> return results in pages
	if simplePagedResultsControl.PageSize().Int() > 0 {
		var cpCookie ldap.OCTETSTRING
		for entriesWritten = 0; entriesWritten != simplePagedResultsControl.PageSize().Int() && m.Client.EntriesSent < len(searchEntries); {
			w.Write(searchEntries[m.Client.EntriesSent]) // m.Client.EntriesSent - how many entries already been sent
			m.Client.EntriesSent++
			entriesWritten++

			// if all entries are sent - send empty cookie
			if m.Client.EntriesSent != len(searchEntries) && entriesWritten == simplePagedResultsControl.PageSize().Int() {
				cpCookie = ldap.OCTETSTRING(programName) // use programName instead of random cookie
			}
		}

		// if all entries are sent - set m.Client.EntriesSent to 0 for next search
		if m.Client.EntriesSent == len(searchEntries) && len(cpCookie) == 0 {
			m.Client.EntriesSent = 0
		}

		v, err := ldap.WritePagedResultsControl(ldap.INTEGER(len(searchEntries)), cpCookie)
		if err != nil {
			diagMessage := fmt.Sprintf("error encoding pagedResultsControl: %s", err)
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultOther)
			res.SetDiagnosticMessage(diagMessage)
			w.Write(res)

			log.Printf("client [%d]: search error: %s", m.Client.Numero, diagMessage)
			return
		}

		c := ldap.NewControl(ldap.PagedResultsControlOID, ldap.BOOLEAN(true), *v)
		newControls = append(newControls, c)

	} else {
		for _, e := range searchEntries {
			w.Write(e)
			entriesWritten++
		}
	}

	resultCode := ldapserver.LDAPResultSuccess
	if (sizeLimitReached && simplePagedResultsControl.PageSize() == 0) ||
		((sizeLimitReached && simplePagedResultsControl.PageSize() > 0) && m.Client.EntriesSent == 0) {
		resultCode = ldapserver.LDAPResultSizeLimitExceeded
	}

	res := ldapserver.NewSearchResultDoneResponse(resultCode)
	responseMessage := ldap.NewLDAPMessageWithProtocolOp(res)

	ldap.SetMessageControls(responseMessage, newControls)
	w.WriteMessage(responseMessage)

	log.Printf("client [%d]: search result=OK nentries=%d", m.Client.Numero, entriesWritten)
}

// handle compare
func handleCompare(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	// handle stop signal - see main.go
	stop := false
	go func() {
		<-m.Done
		log.Printf("client [%d]: leaving handleCompare...", m.Client.Numero)
		stop = true
	}()

	r := m.GetCompareRequest()
	log.Printf("client [%d]: compare dn=\"%s\" attr=\"%s\"", m.Client.Numero, r.Entry(), r.Ava().AttributeDesc())

	// entry must be equal to baseDN or look like cn=<COMMON_NAME>,dc=base,dc=dn
	// TODO: change diag message
	compareEntry := trimSpacesAfterComma(string(r.Entry()))
	compareEntryAttr, compareEntryName := getEntryAttrAndName(compareEntry)
	if !strings.HasSuffix(compareEntry, baseDN) || (compareEntry != baseDN && compareEntryAttr != "cn" && compareEntryAttr != "uid") {
		diagMessage := fmt.Sprintf("wrong dn \"%s\"", r.Entry())
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidDNSyntax)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: compare error: %s", m.Client.Numero, diagMessage)
		return
	}

	// compare for entryDN is not supported
	if strings.ToLower(string(r.Ava().AttributeDesc())) == "entrydn" {
		diagMessage := "entryDN compare not supported"
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: compare error: %s", m.Client.Numero, diagMessage)
		return
	}

	// requested compare on domain and user not ldap admin OR compare entry != bind entry and user not ldap admin
	if (compareEntry == baseDN && !m.Client.ACL.Compare) || (m.Client.ACL.BindEntry != compareEntryName && !m.Client.ACL.Compare) {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultInsufficientAccessRights)
		w.Write(res)

		log.Printf("client [%d]: compare error: insufficient access", m.Client.Numero)
		return
	}

	if compareEntry == baseDN && doCompare(entries.Domain, string(r.Ava().AttributeDesc()), string(r.Ava().AssertionValue())) {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareTrue)
		w.Write(res)

		log.Printf("client [%d]: compare result=TRUE", m.Client.Numero)
		return

	}

	for _, user := range entries.Users {
		if stop {
			return
		}

		if user.CN != compareEntryName {
			continue
		}

		if doCompare(user, string(r.Ava().AttributeDesc()), string(r.Ava().AssertionValue())) {
			res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareTrue)
			w.Write(res)

			log.Printf("client [%d]: compare result=TRUE", m.Client.Numero)
			return
		}
	}
	for _, group := range entries.Groups {
		if stop {
			return
		}

		if group.CN != compareEntryName {
			continue
		}

		if doCompare(group, string(r.Ava().AttributeDesc()), string(r.Ava().AssertionValue())) {
			res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareTrue)
			w.Write(res)

			log.Printf("client [%d]: compare result=TRUE", m.Client.Numero)
			return
		}
	}

	res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareFalse)
	w.Write(res)

	log.Printf("client [%d]: compare result=FALSE", m.Client.Numero)
}

// handle modify (only userPassword for now)
func handleModify(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	// handle stop signal - see main.go
	stop := false
	go func() {
		<-m.Done
		log.Printf("client [%d]: leaving handleModify...", m.Client.Numero)
		stop = true
	}()

	r := m.GetModifyRequest()
	log.Printf("client [%d]: modify dn=\"%s\"", m.Client.Numero, r.Object())

	// TODO: check if string(r.Object()) == baseDN
	//
	// entry must be equal to baseDN or look like cn=<COMMON_NAME>,dc=base,dc=dn
	// TODO: change diag message
	modifyEntry := trimSpacesAfterComma(string(r.Object()))
	modifyEntryAttr, modifyEntryName := getEntryAttrAndName(modifyEntry)
	if !strings.HasSuffix(modifyEntry, baseDN) || (modifyEntryAttr != "cn" && modifyEntryAttr != "uid") {
		diagMessage := fmt.Sprintf("wrong dn \"%s\"", r.Object())
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidDNSyntax)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: modify error: %s", m.Client.Numero, diagMessage)
		return
	}

	// ldap admin can do modify on all entries
	if m.Client.ACL.BindEntry != modifyEntryName && !m.Client.ACL.Modify {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultInsufficientAccessRights)
		w.Write(res)

		log.Printf("client [%d]: modify error: insufficient access", m.Client.Numero)
		return
	}

	for _, c := range r.Changes() {
		if stop {
			return
		}

		// check operation type
		log.Printf("client [%d]: modify op=%d", m.Client.Numero, c.Operation())
		if c.Operation().Int() != ldap.ModifyRequestChangeOperationReplace {
			diagMessage := fmt.Sprintf("wrong operation %d: only replace (2) is supported", c.Operation().Int())
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(diagMessage)
			w.Write(res)

			log.Printf("client [%d]: modify error: %s", m.Client.Numero, diagMessage)
			return
		}

		// check attribute name
		log.Printf("client [%d]: modify attr=%s", m.Client.Numero, c.Modification().Type_())
		if c.Modification().Type_() != "userPassword" {
			diagMessage := fmt.Sprintf("wrong attribute %s, only userPassword is supported", c.Modification().Type_())
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(diagMessage)
			w.Write(res)

			log.Printf("client [%d]: modify error: %s", m.Client.Numero, diagMessage)
			return
		}

		if len(c.Modification().Vals()) > 1 {
			diagMessage := "more than 1 value for userPassword is not supported"
			res := ldapserver.NewBindResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(diagMessage)
			w.Write(res)

			log.Printf("client [%d]: modify error: %s", m.Client.Numero, diagMessage)
			return
		}

		if err := doModify(modifyEntryName, string(c.Modification().Vals()[0])); err != nil {
			res := ldapserver.NewBindResponse(ldapserver.LDAPResultOther)
			res.SetDiagnosticMessage(err.Error())
			w.Write(res)

			log.Printf("client [%d]: modify error: %s", m.Client.Numero, err)
			return
		}
	}

	res := ldapserver.NewModifyResponse(ldapserver.LDAPResultSuccess)
	w.Write(res)

	log.Printf("client [%d]: modify result=OK", m.Client.Numero)
}
