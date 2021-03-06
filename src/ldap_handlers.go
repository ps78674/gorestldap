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
	entries.Mutex.RLock()
	defer entries.Mutex.RUnlock()

	r := m.GetBindRequest()
	log.Printf("client [%d]: bind dn=\"%s\"", m.Client.Numero(), r.Name())

	// only simple authentiacion supported
	if r.AuthenticationChoice() != "simple" {
		diagMessage := fmt.Sprintf("authentication method %s is not supported", r.AuthenticationChoice())
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultAuthMethodNotSupported)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: bind error: %s", m.Client.Numero(), diagMessage)
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

		log.Printf("client [%d]: bind error: %s", m.Client.Numero(), diagMessage)
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

		log.Printf("client [%d]: bind error: %s", m.Client.Numero(), diagMessage)
		return
	}

	// empty password in API
	if len(userData.UserPassword) == 0 {
		diagMessage := fmt.Sprintf("got empty password from API for dn \"%s\"", r.Name())
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: bind error: %s", m.Client.Numero(), diagMessage)
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

		log.Printf("client [%d]: bind error: %s", m.Client.Numero(), diagMessage)
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

	log.Printf("client [%d]: bind result=OK", m.Client.Numero())
}

// search DSE
func handleSearchDSE(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	entries.Mutex.RLock()
	defer entries.Mutex.RUnlock()

	r := m.GetSearchRequest()

	// attrs := []string{}
	// for _, attr := range r.Attributes() {
	// 	attrs = append(attrs, string(attr))
	// }

	log.Printf("client [%d]: search base=\"%s\" scope=%d filter=\"%s\"", m.Client.Numero(), r.BaseObject(), r.Scope(), r.FilterString())

	// TODO: handle search attributes??
	// log.Printf("client [%d]: search attr=%s", m.Client.Numero(), strings.Join(attrs, " "))

	e := ldapserver.NewSearchResultEntry("")
	e.AddAttribute("vendorVersion", ldap.AttributeValue(versionString))
	e.AddAttribute("objectClass", "top", "LDAProotDSE")
	e.AddAttribute("supportedLDAPVersion", "3")
	e.AddAttribute("supportedControl", ldap.AttributeValue(ldap.PagedResultsControlOID))
	e.AddAttribute("namingContexts", ldap.AttributeValue(baseDN))
	// e.AddAttribute("supportedSASLMechanisms", "")

	w.Write(e)
	w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))

	log.Printf("client [%d]: search result=OK nentries=1", m.Client.Numero())
}

// handle search
func handleSearch(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	entries.Mutex.RLock()
	defer entries.Mutex.RUnlock()

	r := m.GetSearchRequest()

	attrs := []string{}
	for _, attr := range r.Attributes() {
		attrs = append(attrs, string(attr))
	}

	log.Printf("client [%d]: search base=\"%s\" scope=%d filter=\"%s\"", m.Client.Numero(), r.BaseObject(), r.Scope(), r.FilterString())
	log.Printf("client [%d]: search attr=%s", m.Client.Numero(), strings.Join(attrs, " "))

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
					log.Printf("client [%d]: error decoding pagedResultsControl: %s", m.Client.Numero(), err)
				}
				simplePagedResultsControl = c
			default:
				if c.Criticality().Bool() {
					controls = append(controls, c.ControlType().String()+"(U,C)")
				} else {
					controls = append(controls, c.ControlType().String()+"(U)")
				}
				// TODO: Handle control criticality
				// if c.Criticality().Bool() && stopOnUnsupportedCriticalControl {
				// 	diagMessage := fmt.Sprintf("unsupported critical control %s", c.ControlType().String())
				// 	res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnavailableCriticalExtension)
				// 	res.SetDiagnosticMessage(diagMessage)
				// 	w.Write(res)

				// 	log.Printf("client [%d]: search error: %s", m.Client.Numero(), diagMessage)
				// 	return
				// }
			}
		}
	}

	log.Printf("client [%d]: search ctrl=%s", m.Client.Numero(), strings.Join(controls, " "))
	log.Printf("client [%d]: search sizelimit=%d pagesize=%d", m.Client.Numero(), r.SizeLimit(), simplePagedResultsControl.PageSize())

	// handle stop signal
	select {
	case <-m.Done:
		log.Printf("client [%d]: leaving handleSearch...", m.Client.Numero())
		deleteSearchControl(m.Client.Numero())
		return
	default:
	}

	// base object must be dc=base,dc=dn or cn=<COMMON_NAME>,dc=base,dc=dn
	// TODO: change diag message
	baseObject := trimSpacesAfterComma(string(r.BaseObject()))
	baseObjectAttr, baseObjectName := getEntryAttrAndName(baseObject)
	if baseObject != baseDN && baseObjectAttr != "cn" {
		diagMessage := fmt.Sprintf("wrong base object \"%s\": wrong dn", r.BaseObject())
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultInvalidDNSyntax)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: search error: %s", m.Client.Numero(), diagMessage)
		return
	}

	// non admin user allowed to search only over his entry
	if !m.Client.ACL().Search && (baseObjectAttr != "cn" || (baseObjectAttr == "cn" && baseObjectName != m.Client.ACL().BindEntry)) {
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultNoSuchObject)
		w.Write(res)

		log.Printf("client [%d]: search error: insufficient access", m.Client.Numero())
		return
	}

	entriesWritten := 0
	sizeLimitReached := false

	// check if more entries is available
	lastIteration := false

	// how much entries is left
	left := simplePagedResultsControl.PageSize().Int()
	if left == 0 {
		left = 1 + len(entries.Users) + len(entries.Groups)
	}

	// create client flow control checker
	searchFlowControl := getSearchControl(m.Client.Numero())

	// if domain processed -> go to users
	if searchFlowControl.domainDone {
		goto users
	}

	// if baseObject == baseDN AND searchScope == {0, 2} -> add domain entry
	if baseObject == baseDN && r.Scope() != ldap.SearchRequestScopeOneLevel && r.Scope() != ldap.SearchRequestScopeChildren {
		ok, err := applySearchFilter(entries.Domain, r.Filter())
		if err != nil {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(err.Error())
			w.Write(res)

			log.Printf("client [%d]: search error: %s", m.Client.Numero(), err)
			return
		}

		if r.SizeLimit().Int() > 0 && searchFlowControl.sent == r.SizeLimit().Int() {
			sizeLimitReached = true
			goto end
		} else if ok {
			e := createSearchResultEntry(entries.Domain, r.Attributes(), baseDN)
			w.Write(e)

			searchFlowControl.sent++
			entriesWritten++
			left--
		}
	}

	// domain processed
	searchFlowControl.domainDone = true

users:
	// if all users processed -> go to groups
	if searchFlowControl.usersDone {
		goto groups
	}

	for i := searchFlowControl.count; i < len(entries.Users); i++ {
		// handle stop signal
		select {
		case <-m.Done:
			log.Printf("client [%d]: leaving handleSearch...", m.Client.Numero())
			deleteSearchControl(m.Client.Numero())
			return
		default:
		}

		if left == 0 && !lastIteration {
			lastIteration = true
		}

		if !lastIteration {
			searchFlowControl.count++
		}

		// if entry not end with baseDN OR baseObject == entry AND (searchScope == 1 OR searchScope == 3) -> skip
		entryName := fmt.Sprintf("cn=%s,%s", entries.Users[i].CN, baseDN)
		if !strings.HasSuffix(entryName, baseObject) || (entryName == baseObject &&
			(r.Scope() == ldap.SearchRequestScopeOneLevel || r.Scope() == ldap.SearchRequestScopeChildren)) {
			continue
		}

		// if size limit reached -> go to response
		if r.SizeLimit().Int() > 0 && searchFlowControl.sent == r.SizeLimit().Int() {
			sizeLimitReached = true
			goto end
		}

		// apply search filter for each user
		ok, err := applySearchFilter(entries.Users[i], r.Filter())
		if err != nil {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(err.Error())
			w.Write(res)

			log.Printf("client [%d]: search error: %s", m.Client.Numero(), err)
			return
		}

		// if filter not applied -> skip user
		if !ok {
			continue
		}

		if lastIteration {
			goto end
		}

		e := createSearchResultEntry(entries.Users[i], r.Attributes(), entryName)
		w.Write(e)

		searchFlowControl.sent++
		entriesWritten++
		left--
	}

	// users processed
	searchFlowControl.count = 0
	searchFlowControl.usersDone = true

groups:
	for i := searchFlowControl.count; i < len(entries.Groups); i++ {
		// handle stop signal
		select {
		case <-m.Done:
			log.Printf("client [%d]: leaving handleSearch...", m.Client.Numero())
			deleteSearchControl(m.Client.Numero())
			return
		default:
		}

		if left == 0 && !lastIteration {
			lastIteration = true
		}

		if !lastIteration {
			searchFlowControl.count++
		}

		// if entry not end with baseDN OR baseObject == entry AND (searchScope == 1 OR searchScope == 3) -> skip
		entryName := fmt.Sprintf("cn=%s,%s", entries.Groups[i].CN, baseDN)
		if !strings.HasSuffix(entryName, baseObject) || entryName == baseObject &&
			(r.Scope() == ldap.SearchRequestScopeOneLevel || r.Scope() == ldap.SearchRequestScopeChildren) {
			continue
		}

		// if size limit reached -> brake loop
		if r.SizeLimit().Int() > 0 && searchFlowControl.sent == r.SizeLimit().Int() {
			sizeLimitReached = true
			goto end
		}

		// apply search filter for each group
		ok, err := applySearchFilter(entries.Groups[i], r.Filter())
		if err != nil {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(err.Error())
			w.Write(res)

			log.Printf("client [%d]: search error: %s", m.Client.Numero(), err)
			return
		}

		// if filter not applied -> skip group
		if !ok {
			continue
		}

		if lastIteration {
			goto end
		}

		e := createSearchResultEntry(entries.Groups[i], r.Attributes(), entryName)
		w.Write(e)

		searchFlowControl.sent++
		entriesWritten++
		left--
	}

	// groups processed
	searchFlowControl.count = 0
	searchFlowControl.groupsDone = true

end:
	newControls := ldap.Controls{}
	if simplePagedResultsControl.PageSize().Int() > 0 {
		cpCookie := ldap.OCTETSTRING(programName)

		// end search
		if (searchFlowControl.domainDone && searchFlowControl.usersDone && searchFlowControl.groupsDone) || sizeLimitReached {
			cpCookie = ldap.OCTETSTRING("")
			deleteSearchControl(m.Client.Numero())
		}

		// encode new paged results control
		v, err := ldap.WritePagedResultsControl(ldap.INTEGER(0), cpCookie)
		if err != nil {
			diagMessage := fmt.Sprintf("error encoding pagedResultsControl: %s", err)
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultOther)
			res.SetDiagnosticMessage(diagMessage)
			w.Write(res)

			log.Printf("client [%d]: search error: %s", m.Client.Numero(), diagMessage)
			return
		}

		c := ldap.NewControl(ldap.PagedResultsControlOID, ldap.BOOLEAN(true), *v)
		newControls = append(newControls, c)
	} else {
		// end search
		deleteSearchControl(m.Client.Numero())
	}

	resultCode := ldapserver.LDAPResultSuccess
	if sizeLimitReached {
		resultCode = ldapserver.LDAPResultSizeLimitExceeded
	}

	res := ldapserver.NewSearchResultDoneResponse(resultCode)
	responseMessage := ldap.NewLDAPMessageWithProtocolOp(res)

	ldap.SetMessageControls(responseMessage, newControls)
	w.WriteMessage(responseMessage)

	log.Printf("client [%d]: search result=OK nentries=%d", m.Client.Numero(), entriesWritten)
}

// handle compare
func handleCompare(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	entries.Mutex.RLock()
	defer entries.Mutex.RUnlock()

	r := m.GetCompareRequest()
	log.Printf("client [%d]: compare dn=\"%s\" attr=\"%s\"", m.Client.Numero(), r.Entry(), r.Ava().AttributeDesc())

	// entry must be equal to baseDN or look like cn=<COMMON_NAME>,dc=base,dc=dn
	// TODO: change diag message
	compareEntry := trimSpacesAfterComma(string(r.Entry()))
	compareEntryAttr, compareEntryName := getEntryAttrAndName(compareEntry)
	if !strings.HasSuffix(compareEntry, baseDN) || (compareEntry != baseDN && compareEntryAttr != "cn" && compareEntryAttr != "uid") {
		diagMessage := fmt.Sprintf("wrong dn \"%s\"", r.Entry())
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultInvalidDNSyntax)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: compare error: %s", m.Client.Numero(), diagMessage)
		return
	}

	// compare for entryDN is not supported
	if strings.ToLower(string(r.Ava().AttributeDesc())) == "entrydn" {
		diagMessage := "entryDN compare not supported"
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: compare error: %s", m.Client.Numero(), diagMessage)
		return
	}

	// requested compare on domain and user not ldap admin OR compare entry != bind entry and user not ldap admin
	if (compareEntry == baseDN && !m.Client.ACL().Compare) || (m.Client.ACL().BindEntry != compareEntryName && !m.Client.ACL().Compare) {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultInsufficientAccessRights)
		w.Write(res)

		log.Printf("client [%d]: compare error: insufficient access", m.Client.Numero())
		return
	}

	if compareEntry == baseDN && doCompare(entries.Domain, string(r.Ava().AttributeDesc()), string(r.Ava().AssertionValue())) {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareTrue)
		w.Write(res)

		log.Printf("client [%d]: compare result=TRUE", m.Client.Numero())
		return

	}

	for _, user := range entries.Users {
		// handle stop signal
		select {
		case <-m.Done:
			log.Printf("client [%d]: leaving handleCompare...", m.Client.Numero())
			return
		default:
		}

		if user.CN != compareEntryName {
			continue
		}

		if doCompare(user, string(r.Ava().AttributeDesc()), string(r.Ava().AssertionValue())) {
			res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareTrue)
			w.Write(res)

			log.Printf("client [%d]: compare result=TRUE", m.Client.Numero())
			return
		}
	}
	for _, group := range entries.Groups {
		// handle stop signal
		select {
		case <-m.Done:
			log.Printf("client [%d]: leaving handleCompare...", m.Client.Numero())
			return
		default:
		}

		if group.CN != compareEntryName {
			continue
		}

		if doCompare(group, string(r.Ava().AttributeDesc()), string(r.Ava().AssertionValue())) {
			res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareTrue)
			w.Write(res)

			log.Printf("client [%d]: compare result=TRUE", m.Client.Numero())
			return
		}
	}

	res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareFalse)
	w.Write(res)

	log.Printf("client [%d]: compare result=FALSE", m.Client.Numero())
}

// handle modify (only userPassword for now)
func handleModify(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	entries.Mutex.RLock()
	defer entries.Mutex.RUnlock()

	r := m.GetModifyRequest()
	log.Printf("client [%d]: modify dn=\"%s\"", m.Client.Numero(), r.Object())

	// entry must be equal to baseDN or look like cn=<COMMON_NAME>,dc=base,dc=dn
	// TODO: change diag message
	modifyEntry := trimSpacesAfterComma(string(r.Object()))
	modifyEntryAttr, modifyEntryName := getEntryAttrAndName(modifyEntry)
	if !strings.HasSuffix(modifyEntry, baseDN) || (modifyEntryAttr != "cn" && modifyEntryAttr != "uid") {
		diagMessage := fmt.Sprintf("wrong dn \"%s\"", r.Object())
		res := ldapserver.NewModifyResponse(ldapserver.LDAPResultInvalidDNSyntax)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: modify error: %s", m.Client.Numero(), diagMessage)
		return
	}

	// ldap admin can do modify on all entries
	if m.Client.ACL().BindEntry != modifyEntryName && !m.Client.ACL().Modify {
		res := ldapserver.NewModifyResponse(ldapserver.LDAPResultInsufficientAccessRights)
		w.Write(res)

		log.Printf("client [%d]: modify error: insufficient access", m.Client.Numero())
		return
	}

	for _, c := range r.Changes() {
		// handle stop signal
		select {
		case <-m.Done:
			log.Printf("client [%d]: leaving handleModify...", m.Client.Numero())
			return
		default:
		}

		// check operation type
		log.Printf("client [%d]: modify op=%d", m.Client.Numero(), c.Operation())
		if c.Operation().Int() != ldap.ModifyRequestChangeOperationReplace {
			diagMessage := fmt.Sprintf("wrong operation %d: only replace (2) is supported", c.Operation().Int())
			res := ldapserver.NewModifyResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(diagMessage)
			w.Write(res)

			log.Printf("client [%d]: modify error: %s", m.Client.Numero(), diagMessage)
			return
		}

		// check attribute name
		log.Printf("client [%d]: modify attr=%s", m.Client.Numero(), c.Modification().Type_())
		if c.Modification().Type_() != "userPassword" {
			diagMessage := fmt.Sprintf("wrong attribute %s, only userPassword is supported", c.Modification().Type_())
			res := ldapserver.NewModifyResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(diagMessage)
			w.Write(res)

			log.Printf("client [%d]: modify error: %s", m.Client.Numero(), diagMessage)
			return
		}

		if len(c.Modification().Vals()) > 1 {
			diagMessage := "more than 1 value for userPassword is not supported"
			res := ldapserver.NewModifyResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(diagMessage)
			w.Write(res)

			log.Printf("client [%d]: modify error: %s", m.Client.Numero(), diagMessage)
			return
		}

		if err := doModify(modifyEntryName, string(c.Modification().Vals()[0])); err != nil {
			res := ldapserver.NewModifyResponse(ldapserver.LDAPResultOther)
			res.SetDiagnosticMessage(err.Error())
			w.Write(res)

			log.Printf("client [%d]: modify error: %s", m.Client.Numero(), err)
			return
		}
	}

	res := ldapserver.NewModifyResponse(ldapserver.LDAPResultSuccess)
	w.Write(res)

	log.Printf("client [%d]: modify result=OK", m.Client.Numero())
}
