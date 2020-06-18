package main

import (
	"fmt"
	"log"
	"strings"

	ldap "github.com/ps78674/goldap/message"
	ldapserver "github.com/ps78674/ldapserver"
)

// search DSE
func handleSearchDSE(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	log.Printf("client [%d]: performing search DSE", m.Client.Numero)

	e := ldapserver.NewSearchResultEntry("")
	e.AddAttribute("vendorVersion", ldap.AttributeValue(versionString))
	e.AddAttribute("objectClass", "top", "LDAProotDSE")
	e.AddAttribute("supportedLDAPVersion", "3")
	e.AddAttribute("supportedControl", ldap.ControlTypePaging)
	e.AddAttribute("namingContexts", ldap.AttributeValue(baseDN))
	// e.AddAttribute("supportedSASLMechanisms", "")

	w.Write(e)
	w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))

	log.Printf(fmt.Sprintf("client [%d]: search DSE successful", m.Client.Numero))
}

// handle bind
func handleBind(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	r := m.GetBindRequest()
	log.Printf("client [%d]: performing bind with dn %s", m.Client.Numero, r.Name())

	// only simple authentiacion supported
	if r.AuthenticationChoice() != "simple" {
		diagMessage := fmt.Sprintf("authentication method %s is not supported", r.AuthenticationChoice())
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: bind error: %s", m.Client.Numero, diagMessage)
		return
	}

	// entry must end with basedn (-b/--basedn)
	if !strings.HasSuffix(trimSpacesAfterComma(string(r.Name())), baseDN) {
		diagMessage := fmt.Sprintf("wrong dn %s: must end with basedn %s", r.Name(), baseDN)
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: bind error: %s", m.Client.Numero, diagMessage)
		return
	}

	bindEntry := strings.SplitN(string(strings.TrimSuffix(trimSpacesAfterComma(string(r.Name())), fmt.Sprintf(",%s", baseDN))), "=", 2)
	bindEntryAttr := bindEntry[0]
	bindEntryName := bindEntry[1]

	// entry must look like cn=<COMMON_NAME>,dc=base,dc=dn or uid=<COMMON_NAME>,dc=base,dc=dn
	switch bindEntryAttr {
	case "cn", "uid":
	default:
		diagMessage := fmt.Sprintf("wrong dn %s: must look like {cn, uid}=<COMMON_NAME>,%s", r.Name(), baseDN)
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: bind error: %s", m.Client.Numero, diagMessage)
		return
	}

	if memStoreTimeout <= 0 {
		restData.update(m.Client.Numero, bindEntryName, "user")
	}

	// FIXME: check all elements of u.CN
	userData := restUser{}
	for _, u := range restData.Users {
		if u.CN[0] == bindEntryName {
			userData = u
			break
		}
	}

	// user not found
	if len(userData.CN) == 0 {
		diagMessage := fmt.Sprintf("user %s not found", r.Name())
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: bind error: %s", m.Client.Numero, diagMessage)
		return
	}

	// FIXME: check all elements of userData.UserPassword
	if !validatePassword(r.AuthenticationSimple().String(), userData.UserPassword[0]) {
		diagMessage := fmt.Sprintf("wrong password for user %s", r.Name())
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: bind error: %s", m.Client.Numero, diagMessage)
		return
	}

	res := ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess)
	w.Write(res)

	log.Printf("client [%d]: bind with dn %s successful", m.Client.Numero, r.Name())
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
	log.Printf("client [%d]: performing search with filter %s, base object %s", m.Client.Numero, r.FilterString(), r.BaseObject())

	// base object must end with basedn (-b/--basedn)
	if !strings.HasSuffix(trimSpacesAfterComma(string(r.BaseObject())), baseDN) {
		diagMessage := fmt.Sprintf("wrong base object %s: base object must end with basedn %s", r.BaseObject(), baseDN)
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: search error: %s", m.Client.Numero, diagMessage)
		return
	}

	// base object must be dc=base,dc=dn or cn=<COMMON_NAME>,dc=base,dc=dn
	baseObject := strings.TrimSuffix(strings.TrimSuffix(trimSpacesAfterComma(string(r.BaseObject())), baseDN), ",")
	if len(baseObject) > 0 && !strings.HasPrefix(baseObject, "cn=") {
		diagMessage := fmt.Sprintf("wrong base object %s: wrong dn", r.BaseObject())
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: search error: %s", m.Client.Numero, diagMessage)
		return
	}

	if memStoreTimeout <= 0 {
		restData.update(m.Client.Numero, strings.TrimPrefix(baseObject, "cn="), "")
	}

	sizeCounter := 0
	sizeLimitReached := false
	var entries []ldap.SearchResultEntry

	// if baseObject == baseDN AND searchScope == 1 -> add domain entry
	if trimSpacesAfterComma(string(r.BaseObject())) == baseDN && r.Scope() != ldap.SearchRequestScopeOneLevel && r.Scope() != ldap.SearchRequestScopeChildren {
		e := ldapserver.NewSearchResultEntry(baseDN)
		e.AddAttribute("objectClass", "top", "domain")
		e.AddAttribute("hasSubordinates", "TRUE")

		ok, err := applySearchFilter(e, r.Filter())

		if err != nil {
			log.Printf("client [%d]: search error: %s", m.Client.Numero, err)
		}

		if ok {
			entries = append(entries, e)
			sizeCounter++
		}
	}

	for _, user := range restData.Users {
		if stop {
			return
		}

		// if entry not end with baseDN OR (baseObject == entry AND searchScope == 1) -> skip
		entryName := fmt.Sprintf("cn=%s,%s", user.CN[0], baseDN)
		if !strings.HasSuffix(entryName, trimSpacesAfterComma(string(r.BaseObject()))) || trimSpacesAfterComma(string(r.BaseObject())) == entryName &&
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

		// create entry
		e := ldapserver.NewSearchResultEntry(fmt.Sprintf(entryName))
		e.AddAttribute("objectClass", "posixAccount", "shadowAccount", "organizationalPerson", "inetOrgPerson", "person")
		e.AddAttribute("hasSubordinates", "FALSE")
		e.AddAttribute("cn", newLDAPAttributeValues(user.CN)...)
		e.AddAttribute("homeDirectory", newLDAPAttributeValues(user.HomeDirectory)...)
		e.AddAttribute("uid", newLDAPAttributeValues(user.UID)...)
		e.AddAttribute("uidNumber", newLDAPAttributeValues(user.UIDNumber)...)
		e.AddAttribute("mail", newLDAPAttributeValues(user.Mail)...)
		e.AddAttribute("displayName", newLDAPAttributeValues(user.DisplayName)...)
		e.AddAttribute("givenName", newLDAPAttributeValues(user.GivenName)...)
		e.AddAttribute("sn", newLDAPAttributeValues(user.SN)...)
		e.AddAttribute("userPassword", newLDAPAttributeValues(user.UserPassword)...)
		e.AddAttribute("loginShell", newLDAPAttributeValues(user.LoginShell)...)
		e.AddAttribute("gidNumber", newLDAPAttributeValues(user.GIDNumber)...)
		e.AddAttribute("sshPublicKey", newLDAPAttributeValues(user.SSHPublicKey)...)
		e.AddAttribute("ipHostNumber", newLDAPAttributeValues(user.IPHostNumber)...)

		entries = append(entries, e)
		sizeCounter++
	}

	for _, group := range restData.Groups {
		if stop {
			return
		}

		// if entry not end with baseDN OR (baseObject == entry AND searchScope == 1) -> skip
		entryName := fmt.Sprintf("cn=%s,%s", group.CN[0], baseDN)
		if !strings.HasSuffix(entryName, trimSpacesAfterComma(string(r.BaseObject()))) || trimSpacesAfterComma(string(r.BaseObject())) == entryName &&
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

		// create entry
		e := ldapserver.NewSearchResultEntry(entryName)
		e.AddAttribute("objectClass", "posixGroup")
		e.AddAttribute("hasSubordinates", "FALSE")
		e.AddAttribute("description", newLDAPAttributeValues(group.Description)...)
		e.AddAttribute("cn", newLDAPAttributeValues(group.CN)...)
		e.AddAttribute("gidNumber", newLDAPAttributeValues(group.GIDNumber)...)
		e.AddAttribute("ou", newLDAPAttributeValues(group.OU)...)
		e.AddAttribute("memberUid", newLDAPAttributeValues(group.MemberUID)...)

		entries = append(entries, e)
		sizeCounter++
	}

	// FIXME: if nothing found -> ldapserver.LDAPResultNoSuchObject ??
	if len(entries) == 0 {
		w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))
		log.Printf("client [%d]: search with filter %s, base object %s successful", m.Client.Numero, r.FilterString(), r.BaseObject())

		return
	}

	// get 1.2.840.113556.1.4.319 from requested controls
	var cp ldap.ControlPaging
	var cpCriticality ldap.BOOLEAN

	if m.Controls() != nil {
		for _, c := range *m.Controls() {
			if c.ControlType().String() == ldap.ControlTypePaging {
				var err error
				cp, err = ldap.ReadControlPaging(ldap.NewBytes(0, c.ControlValue().Bytes()))
				if err != nil {
					log.Printf("client [%d]: error reading pagedResultsControl: %s", m.Client.Numero, err)
				}
				cpCriticality = c.Criticality()
				break
			}
		}
	}

	// if paging requested -> return results in pages
	if cp.PageSize().Int() > 0 {
		var cpCookie ldap.OCTETSTRING
		for c := 0; c != cp.PageSize().Int() && m.Client.EntriesSent < len(entries); {
			w.Write(entries[m.Client.EntriesSent]) // m.Client.EntriesSent - how many entries already been sent
			m.Client.EntriesSent++
			c++

			cpCookie = ldap.OCTETSTRING(programName) // use programName instead of random cookie
		}

		ncp := ldap.NewControlPaging(ldap.INTEGER(len(entries)), cpCookie)
		b, err := ncp.WriteControlPaging()
		if err != nil {
			diagMessage := fmt.Sprintf("error encoding pagedResultsControl: %s", err)
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultOther)
			res.SetDiagnosticMessage(diagMessage)
			w.Write(res)

			log.Printf("client [%d]: search error: %s", m.Client.Numero, diagMessage)
			return
		}

		nc := ldap.NewControl(ldap.LDAPOID(ldap.ControlTypePaging), cpCriticality, ldap.OCTETSTRING(b.Bytes()))

		// FIXME: deadlock on 128 message
		if m.MessageID().Int() == 127 { // m.MessageID().Int() == 127 - something wrong witch conn.Read(), deadlock on 128 message
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSizeLimitExceeded)
			responseMessage := ldap.NewLDAPMessageWithProtocolOpAndControls(res, ldap.Controls{nc})
			w.WriteMessage(responseMessage)
			log.Printf(fmt.Sprintf("client [%d]: search with filter %s exceeds sizeLimit (127)", m.Client.Numero, r.FilterString()))
		} else if sizeLimitReached {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSizeLimitExceeded)
			responseMessage := ldap.NewLDAPMessageWithProtocolOpAndControls(res, ldap.Controls{nc})
			w.WriteMessage(responseMessage)
			log.Printf(fmt.Sprintf("client [%d]: search with filter %s exceeds sizeLimit (%d)", m.Client.Numero, r.FilterString(), r.SizeLimit()))
		} else {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess)
			responseMessage := ldap.NewLDAPMessageWithProtocolOpAndControls(res, ldap.Controls{nc})
			w.WriteMessage(responseMessage)
			log.Printf(fmt.Sprintf("client [%d]: search with filter %s, base object %s successful", m.Client.Numero, r.FilterString(), r.BaseObject()))
		}
	} else {
		for _, e := range entries {
			w.Write(e)
		}

		if sizeLimitReached {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSizeLimitExceeded)
			responseMessage := ldap.NewLDAPMessageWithProtocolOp(res)
			w.WriteMessage(responseMessage)
			log.Printf(fmt.Sprintf("client [%d]: search with filter %s exceeds sizeLimit (%d)", m.Client.Numero, r.FilterString(), r.SizeLimit()))
		} else {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess)
			responseMessage := ldap.NewLDAPMessageWithProtocolOp(res)
			w.WriteMessage(responseMessage)
			log.Printf(fmt.Sprintf("client [%d]: search with filter %s, base object %s successful", m.Client.Numero, r.FilterString(), r.BaseObject()))
		}
	}
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
	log.Printf("client [%d]: performing compare %s:%s for entry %s", m.Client.Numero, r.Ava().AttributeDesc(), r.Ava().AssertionValue(), r.Entry())

	// entry must end with basedn (-b/--basedn)
	if !strings.HasSuffix(trimSpacesAfterComma(string(r.Entry())), baseDN) {
		diagMessage := fmt.Sprintf("wrong entry %s: must end with basedn %s", r.Entry(), baseDN)
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: compare error: %s", m.Client.Numero, diagMessage)
		return
	}

	compareEntry := strings.SplitN(string(strings.TrimSuffix(trimSpacesAfterComma(string(r.Entry())), fmt.Sprintf(",%s", baseDN))), "=", 2)
	compareEntryAttr := compareEntry[0]
	compareEntryName := compareEntry[1]

	// entry must look like cn=<COMMON_NAME>,dc=base,dc=dn
	if compareEntryAttr != "cn" {
		diagMessage := fmt.Sprintf("wrong entry %s: must look like cn=<COMMON_NAME>,%s", r.Entry(), baseDN)
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: compare error: %s", m.Client.Numero, diagMessage)
		return
	}

	if memStoreTimeout <= 0 {
		restData.update(m.Client.Numero, compareEntryName, "")
	}

	for _, user := range restData.Users {
		if stop {
			return
		}

		// FIXME: check all elements of user.CN
		if user.CN[0] != compareEntryName {
			continue
		}

		if doCompare(user, string(r.Ava().AttributeDesc()), string(r.Ava().AssertionValue())) {
			res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareTrue)
			w.Write(res)

			log.Printf("client [%d]: compare %s:%s for entry %s TRUE", m.Client.Numero, r.Ava().AttributeDesc(), r.Ava().AssertionValue(), r.Entry())
			return
		}
	}

	for _, group := range restData.Groups {
		if stop {
			return
		}

		// FIXME: check all elements of group.CN
		if group.CN[0] != compareEntryName {
			continue
		}

		if doCompare(group, string(r.Ava().AttributeDesc()), string(r.Ava().AssertionValue())) {
			res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareTrue)
			w.Write(res)

			log.Printf("client [%d]: compare %s:%s for entry %s TRUE", m.Client.Numero, r.Ava().AttributeDesc(), r.Ava().AssertionValue(), r.Entry())
			return
		}
	}

	res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareFalse)
	w.Write(res)

	log.Printf("client [%d]: compare %s:%s for entry %s FALSE", m.Client.Numero, r.Ava().AttributeDesc(), r.Ava().AssertionValue(), r.Entry())
}

// handle modify (only userPassword for now)
func handleModify(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	r := m.GetModifyRequest()
	log.Printf("client [%d]: performing modify for dn %s", m.Client.Numero, r.Object())

	if !strings.HasSuffix(trimSpacesAfterComma(string(r.Object())), baseDN) {
		diagMessage := fmt.Sprintf("wrong dn %s: must end with basedn %s", r.Object(), baseDN)
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultInvalidDNSyntax)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: modify error: %s", m.Client.Numero, diagMessage)
		return
	}

	for _, c := range r.Changes() {
		// check operation type
		if c.Operation().Int() != ldap.ModifyRequestChangeOperationReplace {
			diagMessage := fmt.Sprintf("wrong operation %d: only replace (2) is supported", c.Operation().Int())
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(diagMessage)
			w.Write(res)

			log.Printf("client [%d]: modify error: %s", m.Client.Numero, diagMessage)
			return
		}

		// check attribute name
		if c.Modification().Type_() != "userPassword" {
			diagMessage := fmt.Sprintf("wrong attribute %s, only userPassword is supported", c.Modification().Type_())
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(diagMessage)
			w.Write(res)

			log.Printf("client [%d]: modify error: %s", m.Client.Numero, diagMessage)
			return
		}

		modifyObject := strings.SplitN(string(strings.TrimSuffix(trimSpacesAfterComma(string(r.Object())), fmt.Sprintf(",%s", baseDN))), "=", 2)
		if modifyObject[0] != "cn" {
			diagMessage := fmt.Sprintf("wrong dn %s: wrong attribute %s", r.Object(), modifyObject[0])
			res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidDNSyntax)
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

		if err := doModify(modifyObject[1], string(c.Modification().Vals()[0])); err != nil {
			res := ldapserver.NewBindResponse(ldapserver.LDAPResultOther)
			res.SetDiagnosticMessage(err.Error())
			w.Write(res)

			log.Printf("client [%d]: modify error: %s", m.Client.Numero, err)
			return
		}
	}

	res := ldapserver.NewModifyResponse(ldapserver.LDAPResultSuccess)
	w.Write(res)

	log.Printf("client [%d]: modify for dn %s successful", m.Client.Numero, r.Object())
}
