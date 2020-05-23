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
	if r.AuthenticationChoice() != "simple" {
		diagMessage := fmt.Sprintf("authentication method '%s' is not supported", r.AuthenticationChoice())
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: bind error: %s", m.Client.Numero, diagMessage)
		return
	}

	if !strings.HasSuffix(string(r.Name()), baseDN) {
		diagMessage := fmt.Sprintf("binddn must end with basedn '%s'", baseDN)
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: bind error: %s", m.Client.Numero, diagMessage)
		return
	}

	bindDNParts := strings.Split(strings.TrimSuffix(string(r.Name()), fmt.Sprintf(",%s", baseDN)), ",")
	if len(bindDNParts) != 1 || !(strings.HasPrefix(bindDNParts[0], "cn=") || strings.HasPrefix(bindDNParts[0], "uid=")) {
		diagMessage := fmt.Sprintf("wrong binddn '%s'", r.Name())
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: bind error: %s", m.Client.Numero, diagMessage)
		return
	}

	userName := strings.TrimPrefix(strings.TrimPrefix(bindDNParts[0], "cn="), "uid=")

	if memStoreTimeout <= 0 {
		restData.update(m.Client.Numero, userName, "user")
	}

	userData := restUserAttrs{}
	for _, u := range restData.Users {
		if u.CN[0] == userName {
			userData = u
			break
		}
	}

	if len(userData.CN) == 0 {
		diagMessage := fmt.Sprintf("user '%s' not found", userName)
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: bind error: %s", m.Client.Numero, diagMessage)
		return
	}

	if !validatePassword(string(r.AuthenticationSimple()), userData.UserPassword[0]) {
		diagMessage := fmt.Sprintf("wrong password for user '%s'", r.Name())
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: bind error: %s", m.Client.Numero, diagMessage)
		return
	}

	res := ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess)
	w.Write(res)

	log.Printf("client [%d]: bind for user '%s' successful", m.Client.Numero, r.Name())
}

// handle search for our basedn
func handleSearch(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	// handle stop signal - see main.go
	stop := false
	go func() {
		<-m.Done
		log.Printf("client [%d]: leaving handleSearch...", m.Client.Numero)
		stop = true
	}()

	r := m.GetSearchRequest()
	log.Printf("client [%d]: performing search with filter '%s'", m.Client.Numero, r.FilterString())

	// update data manually
	if memStoreTimeout <= 0 {
		restData.update(m.Client.Numero, "", "")
	}

	sizeCounter := 0
	var entries []ldap.SearchResultEntry

	for _, user := range restData.Users {
		if stop {
			return
		}

		if r.SizeLimit().Int() > 0 && sizeCounter >= r.SizeLimit().Int() {
			break
		}

		ok, err := applySearchFilter(user, r.Filter())
		if err != nil {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(err.Error())
			w.Write(res)

			log.Printf("client [%d]: search error: %s", m.Client.Numero, err)
			return
		}

		if !ok {
			continue
		}

		e := ldapserver.NewSearchResultEntry(fmt.Sprintf("cn=%s,%s", user.CN[0], r.BaseObject()))
		e.AddAttribute("cn", newLDAPAttributeValues(user.CN)...)
		e.AddAttribute("objectClass", "posixAccount", "shadowAccount", "organizationalPerson", "inetOrgPerson", "person")
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

		if r.SizeLimit().Int() > 0 && sizeCounter >= r.SizeLimit().Int() {
			break
		}

		ok, err := applySearchFilter(group, r.Filter())
		if err != nil {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(err.Error())
			w.Write(res)

			log.Printf("client [%d]: search error: %s", m.Client.Numero, err)
			return
		}

		if !ok {
			continue
		}

		e := ldapserver.NewSearchResultEntry(fmt.Sprintf("cn=%s,%s", group.CN[0], r.BaseObject()))
		e.AddAttribute("objectClass", "posixGroup")
		e.AddAttribute("description", newLDAPAttributeValues(group.Description)...)
		e.AddAttribute("cn", newLDAPAttributeValues(group.CN)...)
		e.AddAttribute("gidNumber", newLDAPAttributeValues(group.GIDNumber)...)
		e.AddAttribute("ou", newLDAPAttributeValues(group.OU)...)
		e.AddAttribute("memberUid", newLDAPAttributeValues(group.MemberUID)...)

		entries = append(entries, e)
		sizeCounter++
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
					log.Printf("client [%d]: error reading control paging: %s", m.Client.Numero, err)
				}
				cpCriticality = c.Criticality()
				break
			}
		}
	}

	// if paging requested -> return results in pages
	if cp.PageSize().Int() > 0 {
		c := 0
		for {
			w.Write(entries[m.Client.EntriesSent]) // m.Client.EntriesSent - how many entries already been sent
			m.Client.EntriesSent++
			c++

			if c == cp.PageSize().Int() || m.Client.EntriesSent == len(entries) {
				var cpCookie ldap.OCTETSTRING
				if m.Client.EntriesSent != len(entries) {
					cpCookie = ldap.OCTETSTRING(programName) // use programName instead of random cookie
				}

				ncp := ldap.NewControlPaging(ldap.INTEGER(len(entries)), cpCookie)

				b, err := ncp.WriteControlPaging()
				if err != nil {
					diagMessage := fmt.Sprintf("error encoding control paging: %s", err)
					res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultOther)
					res.SetDiagnosticMessage(diagMessage)
					w.Write(res)

					log.Printf("client [%d]: search error: %s", m.Client.Numero, diagMessage)
					return
				}

				nc := ldap.NewControl(ldap.LDAPOID(ldap.ControlTypePaging), cpCriticality, ldap.OCTETSTRING(b.Bytes()))

				if (r.SizeLimit().Int() > 0 && sizeCounter >= r.SizeLimit().Int()) || m.MessageID().Int() == 127 { // m.MessageID().Int() == 127 - error in goldap, deadlock on 128 message
					res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSizeLimitExceeded)
					responseMessage := ldap.NewLDAPMessageWithProtocolOpAndControls(res, ldap.Controls{nc})
					w.WriteMessage(responseMessage)
					log.Printf(fmt.Sprintf("client [%d]: paged search with filter '%s' exceeded sizeLimit (%d)", m.Client.Numero, r.FilterString(), r.SizeLimit()))
				} else {
					res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess)
					responseMessage := ldap.NewLDAPMessageWithProtocolOpAndControls(res, ldap.Controls{nc})
					w.WriteMessage(responseMessage)
					log.Printf(fmt.Sprintf("client [%d]: paged search with filter '%s' successful", m.Client.Numero, r.FilterString()))
				}

				break
			}
		}
	} else {
		for _, e := range entries {
			w.Write(e)
		}

		if r.SizeLimit().Int() > 0 && sizeCounter >= r.SizeLimit().Int() {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSizeLimitExceeded)
			responseMessage := ldap.NewLDAPMessageWithProtocolOp(res)
			w.WriteMessage(responseMessage)
			log.Printf(fmt.Sprintf("client [%d]: search with filter '%s' exceeded sizeLimit (%d)", m.Client.Numero, r.FilterString(), r.SizeLimit()))
		} else {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess)
			responseMessage := ldap.NewLDAPMessageWithProtocolOp(res)
			w.WriteMessage(responseMessage)
			log.Printf(fmt.Sprintf("client [%d]: search with filter '%s' successful", m.Client.Numero, r.FilterString()))
		}
	}
}

// handle search for different basedn
func handleSearchOther(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	r := m.GetSearchRequest()

	// remove spaces from baseDN
	if strings.ReplaceAll(string(r.BaseObject()), " ", "") == baseDN {
		handleSearch(w, m)
		return
	}

	diagMessage := fmt.Sprintf("search allowed only for basedn '%s', got '%s'", baseDN, r.BaseObject())
	res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
	res.SetDiagnosticMessage(diagMessage)
	w.Write(res)

	log.Printf("client [%d]: search error: %s", m.Client.Numero, diagMessage)
}

func handleCompare(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	stop := false
	go func() {
		<-m.Done
		log.Printf("client [%d]: leaving handleCompare...", m.Client.Numero)
		stop = true
	}()

	r := m.GetCompareRequest()
	log.Printf("client [%d]: performing compare '%s' for dn '%s'", m.Client.Numero, r.Ava(), r.Entry())

	if !strings.HasSuffix(string(r.Entry()), baseDN) {
		diagMessage := fmt.Sprintf("entry must end with basedn '%s'", baseDN)
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: compare error: %s", m.Client.Numero, diagMessage)
		return
	}

	compareEntry := strings.SplitN(string(strings.TrimSuffix(string(r.Entry()), fmt.Sprintf(",%s", baseDN))), "=", 2)
	compareAttrName := compareEntry[0]
	compareAttrValue := compareEntry[1]

	if compareAttrName != "cn" {
		diagMessage := fmt.Sprintf("entry must look like 'cn=<COMMON_NAME>,%s'", baseDN)
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: compare error: %s", m.Client.Numero, diagMessage)
		return
	}

	if memStoreTimeout <= 0 {
		restData.update(m.Client.Numero, compareAttrValue, "")
	}

	for _, user := range restData.Users {
		if stop {
			return
		}

		if user.CN[0] != compareAttrValue {
			continue
		}

		if doCompare(user, string(r.Ava().AttributeDesc()), string(r.Ava().AssertionValue())) {
			res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareTrue)
			w.Write(res)

			log.Printf("client [%d]: compare '%s:%s' for dn '%s' TRUE", m.Client.Numero, r.Ava().AttributeDesc(), r.Ava().AssertionValue(), r.Entry())
			return
		}
	}

	for _, group := range restData.Groups {
		if stop {
			return
		}

		if group.CN[0] != compareAttrValue {
			continue
		}

		if doCompare(group, string(r.Ava().AttributeDesc()), string(r.Ava().AssertionValue())) {
			res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareTrue)
			w.Write(res)

			log.Printf("client [%d]: compare '%s:%s' for dn '%s' TRUE", m.Client.Numero, r.Ava().AttributeDesc(), r.Ava().AssertionValue(), r.Entry())
			return
		}
	}

	res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareFalse)
	w.Write(res)

	log.Printf("client [%d]: compare '%s for dn '%s' FALSE", m.Client.Numero, r.Ava(), r.Entry())
}
