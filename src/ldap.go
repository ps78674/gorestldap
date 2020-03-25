package main

import (
	"fmt"
	"log"
	"reflect"
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
	userData := getRESTUserData(m.Client.Numero, userName)

	if len(userData) == 0 {
		diagMessage := fmt.Sprintf("user '%s' not found", userName)
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: bind error: %s", m.Client.Numero, diagMessage)
		return
	}

	if !validatePassword(string(r.AuthenticationSimple()), userData[0].UserPassword[0]) {
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

// handle search for different basedn
func handleSearchOther(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	diagMessage := fmt.Sprintf("search allowed only for basedn '%s'", baseDN)
	res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
	res.SetDiagnosticMessage(diagMessage)
	w.Write(res)

	log.Printf("client [%d]: search error: %s", m.Client.Numero, diagMessage)
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
		restData.update(m.Client.Numero, "")
	}

	for _, user := range restData.Users {
		if stop {
			return
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
		e.AddAttribute("cn", ldap.AttributeValue(user.CN[0]))
		e.AddAttribute("objectClass", "posixAccount", "shadowAccount", "organizationalPerson", "inetOrgPerson", "person")
		e.AddAttribute("homeDirectory", ldap.AttributeValue(user.HomeDirectory[0]))
		e.AddAttribute("uid", ldap.AttributeValue(user.UID[0]))
		e.AddAttribute("uidNumber", ldap.AttributeValue(user.UIDNumber[0]))
		e.AddAttribute("mail", ldap.AttributeValue(user.Mail[0]))
		e.AddAttribute("displayName", ldap.AttributeValue(user.DisplayName[0]))
		e.AddAttribute("givenName", ldap.AttributeValue(user.GivenName[0]))
		e.AddAttribute("sn", ldap.AttributeValue(user.SN[0]))
		e.AddAttribute("userPassword", ldap.AttributeValue(user.UserPassword[0]))
		e.AddAttribute("loginShell", ldap.AttributeValue(user.LoginShell[0]))
		e.AddAttribute("gidNumber", ldap.AttributeValue(user.GIDNumber[0]))
		// e.AddAttribute("ibm-chassisRole", ldap.AttributeValue("IBMRBSPermissions=010000000000")) // TESTING - attribute for lenovo lxcc (bmc ldap login)

		attrs := []ldap.AttributeValue{}
		for _, sshKey := range user.SSHPublicKey {
			attrs = append(attrs, ldap.AttributeValue(sshKey))
		}
		e.AddAttribute("sshPublicKey", attrs...)

		attrs = []ldap.AttributeValue{}
		for _, hostIP := range user.IPHostNumber {
			attrs = append(attrs, ldap.AttributeValue(hostIP))
		}
		e.AddAttribute("ipHostNumber", attrs...)

		w.Write(e)
	}

	for _, group := range restData.Groups {
		if stop {
			return
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
		e.AddAttribute("description", ldap.AttributeValue(group.Description[0]))
		e.AddAttribute("cn", ldap.AttributeValue(group.CN[0]))
		e.AddAttribute("gidNumber", ldap.AttributeValue(group.GIDNumber[0]))

		attrs := []ldap.AttributeValue{}
		for _, ou := range group.OU {
			attrs = append(attrs, ldap.AttributeValue(ou))
		}
		e.AddAttribute("ou", attrs...)

		attrs = []ldap.AttributeValue{}
		for _, membrUID := range group.MemberUID {
			attrs = append(attrs, ldap.AttributeValue(membrUID))
		}
		e.AddAttribute("memberUid", attrs...)

		w.Write(e)
	}

	res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess)
	w.Write(res)

	log.Printf("client [%d]: search with filter '%s' successful", m.Client.Numero, r.FilterString())
}

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
			if strings.ToLower(rValue.Type().Field(i).Tag.Get("json")) == strings.ToLower(reflect.ValueOf(f).String()) && rValue.Field(i).Len() > 0 {
				return true, nil
			}
		}
	default:
		return false, fmt.Errorf("unsupported filter type '%T'", f)
	}

	return false, nil
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
		restData.update(m.Client.Numero, compareAttrValue)
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
