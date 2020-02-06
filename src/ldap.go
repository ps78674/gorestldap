package main

import (
	"fmt"
	"log"
	"reflect"
	"strings"

	ldap "github.com/ps78674/goldap/message"
	ldapserver "github.com/ps78674/ldapserver"
)

type searchAttributes struct {
	objectClass  string
	cn           string
	uidNumber    string
	gidNumber    string
	ipHostNumber string
	memberUID    string
	member       string
}

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
	userData := getRESTUserData(m.Client.Numero, userName, "", "")

	if len(userData) == 0 {
		diagMessage := fmt.Sprintf("user '%s' not found", userName)
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: bind error: %s", m.Client.Numero, diagMessage)
		return
	}

	// if !validatePassword(string(r.AuthenticationSimple()), userData[0].UserPassword[0]) {
	// 	diagMessage := fmt.Sprintf("wrong password for user '%s'", r.Name())
	// 	res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
	// 	res.SetDiagnosticMessage(diagMessage)
	// 	w.Write(res)

	// 	log.Printf("bind error: %s", diagMessage)
	// 	return
	// }

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
		log.Print("leaving handleSearch...")
		stop = true
	}()

	r := m.GetSearchRequest()

	log.Printf("client [%d]: performing search with filter '%s'", m.Client.Numero, r.FilterString())

	sa := new(searchAttributes)
	if err := expandFilter(m.Client.Numero, r.Filter(), r.FilterString(), sa); err != nil {
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(err.Error())
		w.Write(res)

		log.Printf("client [%d]: search error: %s", m.Client.Numero, err)
		return
	}

	switch sa.objectClass {
	case "", "posixAccount", "shadowAccount":
		users := getRESTUserData(m.Client.Numero, sa.cn, sa.uidNumber, sa.ipHostNumber)

		if stop {
			return
		}

		for _, user := range users {
			e := ldapserver.NewSearchResultEntry(fmt.Sprintf("cn=%s,%s", user.CN[0], r.BaseObject()))
			e.AddAttribute("cn", ldap.AttributeValue(user.CN[0]))
			// e.AddAttribute("objectClass", "inetOrgPerson", "organizationalPerson", "top", "posixAccount", "person", "ipHost", "ldapPublicKey", "shadowAccount")
			e.AddAttribute("objectClass", "inetOrgPerson", "organizationalPerson", "person", "posixAccount", "shadowAccount")
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

			for _, sshKey := range user.SSHPublicKey {
				e.AddAttribute("sshPublicKey", ldap.AttributeValue(sshKey))
			}

			for _, hostIP := range user.IPHostNumber {
				e.AddAttribute("ipHostNumber", ldap.AttributeValue(hostIP))
			}

			w.Write(e)
		}
	case "posixGroup":
		groups := getRESTGroupData(m.Client.Numero, sa.cn, sa.gidNumber, sa.memberUID)

		if stop {
			return
		}

		for _, group := range groups {
			e := ldapserver.NewSearchResultEntry(fmt.Sprintf("cn=%s,%s", group.CN[0], r.BaseObject()))
			// e.AddAttribute("objectClass", "top", "posixGroup")
			e.AddAttribute("objectClass", "posixGroup")
			e.AddAttribute("description", ldap.AttributeValue(group.Description[0]))
			e.AddAttribute("cn", ldap.AttributeValue(group.CN[0]))
			e.AddAttribute("gidNumber", ldap.AttributeValue(group.GIDNumber[0]))

			for _, membrUID := range group.MemberUID {
				e.AddAttribute("memberUid", ldap.AttributeValue(membrUID))
			}

			w.Write(e)
		}
	default:
		diagMessage := fmt.Sprintf("wrong objectClass '%s', should be posixAccount or posixGroup", sa.objectClass)
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Printf("client [%d]: search error: %s", m.Client.Numero, diagMessage)
		return
	}

	res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess)
	w.Write(res)

	log.Printf("client [%d]: search with filter '%s' successful", m.Client.Numero, r.FilterString())
}

// handle search filter
func expandFilter(cNum int, filter ldap.Filter, filterString string, sa *searchAttributes) error {
	switch fmt.Sprintf("%T", filter) {
	case "message.FilterAnd", "message.FilterOr":
		items := reflect.ValueOf(filter)
		for i := 0; i < items.Len(); i++ {
			if err := expandFilter(cNum, items.Index(i).Interface().(ldap.Filter), filterString, sa); err != nil {
				return err
			}
		}
	case "message.Filter", "message.FilterEqualityMatch":
		attrName := reflect.ValueOf(filter).Field(0).String()
		attrValue := reflect.ValueOf(filter).Field(1).String()

		switch attrName {
		case "cn", "uid", "gid":
			sa.cn = attrValue
		case "objectClass":
			sa.objectClass = attrValue
		case "uidNumber":
			sa.uidNumber = attrValue
		case "gidNumber":
			sa.gidNumber = attrValue
		case "ipHostNumber":
			sa.ipHostNumber = attrValue
		case "memberUid":
			sa.memberUID = attrValue
		case "member":
			sa.member = attrValue
		default:
			return fmt.Errorf("client [%d]: unsupported search filter '%s'", cNum, filterString)
		}
	default:
		return fmt.Errorf("client [%d]: unsupported message filter type '%s'", cNum, reflect.TypeOf(filter).String())
	}

	return nil
}
