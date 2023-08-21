package ldap

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/ps78674/gorestldap/internal/data"
	"github.com/ps78674/gorestldap/internal/ldaputils"
	ldapserver "github.com/ps78674/ldapserver"
	"github.com/sirupsen/logrus"
)

// handle compare
func handleCompare(w ldapserver.ResponseWriter, m *ldapserver.Message, entries *data.Entries, baseDN, usersOUName, groupsOUName string, logger *logrus.Logger) {
	entries.RLock()
	defer entries.RUnlock()

	r := m.GetCompareRequest()
	attrName := string(r.Ava().AttributeDesc())
	logger.Infof("client [%d]: compare dn='%s' attr='%s'", m.Client.Numero(), r.Entry(), attrName)

	// check compare entry dn
	compareEntry := ldaputils.NormalizeEntry(string(r.Entry()))
	if !isCorrectDn(compareEntry) {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultInvalidDNSyntax)
		w.Write(res)

		logger.Errorf("client [%d]: compare error: wrong dn '%s'", m.Client.Numero(), r.Entry())
		return
	}

	// compare for entryDN is not supported
	if strings.ToLower(attrName) == "entrydn" {
		diagMessage := "compare over entrydn is not supported"
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		logger.Errorf("client [%d]: compare error: %s", m.Client.Numero(), diagMessage)
		return
	}

	// get ACLs
	acl := clientACL{}
	if addData := m.Client.GetAddData(); addData != nil {
		acl = addData.(additionalData).acl
	}

	// non-admin can only compare by own entry
	if !acl.compare && compareEntry != acl.bindEntry {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultInsufficientAccessRights)
		w.Write(res)

		logger.Warnf("client [%d]: compare insufficient access", m.Client.Numero())
		return
	}

	var entry interface{}
	compareEntryAttr, compareEntryName, compareEntrySuffix := getEntryAttrValueSuffix(compareEntry)
	switch {
	case compareEntry == baseDN:
		entry = entries.Domain
	case strings.HasPrefix(compareEntry, "ou=") && compareEntrySuffix == baseDN:
		for _, ou := range entries.OUs {
			// handle stop signal
			select {
			case <-m.Done:
				logger.Infof("client [%d]: leaving handleCompare...", m.Client.Numero())
				return
			default:
			}

			if ou.OU != compareEntryName {
				continue
			}

			entry = ou
			break
		}
	case compareEntrySuffix == "ou="+usersOUName+","+baseDN:
		for _, user := range entries.Users {
			// handle stop signal
			select {
			case <-m.Done:
				logger.Infof("client [%d]: leaving handleCompare...", m.Client.Numero())
				return
			default:
			}

			var cmpValue string
			switch compareEntryAttr {
			case "cn":
				cmpValue = user.CN
			case "uid":
				cmpValue = user.UID
			}
			if cmpValue != compareEntryName {
				continue
			}

			entry = user
			break
		}
	case strings.HasPrefix(compareEntry, "cn=") && compareEntrySuffix == "ou="+groupsOUName+","+baseDN:
		for _, group := range entries.Groups {
			// handle stop signal
			select {
			case <-m.Done:
				logger.Infof("client [%d]: leaving handleCompare...", m.Client.Numero())
				return
			default:
			}

			if group.CN != compareEntryName {
				continue
			}

			entry = group
			break
		}
	}

	// entry not found
	if entry == nil {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultNoSuchObject)
		w.Write(res)

		logger.Errorf("client [%d]: compare error: target entry not found", m.Client.Numero())
		return
	}

	// compare
	ok, err := doCompare(entry, attrName, string(r.Ava().AssertionValue()))
	if err != nil {
		res := ldapserver.NewCompareResponse(err.(LDAPError).ResultCode)
		w.Write(res)

		logger.Errorf("client [%d]: compare error: %s", m.Client.Numero(), err)
		return
	}
	if !ok {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareFalse)
		w.Write(res)

		logger.Infof("client [%d]: compare result=FALSE", m.Client.Numero())
		return
	}

	// compare TRUE
	res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareTrue)
	w.Write(res)

	logger.Infof("client [%d]: compare result=TRUE", m.Client.Numero())
}

// doCompare checks if object 'o' have attr 'attrName' with value 'attrValue'
func doCompare(o interface{}, attrName string, attrValue string) (bool, error) {
	field, found := reflect.TypeOf(o).FieldByNameFunc(func(s string) bool { return strings.EqualFold(s, attrName) })
	if !found {
		return false, errLDAPNoAttr
	}
	if tagValueContains(field.Tag, "ldap", "skip") {
		return false, errLDAPNoAttr
	}

	fieldValue := reflect.ValueOf(o).FieldByName(field.Name)
	if !fieldValue.IsValid() {
		return false, errLDAPNoAttr
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

	return false, nil
}
