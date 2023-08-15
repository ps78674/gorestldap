package ldap

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	ldap "github.com/ps78674/goldap/message"
	"github.com/ps78674/gorestldap/internal/backend"
	"github.com/ps78674/gorestldap/internal/data"
	"github.com/ps78674/gorestldap/internal/ticker"
	ldapserver "github.com/ps78674/ldapserver"
	"github.com/sirupsen/logrus"
)

// handle modify
func handleModify(w ldapserver.ResponseWriter, m *ldapserver.Message, entries *data.Entries, baseDN, usersOUName, groupsOUName string, b backend.Backend, ticker *ticker.Ticker, logger *logrus.Logger) {
	entries.RLock()
	defer entries.RUnlock()

	r := m.GetModifyRequest()
	logger.Infof("client [%d]: modify dn='%s'", m.Client.Numero(), r.Object())

	// check modify entry dn
	modifyEntry := NormalizeEntry(string(r.Object()))
	if !isCorrectDn(modifyEntry) {
		res := ldapserver.NewModifyResponse(ldapserver.LDAPResultInvalidDNSyntax)
		w.Write(res)

		logger.Errorf("client [%d]: modify error: wrong dn '%s'", m.Client.Numero(), r.Object())
		return
	}

	// modify of domain or ou is not supported
	if modifyEntry == baseDN || modifyEntry == "ou="+usersOUName+","+baseDN || modifyEntry == "ou="+groupsOUName+","+baseDN {
		diagMessage := fmt.Sprintf("modify of '%s' is not supported", modifyEntry)
		res := ldapserver.NewModifyResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		logger.Errorf("client [%d]: modify error: %s", m.Client.Numero(), diagMessage)
		return
	}

	// get ACLs
	acl := clientACL{}
	if addData := m.Client.GetAddData(); addData != nil {
		acl = addData.(additionalData).acl
	}

	// non-admin can modify only own entry
	if !acl.modify && modifyEntry != acl.bindEntry {
		res := ldapserver.NewModifyResponse(ldapserver.LDAPResultInsufficientAccessRights)
		w.Write(res)

		logger.Warnf("client [%d]: modify insufficient access", m.Client.Numero())
		return
	}

	var oldEntry interface{}
	modifyEntryAttr, modifyEntryName, modifyEntrySuffix := getEntryAttrValueSuffix(modifyEntry)
	switch {
	case modifyEntrySuffix == "ou="+usersOUName+","+baseDN:
		for _, user := range entries.Users {
			// handle stop signal
			select {
			case <-m.Done:
				logger.Infof("client [%d]: leaving handleModify...", m.Client.Numero())
				return
			default:
			}

			var cmpValue string
			switch modifyEntryAttr {
			case "cn":
				cmpValue = user.CN
			case "uid":
				cmpValue = user.UID
			}

			if cmpValue != modifyEntryName {
				continue
			}

			oldEntry = user
			break
		}
	case strings.HasPrefix(modifyEntry, "cn=") && modifyEntrySuffix == "ou="+groupsOUName+","+baseDN:
		for _, group := range entries.Groups {
			// handle stop signal
			select {
			case <-m.Done:
				logger.Infof("client [%d]: leaving handleModify...", m.Client.Numero())
				return
			default:
			}

			if group.CN != modifyEntryName {
				continue
			}

			oldEntry = group
			break
		}
	}

	// entry not found
	if oldEntry == nil {
		res := ldapserver.NewModifyResponse(ldapserver.LDAPResultNoSuchObject)
		w.Write(res)

		logger.Errorf("client [%d]: modify error: target entry not found", m.Client.Numero())
		return
	}

	// copy entry for modify
	newEntry := oldEntry

	for _, c := range r.Changes() {
		// handle stop signal
		select {
		case <-m.Done:
			logger.Infof("client [%d]: leaving handleModify...", m.Client.Numero())
			return
		default:
		}

		// check operation type
		attrName := string(c.Modification().Type_())
		opType := c.Operation().Int()
		logger.Infof("client [%d]: modify op=%d attr=%s", m.Client.Numero(), c.Operation(), attrName)
		if c.Operation().Int() != ldap.ModifyRequestChangeOperationReplace {
			diagMessage := fmt.Sprintf("wrong operation %d: only 2 (replace) is supported", opType)
			res := ldapserver.NewModifyResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(diagMessage)
			w.Write(res)

			logger.Errorf("client [%d]: modify error: %s", m.Client.Numero(), diagMessage)
			return
		}

		// modify
		if err := doModify(&newEntry, attrName, c.Modification().Vals()); err != nil {
			res := ldapserver.NewModifyResponse(err.(LDAPError).ResultCode)
			w.Write(res)

			logger.Errorf("client [%d]: modify error: %s", m.Client.Numero(), err)
			return
		}
	}

	// update backend entry
	if err := b.UpdateData(oldEntry, newEntry); err != nil {
		diagMessage := fmt.Sprintf("error updating backend data: %s", err)
		res := ldapserver.NewModifyResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		logger.Errorf("client [%d]: modify error: %s", m.Client.Numero(), diagMessage)
		return
	}

	// get updated entries
	ticker.Reset()

	// modify OK
	res := ldapserver.NewModifyResponse(ldapserver.LDAPResultSuccess)
	w.Write(res)

	logger.Infof("client [%d]: modify result=OK", m.Client.Numero())
}

// doModify update object's 'o' attr 'attrName' with value 'attrValue'
func doModify(o interface{}, attrName string, values []ldap.AttributeValue) error {
	root := reflect.ValueOf(o).Elem()
	obj := root.Elem()
	objType := obj.Type()

	field, found := objType.FieldByNameFunc(func(s string) bool { return strings.EqualFold(s, attrName) })
	if !found {
		return errLDAPNoAttr
	}
	if tagValueContains(field.Tag, "ldap", "skip") {
		return errLDAPNoAttr
	}

	objCopy := reflect.New(objType).Elem()
	objCopy.Set(obj)

	fieldValue := objCopy.FieldByName(field.Name)
	if !fieldValue.IsValid() {
		return errLDAPNoAttr
	}

	switch fieldValue.Interface().(type) {
	case uint:
		if len(values) > 1 {
			return errLDAPMultiValue
		}
		_uint, err := strconv.ParseUint(string(values[0]), 10, 32)
		if err != nil {
			return LDAPError{
				ldap.ResultCodeUndefinedAttributeType,
				fmt.Errorf("wrong attribute value: %s", err),
			}
		}
		fieldValue.SetUint(_uint)
	case string:
		if len(values) > 1 {
			return errLDAPMultiValue
		}
		fieldValue.SetString(string(values[0]))
	case []string:
		for _, v := range values {
			fieldValue.SetString(string(v))
		}
	}

	root.Set(objCopy)

	return nil
}
