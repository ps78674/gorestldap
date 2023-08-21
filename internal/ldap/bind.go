package ldap

import (
	"fmt"
	"reflect"

	"github.com/ps78674/gorestldap/internal/data"
	"github.com/ps78674/gorestldap/internal/ldaputils"
	"github.com/ps78674/gorestldap/internal/ssha"
	ldapserver "github.com/ps78674/ldapserver"
	"github.com/sirupsen/logrus"
)

func handleBind(w ldapserver.ResponseWriter, m *ldapserver.Message, entries *data.Entries, baseDN, usersOUName string, logger *logrus.Logger) {
	entries.RLock()
	defer entries.RUnlock()

	r := m.GetBindRequest()
	logger.Infof("client [%d]: bind dn='%s'", m.Client.Numero(), r.Name())

	// only simple authentication supported
	if r.AuthenticationChoice() != "simple" {
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultAuthMethodNotSupported)
		w.Write(res)

		logger.Errorf("client [%d]: bind error: authentication method '%s' is not supported", m.Client.Numero(), r.AuthenticationChoice())
		return
	}

	// check bind entry dn
	bindEntry := ldaputils.NormalizeEntry(string(r.Name()))
	if !isCorrectDn(bindEntry) {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultInvalidDNSyntax)
		w.Write(res)

		logger.Errorf("client [%d]: bind error: wrong dn '%s'", m.Client.Numero(), r.Name())
		return
	}

	bindEntryAttr, bindEntryName, bindEntrySuffix := getEntryAttrValueSuffix(bindEntry)

	userData := data.User{}
	if bindEntrySuffix != "ou="+usersOUName+","+baseDN {
		goto userNotFound
	}

	for _, user := range entries.Users {
		var cmpValue string
		switch bindEntryAttr {
		case "cn":
			cmpValue = user.CN
		case "uid":
			cmpValue = user.UID
		}
		if cmpValue != bindEntryName {
			continue
		}
		userData = user
	}

userNotFound:
	// got empty struct -> user not found
	if reflect.DeepEqual(userData, data.User{}) {
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultNoSuchObject)
		w.Write(res)

		logger.Errorf("client [%d]: bind error: dn '%s' not found", m.Client.Numero(), r.Name())
		return
	}

	// validate password
	ok, err := ssha.ValidatePassword(r.AuthenticationSimple().String(), userData.UserPassword)
	if !ok {
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
		w.Write(res)

		errMsg := fmt.Sprintf("wrong password for dn '%s'", r.Name())
		if err != nil {
			errMsg = errMsg + ": " + err.Error()
		}

		logger.Errorf("client [%d]: bind error: %s", m.Client.Numero(), errMsg)
		return
	}

	// set ACLs
	acl := clientACL{
		bindEntry: bindEntry,
	}
	if userData.LDAPAdmin {
		acl = clientACL{
			search:  true,
			compare: true,
			modify:  true,
		}
	}

	// update additional data with created ACLs
	m.Client.SetAddData(additionalData{acl: acl})

	res := ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess)
	w.Write(res)

	logger.Infof("client [%d]: bind result=OK", m.Client.Numero())
}
