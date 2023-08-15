package ldap

import (
	"fmt"
	"time"

	"github.com/ps78674/gorestldap/internal/backend"
	"github.com/ps78674/gorestldap/internal/data"
	ldapserver "github.com/ps78674/ldapserver"
	log "github.com/sirupsen/logrus"
)

func NewServer(entries *data.Entries, baseDN, usersOUName, groupsOUName string, respectCritical bool, updateInterval time.Duration, backend backend.Backend, ticker *time.Ticker) (*ldapserver.Server, error) {
	// create server
	s := ldapserver.NewServer()

	log.Debug("registering handlers")

	// create route bindings
	routes := ldapserver.NewRouteMux()
	routes.Bind(func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		handleBind(w, m, entries, baseDN, usersOUName)
	})
	routes.Search(func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		handleSearchDSE(w, m, baseDN)
	}).BaseDn("").Scope(ldapserver.SearchRequestScopeBaseObject).Filter("(objectclass=*)")
	routes.Search(func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		handleSearch(w, m, entries, baseDN, usersOUName, groupsOUName, respectCritical)
	})
	routes.Compare(func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		handleCompare(w, m, entries, baseDN, usersOUName, groupsOUName)
	})
	routes.Modify(func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		handleModify(w, m, entries, baseDN, usersOUName, groupsOUName, backend, ticker, updateInterval)
	})

	// attach routes to server
	if err := s.Handle(routes); err != nil {
		return nil, fmt.Errorf("error registering handlers: %s", err)
	}

	return s, nil
}
