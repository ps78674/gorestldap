package ldap

import (
	"fmt"

	"github.com/ps78674/gorestldap/internal/backend"
	"github.com/ps78674/gorestldap/internal/data"
	"github.com/ps78674/gorestldap/internal/ticker"
	ldapserver "github.com/ps78674/ldapserver"
	"github.com/sirupsen/logrus"
)

func NewServer(entries *data.Entries, baseDN, usersOUName, groupsOUName string, respectCritical bool, backend backend.Backend, ticker *ticker.Ticker, logger *logrus.Logger) (*ldapserver.Server, error) {
	// create server
	s := ldapserver.NewServer()

	logger.Debug("registering handlers")

	// create route bindings
	routes := ldapserver.NewRouteMux()
	routes.Bind(func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		handleBind(w, m, entries, baseDN, usersOUName, logger)
	})
	routes.Search(func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		handleSearchDSE(w, m, baseDN, logger)
	}).BaseDn("").Scope(ldapserver.SearchRequestScopeBaseObject).Filter("(objectclass=*)")
	routes.Search(func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		handleSearch(w, m, entries, baseDN, usersOUName, groupsOUName, respectCritical, logger)
	})
	routes.Compare(func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		handleCompare(w, m, entries, baseDN, usersOUName, groupsOUName, logger)
	})
	routes.Modify(func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		handleModify(w, m, entries, baseDN, usersOUName, groupsOUName, backend, ticker, logger)
	})

	// attach routes to server
	if err := s.Handle(routes); err != nil {
		return nil, fmt.Errorf("error registering handlers: %s", err)
	}

	return s, nil
}
