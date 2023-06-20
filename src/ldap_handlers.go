package main

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	ldap "github.com/ps78674/goldap/message"
	"github.com/ps78674/gorestldap/src/internal/data"
	ldapserver "github.com/ps78674/ldapserver"
	log "github.com/sirupsen/logrus"
)

type clientACL struct {
	bindEntry string
	search    bool
	compare   bool
	modify    bool
}

type clientSearchControl struct {
	domainDone bool
	ousDone    bool
	usersDone  bool
	groupsDone bool
	count      int
	sent       int
}

type additionalData struct {
	acl clientACL
	sc  clientSearchControl
}

// handle bind
func handleBind(w ldapserver.ResponseWriter, m *ldapserver.Message, entries *data.Entries, cfg *Config) {
	entries.RLock()
	defer entries.RUnlock()

	r := m.GetBindRequest()
	log.Infof("client [%d]: bind dn='%s'", m.Client.Numero(), r.Name())

	// only simple authentication supported
	if r.AuthenticationChoice() != "simple" {
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultAuthMethodNotSupported)
		w.Write(res)

		log.Errorf("client [%d]: bind error: authentication method '%s' is not supported", m.Client.Numero(), r.AuthenticationChoice())
		return
	}

	// check bind entry dn
	bindEntry := normalizeEntry(string(r.Name()))
	if !isCorrectDn(bindEntry) {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultInvalidDNSyntax)
		w.Write(res)

		log.Errorf("client [%d]: bind error: wrong dn '%s'", m.Client.Numero(), r.Name())
		return
	}

	bindEntryAttr, bindEntryName, bindEntrySuffix := getEntryAttrValueSuffix(bindEntry)

	userData := data.User{}
	if bindEntrySuffix != "ou="+cfg.UsersOUName+","+cfg.BaseDN {
		goto userNotFound
	}

	for i := range entries.Users {
		var cmpValue string
		switch bindEntryAttr {
		case "cn":
			cmpValue = entries.Users[i].CN
		case "uid":
			cmpValue = entries.Users[i].UID
		}
		if cmpValue != bindEntryName {
			continue
		}
		userData = entries.Users[i]
	}

userNotFound:
	// got empty struct -> user not found
	if reflect.DeepEqual(userData, data.User{}) {
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultNoSuchObject)
		w.Write(res)

		log.Errorf("client [%d]: bind error: dn '%s' not found", m.Client.Numero(), r.Name())
		return
	}

	// validate password
	ok, err := validatePassword(r.AuthenticationSimple().String(), userData.UserPassword)
	if !ok {
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
		w.Write(res)

		errMsg := fmt.Sprintf("wrong password for dn '%s'", r.Name())
		if err != nil {
			errMsg = errMsg + ": " + err.Error()
		}

		log.Errorf("client [%d]: bind error: %s", m.Client.Numero(), errMsg)
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

	log.Infof("client [%d]: bind result=OK", m.Client.Numero())
}

// search DSE
func handleSearchDSE(w ldapserver.ResponseWriter, m *ldapserver.Message, cfg *Config) {
	r := m.GetSearchRequest()

	log.Infof("client [%d]: search base='%s' scope=%d filter='%s'", m.Client.Numero(), r.BaseObject(), r.Scope(), r.FilterString())

	searchAttrs := []string{}
	for i := range r.Attributes() {
		searchAttrs = append(searchAttrs, string(r.Attributes()[i]))
	}

	log.Infof("client [%d]: search attr=%s", m.Client.Numero(), strings.Join(searchAttrs, " "))

	rootDSE := data.DSE{
		ObjectClass:          []string{"top", "LDAProotDSE"},
		VendorVersion:        versionString,
		SupportedLDAPVersion: 3,
		SupportedControl:     []string{string(ldap.PagedResultsControlOID)},
		NamingContexts:       []string{cfg.BaseDN},
	}

	e := createSearchEntry(rootDSE, searchAttrs, "")

	w.Write(e)
	w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))

	log.Infof("client [%d]: search result=OK nentries=1", m.Client.Numero())
}

// handle search
func handleSearch(w ldapserver.ResponseWriter, m *ldapserver.Message, entries *data.Entries, cfg *Config) {
	entries.RLock()
	defer entries.RUnlock()

	r := m.GetSearchRequest()

	log.Infof("client [%d]: search base='%s' scope=%d filter='%s'", m.Client.Numero(), r.BaseObject(), r.Scope(), r.FilterString())

	searchAttrs := []string{}
	for i := range r.Attributes() {
		searchAttrs = append(searchAttrs, string(r.Attributes()[i]))
	}

	log.Infof("client [%d]: search attr=%s", m.Client.Numero(), strings.Join(searchAttrs, " "))

	// check requested controls
	var controls []string
	var simplePagedResultsControl ldap.SimplePagedResultsControl
	var gotUCControl bool
	if m.Controls() != nil {
		_controls := *m.Controls()
		for i := range controls {
			switch _controls[i].ControlType() {
			// 1.2.840.113556.1.4.319 (pagedSearch)
			case ldap.PagedResultsControlOID:
				controls = append(controls, _controls[i].ControlType().String())
				c, err := ldap.ReadPagedResultsControl(_controls[i].ControlValue())
				if err != nil {
					log.Errorf("client [%d]: error decoding pagedResultsControl: %s", m.Client.Numero(), err)
				}
				simplePagedResultsControl = c
			default:
				if _controls[i].Criticality().Bool() {
					controls = append(controls, _controls[i].ControlType().String()+"(U,C)")
					gotUCControl = true
				} else {
					controls = append(controls, _controls[i].ControlType().String()+"(U)")
				}
			}
		}
	}

	log.Infof("client [%d]: search ctrl=%s", m.Client.Numero(), strings.Join(controls, " "))

	// check for unsupported critical controls
	if gotUCControl && cfg.RespectCritical {
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnavailableCriticalExtension)
		w.Write(res)

		log.Errorf("client [%d]: search error: got unsupported critical controls, aborting", m.Client.Numero())
		return
	}

	log.Infof("client [%d]: search sizelimit=%d pagesize=%d", m.Client.Numero(), r.SizeLimit(), simplePagedResultsControl.PageSize())

	// handle stop signal
	select {
	case <-m.Done:
		log.Infof("client [%d]: leaving handleSearch...", m.Client.Numero())
		return
	default:
	}

	// setup baseObject
	var baseObject string
	if len(r.BaseObject()) == 0 {
		baseObject = cfg.BaseDN
	} else {
		baseObject = normalizeEntry(string(r.BaseObject()))
	}

	// get ACLs & search control
	acl := clientACL{}
	searchControl := clientSearchControl{}
	if addData := m.Client.GetAddData(); addData != nil {
		acl = addData.(additionalData).acl
		searchControl = addData.(additionalData).sc
	}

	// non admin user allowed to search only over his entry
	if !acl.search && baseObject != acl.bindEntry {
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultNoSuchObject)
		w.Write(res)

		log.Warnf("client [%d]: search insufficient access", m.Client.Numero())
		return
	}

	entriesWritten := 0
	sizeLimitReached := false

	// check if more entries is available
	lastIteration := false

	// how much entries is left
	left := simplePagedResultsControl.PageSize().Int()
	if left == 0 {
		// 3 = domain + users ou + groups ou
		left = 3 + len(entries.Users) + len(entries.Groups)
	}

	// if domain processed -> go to users
	if searchControl.domainDone {
		goto ous
	}

	// got match
	if baseObject == cfg.BaseDN {
		// if searchScope == {base, sub} -> add domain entry
		if r.Scope() == ldap.SearchRequestScopeBaseObject || r.Scope() == ldap.SearchRequestScopeSubtree {
			ok, err := applySearchFilter(entries.Domain, r.Filter())
			if err != nil {
				res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
				res.SetDiagnosticMessage(err.Error())
				w.Write(res)

				log.Errorf("client [%d]: search error: %s", m.Client.Numero(), err)
				return
			}

			if r.SizeLimit().Int() > 0 && searchControl.sent == r.SizeLimit().Int() {
				sizeLimitReached = true
				goto end
			} else if ok {
				e := createSearchEntry(entries.Domain, searchAttrs, cfg.BaseDN)
				w.Write(e)

				searchControl.sent++
				entriesWritten++
				left--

				// base object found & written -> should not search more
				if r.Scope() == ldap.SearchRequestScopeBaseObject {
					goto end
				}
			}
		}

		// should search only one level down, over OUs
		if r.Scope() == ldap.SearchRequestScopeOneLevel {
			searchControl.usersDone = true
			searchControl.groupsDone = true
		}
	}

	// domain processed
	searchControl.domainDone = true

ous:
	// if ous processed -> go to users
	if searchControl.ousDone {
		goto users
	}

	for i := searchControl.count; i < len(entries.OUs); i++ {
		// handle stop signal
		select {
		case <-m.Done:
			log.Infof("client [%d]: leaving handleSearch...", m.Client.Numero())
			return
		default:
		}

		if left == 0 && !lastIteration {
			lastIteration = true
		}

		if !lastIteration {
			searchControl.count++
		}

		entryName := fmt.Sprintf("ou=%s,%s", entries.OUs[i].OU, cfg.BaseDN)

		// entry does not belong to base object
		if !strings.HasSuffix(entryName, baseObject) {
			continue
		}

		// entry != baseobject & scope == base requested
		if r.Scope() == ldap.SearchRequestScopeBaseObject && entryName != baseObject {
			continue
		}

		// search sublevel based on ou name (users or groups)
		if entryName == baseObject && (r.Scope() == ldap.SearchRequestScopeOneLevel || r.Scope() == ldap.SearchRequestScopeChildren) {
			searchControl.count = 0
			switch entries.OUs[i].OU {
			case cfg.UsersOUName:
				searchControl.groupsDone = true
				goto users
			case cfg.GroupsOUName:
				searchControl.usersDone = true
				goto groups
			}
		}

		// if size limit reached -> go to response
		if r.SizeLimit().Int() > 0 && searchControl.sent == r.SizeLimit().Int() {
			sizeLimitReached = true
			goto end
		}

		// apply search filter for each ou
		ok, err := applySearchFilter(entries.OUs[i], r.Filter())
		if err != nil {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(err.Error())
			w.Write(res)

			log.Errorf("client [%d]: search error: %s", m.Client.Numero(), err)
			return
		}

		// if filter not applied -> skip ou
		if !ok {
			continue
		}

		if lastIteration {
			goto end
		}

		e := createSearchEntry(entries.OUs[i], searchAttrs, entryName)
		w.Write(e)

		searchControl.sent++
		entriesWritten++
		left--

		// base object found & written -> should not search more
		if r.Scope() == ldap.SearchRequestScopeBaseObject {
			goto end
		}
	}

	// ous processed
	searchControl.count = 0
	searchControl.ousDone = true

users:
	// if users processed -> go to groups
	if searchControl.usersDone {
		goto groups
	}

	for i := searchControl.count; i < len(entries.Users); i++ {
		// handle stop signal
		select {
		case <-m.Done:
			log.Infof("client [%d]: leaving handleSearch...", m.Client.Numero())
			return
		default:
		}

		if left == 0 && !lastIteration {
			lastIteration = true
		}

		if !lastIteration {
			searchControl.count++
		}

		entryName := fmt.Sprintf("cn=%s,ou=%s,%s", entries.Users[i].CN, cfg.UsersOUName, cfg.BaseDN)

		// entry does not belong to base object
		if !strings.HasSuffix(entryName, baseObject) {
			continue
		}

		// entry != baseobject & scope == base requested
		if r.Scope() == ldap.SearchRequestScopeBaseObject && entryName != baseObject {
			continue
		}

		// user does not have sublevel, END
		if entryName == baseObject && (r.Scope() == ldap.SearchRequestScopeOneLevel || r.Scope() == ldap.SearchRequestScopeChildren) {
			searchControl.usersDone = true
			searchControl.groupsDone = true
			goto end
		}

		// if size limit reached -> go to response
		if r.SizeLimit().Int() > 0 && searchControl.sent == r.SizeLimit().Int() {
			sizeLimitReached = true
			goto end
		}

		// apply search filter for each user
		ok, err := applySearchFilter(entries.Users[i], r.Filter())
		if err != nil {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(err.Error())
			w.Write(res)

			log.Errorf("client [%d]: search error: %s", m.Client.Numero(), err)
			return
		}

		// if filter not applied -> skip user
		if !ok {
			continue
		}

		if lastIteration {
			goto end
		}

		e := createSearchEntry(entries.Users[i], searchAttrs, entryName)
		w.Write(e)

		searchControl.sent++
		entriesWritten++
		left--

		// base object found & written -> should not search more
		if r.Scope() == ldap.SearchRequestScopeBaseObject {
			goto end
		}
	}

	// users processed
	searchControl.count = 0
	searchControl.usersDone = true

groups:
	// if groups processed -> go to end
	if searchControl.groupsDone {
		goto end
	}

	for i := searchControl.count; i < len(entries.Groups); i++ {
		// handle stop signal
		select {
		case <-m.Done:
			log.Infof("client [%d]: leaving handleSearch...", m.Client.Numero())
			return
		default:
		}

		if left == 0 && !lastIteration {
			lastIteration = true
		}

		if !lastIteration {
			searchControl.count++
		}

		entryName := fmt.Sprintf("cn=%s,ou=%s,%s", entries.Groups[i].CN, cfg.GroupsOUName, cfg.BaseDN)

		// entry does not belong to base object
		if !strings.HasSuffix(entryName, baseObject) {
			continue
		}

		// entry != baseobject & scope == base requested
		if r.Scope() == ldap.SearchRequestScopeBaseObject && entryName != baseObject {
			continue
		}

		// user does not have sublevel, END
		if entryName == baseObject && (r.Scope() == ldap.SearchRequestScopeOneLevel || r.Scope() == ldap.SearchRequestScopeChildren) {
			searchControl.usersDone = true
			searchControl.groupsDone = true
			goto end
		}

		// if size limit reached -> brake loop
		if r.SizeLimit().Int() > 0 && searchControl.sent == r.SizeLimit().Int() {
			sizeLimitReached = true
			goto end
		}

		// apply search filter for each group
		ok, err := applySearchFilter(entries.Groups[i], r.Filter())
		if err != nil {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(err.Error())
			w.Write(res)

			log.Errorf("client [%d]: search error: %s", m.Client.Numero(), err)
			return
		}

		// if filter not applied -> skip group
		if !ok {
			continue
		}

		if lastIteration {
			goto end
		}

		e := createSearchEntry(entries.Groups[i], searchAttrs, entryName)
		w.Write(e)

		searchControl.sent++
		entriesWritten++
		left--

		// base object found & written -> should not search more
		if r.Scope() == ldap.SearchRequestScopeBaseObject {
			goto end
		}
	}

	// groups processed
	searchControl.count = 0
	searchControl.groupsDone = true

end:
	newControls := ldap.Controls{}
	if simplePagedResultsControl.PageSize().Int() > 0 {
		cpCookie := ldap.OCTETSTRING(programName)

		// end search
		if (searchControl.domainDone && searchControl.ousDone && searchControl.usersDone && searchControl.groupsDone) || sizeLimitReached {
			cpCookie = ldap.OCTETSTRING("")
			// end search -> cleanup search control
			searchControl = clientSearchControl{}
		}

		// encode new paged results control
		v, err := ldap.WritePagedResultsControl(ldap.INTEGER(0), cpCookie)
		if err != nil {
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultProtocolError)
			w.Write(res)

			log.Errorf("client [%d]: search error: error encoding pagedResultsControl: %s", m.Client.Numero(), err)
			return
		}

		c := ldap.NewControl(ldap.PagedResultsControlOID, ldap.BOOLEAN(true), *v)
		newControls = append(newControls, c)
	} else {
		// end search -> cleanup search control
		searchControl = clientSearchControl{}
	}

	// update additional data with new search control
	m.Client.SetAddData(additionalData{acl: acl, sc: searchControl})

	resultCode := ldapserver.LDAPResultSuccess
	if sizeLimitReached {
		resultCode = ldapserver.LDAPResultSizeLimitExceeded
	}

	res := ldapserver.NewSearchResultDoneResponse(resultCode)
	responseMessage := ldap.NewLDAPMessageWithProtocolOp(res)

	ldap.SetMessageControls(responseMessage, newControls)
	w.WriteMessage(responseMessage)

	log.Infof("client [%d]: search result=OK nentries=%d", m.Client.Numero(), entriesWritten)
}

// handle compare
func handleCompare(w ldapserver.ResponseWriter, m *ldapserver.Message, entries *data.Entries, cfg *Config) {
	entries.RLock()
	defer entries.RUnlock()

	r := m.GetCompareRequest()
	attrName := string(r.Ava().AttributeDesc())
	log.Infof("client [%d]: compare dn='%s' attr='%s'", m.Client.Numero(), r.Entry(), attrName)

	// check compare entry dn
	compareEntry := normalizeEntry(string(r.Entry()))
	if !isCorrectDn(compareEntry) {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultInvalidDNSyntax)
		w.Write(res)

		log.Errorf("client [%d]: compare error: wrong dn '%s'", m.Client.Numero(), r.Entry())
		return
	}

	// compare for entryDN is not supported
	if strings.ToLower(attrName) == "entrydn" {
		diagMessage := "compare over entrydn is not supported"
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Errorf("client [%d]: compare error: %s", m.Client.Numero(), diagMessage)
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

		log.Warnf("client [%d]: compare insufficient access", m.Client.Numero())
		return
	}

	var entry interface{}
	compareEntryAttr, compareEntryName, compareEntrySuffix := getEntryAttrValueSuffix(compareEntry)
	switch {
	case compareEntry == cfg.BaseDN:
		entry = entries.Domain
	case strings.HasPrefix(compareEntry, "ou=") && compareEntrySuffix == cfg.BaseDN:
		for i := range entries.OUs {
			// handle stop signal
			select {
			case <-m.Done:
				log.Infof("client [%d]: leaving handleCompare...", m.Client.Numero())
				return
			default:
			}

			if entries.OUs[i].OU != compareEntryName {
				continue
			}

			entry = entries.OUs[i]
			break
		}
	case compareEntrySuffix == "ou="+cfg.UsersOUName+","+cfg.BaseDN:
		for i := range entries.Users {
			// handle stop signal
			select {
			case <-m.Done:
				log.Infof("client [%d]: leaving handleCompare...", m.Client.Numero())
				return
			default:
			}

			var cmpValue string
			switch compareEntryAttr {
			case "cn":
				cmpValue = entries.Users[i].CN
			case "uid":
				cmpValue = entries.Users[i].UID
			}
			if cmpValue != compareEntryName {
				continue
			}

			entry = entries.Users[i]
			break
		}
	case strings.HasPrefix(compareEntry, "cn=") && compareEntrySuffix == "ou="+cfg.GroupsOUName+","+cfg.BaseDN:
		for i := range entries.Groups {
			// handle stop signal
			select {
			case <-m.Done:
				log.Infof("client [%d]: leaving handleCompare...", m.Client.Numero())
				return
			default:
			}

			if entries.Groups[i].CN != compareEntryName {
				continue
			}

			entry = entries.Groups[i]
			break
		}
	}

	// entry not found
	if entry == nil {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultNoSuchObject)
		w.Write(res)

		log.Errorf("client [%d]: compare error: target entry not found", m.Client.Numero())
		return
	}

	// compare
	ok, err := doCompare(entry, attrName, string(r.Ava().AssertionValue()))
	if err != nil {
		res := ldapserver.NewCompareResponse(err.(LDAPError).ResultCode)
		w.Write(res)

		log.Errorf("client [%d]: compare error: %s", m.Client.Numero(), err)
		return
	}
	if !ok {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareFalse)
		w.Write(res)

		log.Infof("client [%d]: compare result=FALSE", m.Client.Numero())
		return
	}

	// compare TRUE
	res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareTrue)
	w.Write(res)

	log.Infof("client [%d]: compare result=TRUE", m.Client.Numero())
}

// handle modify
func handleModify(w ldapserver.ResponseWriter, m *ldapserver.Message, entries *data.Entries, cfg *Config, b Backend, ticker *time.Ticker) {
	entries.RLock()
	defer entries.RUnlock()

	r := m.GetModifyRequest()
	log.Infof("client [%d]: modify dn='%s'", m.Client.Numero(), r.Object())

	// check modify entry dn
	modifyEntry := normalizeEntry(string(r.Object()))
	if !isCorrectDn(modifyEntry) {
		res := ldapserver.NewModifyResponse(ldapserver.LDAPResultInvalidDNSyntax)
		w.Write(res)

		log.Errorf("client [%d]: modify error: wrong dn '%s'", m.Client.Numero(), r.Object())
		return
	}

	// modify of domain or ou is not supported
	if modifyEntry == cfg.BaseDN || modifyEntry == "ou="+cfg.UsersOUName+","+cfg.BaseDN || modifyEntry == "ou="+cfg.GroupsOUName+","+cfg.BaseDN {
		diagMessage := fmt.Sprintf("modify of '%s' is not supported", modifyEntry)
		res := ldapserver.NewModifyResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Errorf("client [%d]: modify error: %s", m.Client.Numero(), diagMessage)
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

		log.Warnf("client [%d]: modify insufficient access", m.Client.Numero())
		return
	}

	var oldEntry interface{}
	modifyEntryAttr, modifyEntryName, modifyEntrySuffix := getEntryAttrValueSuffix(modifyEntry)
	switch {
	case modifyEntrySuffix == "ou="+cfg.UsersOUName+","+cfg.BaseDN:
		for i := range entries.Users {
			// handle stop signal
			select {
			case <-m.Done:
				log.Infof("client [%d]: leaving handleModify...", m.Client.Numero())
				return
			default:
			}

			var cmpValue string
			switch modifyEntryAttr {
			case "cn":
				cmpValue = entries.Users[i].CN
			case "uid":
				cmpValue = entries.Users[i].UID
			}

			if cmpValue != modifyEntryName {
				continue
			}

			oldEntry = entries.Users[i]
			break
		}
	case strings.HasPrefix(modifyEntry, "cn=") && modifyEntrySuffix == "ou="+cfg.GroupsOUName+","+cfg.BaseDN:
		for i := range entries.Groups {
			// handle stop signal
			select {
			case <-m.Done:
				log.Infof("client [%d]: leaving handleModify...", m.Client.Numero())
				return
			default:
			}

			if entries.Groups[i].CN != modifyEntryName {
				continue
			}

			oldEntry = entries.Groups[i]
			break
		}
	}

	// entry not found
	if oldEntry == nil {
		res := ldapserver.NewModifyResponse(ldapserver.LDAPResultNoSuchObject)
		w.Write(res)

		log.Errorf("client [%d]: modify error: target entry not found", m.Client.Numero())
		return
	}

	// copy entry for modify
	newEntry := oldEntry

	for i := range r.Changes() {
		// handle stop signal
		select {
		case <-m.Done:
			log.Infof("client [%d]: leaving handleModify...", m.Client.Numero())
			return
		default:
		}

		// check operation type
		attrName := string(r.Changes()[i].Modification().Type_())
		opType := r.Changes()[i].Operation().Int()
		log.Infof("client [%d]: modify op=%d attr=%s", m.Client.Numero(), r.Changes()[i].Operation(), attrName)
		if r.Changes()[i].Operation().Int() != ldap.ModifyRequestChangeOperationReplace {
			diagMessage := fmt.Sprintf("wrong operation %d: only 2 (replace) is supported", opType)
			res := ldapserver.NewModifyResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(diagMessage)
			w.Write(res)

			log.Errorf("client [%d]: modify error: %s", m.Client.Numero(), diagMessage)
			return
		}

		// modify
		if err := doModify(&newEntry, attrName, r.Changes()[i].Modification().Vals()); err != nil {
			res := ldapserver.NewModifyResponse(err.(LDAPError).ResultCode)
			w.Write(res)

			log.Errorf("client [%d]: modify error: %s", m.Client.Numero(), err)
			return
		}
	}

	// update backend entry
	if err := b.UpdateData(oldEntry, newEntry); err != nil {
		diagMessage := fmt.Sprintf("error updating backend data: %s", err)
		res := ldapserver.NewModifyResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Errorf("client [%d]: modify error: %s", m.Client.Numero(), diagMessage)
		return
	}

	// get updated entries
	ticker.Reset(time.Millisecond)
	<-ticker.C
	ticker.Reset(cfg.UpdateInterval)

	// modify OK
	res := ldapserver.NewModifyResponse(ldapserver.LDAPResultSuccess)
	w.Write(res)

	log.Infof("client [%d]: modify result=OK", m.Client.Numero())
}
