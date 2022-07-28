package main

import (
	"fmt"
	"reflect"
	"strings"

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
func handleBind(w ldapserver.ResponseWriter, m *ldapserver.Message, entries *data.Entries) {
	entries.RLock()
	defer entries.RUnlock()

	r := m.GetBindRequest()
	log.Infof("client [%d]: bind dn=\"%s\"", m.Client.Numero(), r.Name())

	// only simple authentiacion supported
	if r.AuthenticationChoice() != "simple" {
		diagMessage := fmt.Sprintf("authentication method %s is not supported", r.AuthenticationChoice())
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultAuthMethodNotSupported)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Errorf("client [%d]: bind error: %s", m.Client.Numero(), diagMessage)
		return
	}

	bindEntry := normalizeEntry(string(r.Name()))
	bindEntryAttr, bindEntryName, _ := getEntryAttrNameSuffix(bindEntry)
	entrySuffix := "ou=" + cfg.UsersOUName + "," + cfg.BaseDN

	// entry must have proper suffix & attr must be cn || uid
	if !strings.HasSuffix(bindEntry, entrySuffix) || (bindEntryAttr != "cn" && bindEntryAttr != "uid") {
		diagMessage := fmt.Sprintf("wrong dn \"%s\"", r.Name())
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidDNSyntax)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Errorf("client [%d]: bind error: %s", m.Client.Numero(), diagMessage)
		return
	}

	// get user
	userData := data.User{}
	for _, u := range entries.Users {
		var cmpValue string

		v := getAttrValues(u, bindEntryAttr)
		if v != nil {
			cmpValue = v.(string)
		}

		if strings.EqualFold(cmpValue, bindEntryName) {
			userData = u
			break
		}
	}

	// got empty struct -> user not found
	if reflect.DeepEqual(userData, data.User{}) {
		diagMessage := fmt.Sprintf("dn \"%s\" not found", r.Name())
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Errorf("client [%d]: bind error: %s", m.Client.Numero(), diagMessage)
		return
	}

	// validate password
	ok, err := validatePassword(r.AuthenticationSimple().String(), userData.UserPassword)
	if !ok {
		diagMessage := fmt.Sprintf("wrong password for dn \"%s\"", r.Name())

		if err != nil {
			diagMessage = fmt.Sprintf("%s: %s", diagMessage, err)
		}

		res := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Errorf("client [%d]: bind error: %s", m.Client.Numero(), diagMessage)
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
func handleSearchDSE(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	r := m.GetSearchRequest()

	// attrs := []string{}
	// for _, attr := range r.Attributes() {
	// 	attrs = append(attrs, string(attr))
	// }

	log.Infof("client [%d]: search base=\"%s\" scope=%d filter=\"%s\"", m.Client.Numero(), r.BaseObject(), r.Scope(), r.FilterString())

	// TODO: handle search attributes??
	// log.Infof("client [%d]: search attr=%s", m.Client.Numero(), strings.Join(attrs, " "))

	e := ldapserver.NewSearchResultEntry("")
	e.AddAttribute("vendorVersion", ldap.AttributeValue(versionString))
	e.AddAttribute("objectClass", "top", "LDAProotDSE")
	e.AddAttribute("supportedLDAPVersion", "3")
	e.AddAttribute("supportedControl", ldap.AttributeValue(ldap.PagedResultsControlOID))
	e.AddAttribute("namingContexts", ldap.AttributeValue(cfg.BaseDN))
	// e.AddAttribute("supportedSASLMechanisms", "")

	w.Write(e)
	w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))

	log.Infof("client [%d]: search result=OK nentries=1", m.Client.Numero())
}

// handle search
func handleSearch(w ldapserver.ResponseWriter, m *ldapserver.Message, entries *data.Entries) {
	entries.RLock()
	defer entries.RUnlock()

	r := m.GetSearchRequest()

	attrs := []string{}
	for _, attr := range r.Attributes() {
		attrs = append(attrs, string(attr))
	}

	log.Infof("client [%d]: search base=\"%s\" scope=%d filter=\"%s\"", m.Client.Numero(), r.BaseObject(), r.Scope(), r.FilterString())
	log.Infof("client [%d]: search attr=%s", m.Client.Numero(), strings.Join(attrs, " "))

	// check requested controls
	var controls []string
	var simplePagedResultsControl ldap.SimplePagedResultsControl
	var gotUCControl bool
	if m.Controls() != nil {
		for _, c := range *m.Controls() {
			switch c.ControlType() {
			// 1.2.840.113556.1.4.319 (pagedSearch)
			case ldap.PagedResultsControlOID:
				controls = append(controls, c.ControlType().String())
				c, err := ldap.ReadPagedResultsControl(c.ControlValue())
				if err != nil {
					log.Errorf("client [%d]: error decoding pagedResultsControl: %s", m.Client.Numero(), err)
				}
				simplePagedResultsControl = c
			default:
				if c.Criticality().Bool() {
					controls = append(controls, c.ControlType().String()+"(U,C)")
					gotUCControl = true
				} else {
					controls = append(controls, c.ControlType().String()+"(U)")
				}
			}
		}
	}

	log.Infof("client [%d]: search ctrl=%s", m.Client.Numero(), strings.Join(controls, " "))

	// check for unsupported critical controls
	if gotUCControl && cfg.RespectCritical {
		diagMessage := "got unsupported critical controls, aborting"
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnavailableCriticalExtension)
		res.SetDiagnosticMessage(diagMessage)
		w.Write(res)

		log.Errorf("client [%d]: search error: %s", m.Client.Numero(), diagMessage)
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
				e := createSearchResultEntry(entries.Domain, r.Attributes(), cfg.BaseDN)
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

		e := createSearchResultEntry(entries.OUs[i], r.Attributes(), entryName)
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

		e := createSearchResultEntry(entries.Users[i], r.Attributes(), entryName)
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

		e := createSearchResultEntry(entries.Groups[i], r.Attributes(), entryName)
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
			diagMessage := fmt.Sprintf("error encoding pagedResultsControl: %s", err)
			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultOther)
			res.SetDiagnosticMessage(diagMessage)
			w.Write(res)

			log.Errorf("client [%d]: search error: %s", m.Client.Numero(), diagMessage)
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
func handleCompare(w ldapserver.ResponseWriter, m *ldapserver.Message, entries *data.Entries) {
	entries.RLock()
	defer entries.RUnlock()

	r := m.GetCompareRequest()
	log.Infof("client [%d]: compare dn=\"%s\" attr=\"%s\"", m.Client.Numero(), r.Entry(), r.Ava().AttributeDesc())

	// check compare entry dn
	compareEntry := normalizeEntry(string(r.Entry()))
	if !isCorrectDn(compareEntry) {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultInvalidDNSyntax)
		w.Write(res)

		log.Errorf("client [%d]: compare error: wrong dn '%s'", m.Client.Numero(), r.Entry())
		return
	}

	// compare for entryDN is not supported
	if strings.ToLower(string(r.Ava().AttributeDesc())) == "entrydn" {
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

	var attrExist, entryFound, compareOK bool
	compareEntryAttr, compareEntryName, compareEntrySuffix := getEntryAttrNameSuffix(compareEntry)
	switch {
	case compareEntry == cfg.BaseDN:
		entryFound = true
		attrExist, compareOK = doCompare(entries.Domain, string(r.Ava().AttributeDesc()), string(r.Ava().AssertionValue()))
	case strings.HasPrefix(compareEntry, "ou=") && compareEntrySuffix == cfg.BaseDN:
		for _, ou := range entries.OUs {
			// handle stop signal
			select {
			case <-m.Done:
				log.Infof("client [%d]: leaving handleCompare...", m.Client.Numero())
				return
			default:
			}

			if ou.OU != compareEntryName {
				continue
			}

			entryFound = true
			attrExist, compareOK = doCompare(ou, string(r.Ava().AttributeDesc()), string(r.Ava().AssertionValue()))
			break
		}
	case compareEntrySuffix == "ou="+cfg.UsersOUName+","+cfg.BaseDN:
		for _, user := range entries.Users {
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
				cmpValue = user.CN
			case "uid":
				cmpValue = user.UID
			}
			if cmpValue != compareEntryName {
				continue
			}

			entryFound = true
			attrExist, compareOK = doCompare(user, string(r.Ava().AttributeDesc()), string(r.Ava().AssertionValue()))
			break
		}
	case strings.HasPrefix(compareEntry, "cn=") && compareEntrySuffix == "ou="+cfg.GroupsOUName+","+cfg.BaseDN:
		for _, group := range entries.Groups {
			// handle stop signal
			select {
			case <-m.Done:
				log.Infof("client [%d]: leaving handleCompare...", m.Client.Numero())
				return
			default:
			}

			if group.CN != compareEntryName {
				continue
			}

			entryFound = true
			attrExist, compareOK = doCompare(group, string(r.Ava().AttributeDesc()), string(r.Ava().AssertionValue()))
			break
		}
	}

	switch {
	case !entryFound:
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultNoSuchObject)
		w.Write(res)
		log.Infof("client [%d]: compare entry not found", m.Client.Numero())
	case !attrExist:
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultUndefinedAttributeType)
		w.Write(res)
		log.Infof("client [%d]: compare entry does not have requested attribute", m.Client.Numero())
	case !compareOK:
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareFalse)
		w.Write(res)
		log.Infof("client [%d]: compare result=FALSE", m.Client.Numero())
	case compareOK:
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareTrue)
		w.Write(res)
		log.Infof("client [%d]: compare result=TRUE", m.Client.Numero())
	}
}

// handle modify (only userPassword for now)
func handleModify(w ldapserver.ResponseWriter, m *ldapserver.Message, entries *data.Entries) {
	entries.RLock()
	defer entries.RUnlock()

	r := m.GetModifyRequest()
	log.Infof("client [%d]: modify dn=\"%s\"", m.Client.Numero(), r.Object())

	// entry must be equal to baseDN or look like cn=<COMMON_NAME>,dc=base,dc=dn
	// TODO: change diag message
	modifyEntry := normalizeEntry(string(r.Object()))
	modifyEntryAttr, modifyEntryName, _ := getEntryAttrNameSuffix(modifyEntry)
	if !strings.HasSuffix(modifyEntry, cfg.BaseDN) || (modifyEntryAttr != "cn" && modifyEntryAttr != "uid") {
		diagMessage := fmt.Sprintf("wrong dn \"%s\"", r.Object())
		res := ldapserver.NewModifyResponse(ldapserver.LDAPResultInvalidDNSyntax)
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

	// ldap admin can do modify on all entries
	if !acl.modify && modifyEntry != acl.bindEntry {
		res := ldapserver.NewModifyResponse(ldapserver.LDAPResultInsufficientAccessRights)
		w.Write(res)

		log.Warnf("client [%d]: modify insufficient access", m.Client.Numero())
		return
	}

	for _, c := range r.Changes() {
		// handle stop signal
		select {
		case <-m.Done:
			log.Infof("client [%d]: leaving handleModify...", m.Client.Numero())
			return
		default:
		}

		// check operation type
		log.Infof("client [%d]: modify op=%d", m.Client.Numero(), c.Operation())
		if c.Operation().Int() != ldap.ModifyRequestChangeOperationReplace {
			diagMessage := fmt.Sprintf("wrong operation %d: only replace (2) is supported", c.Operation().Int())
			res := ldapserver.NewModifyResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(diagMessage)
			w.Write(res)

			log.Errorf("client [%d]: modify error: %s", m.Client.Numero(), diagMessage)
			return
		}

		// check attribute name
		log.Infof("client [%d]: modify attr=%s", m.Client.Numero(), c.Modification().Type_())
		if c.Modification().Type_() != "userPassword" {
			diagMessage := fmt.Sprintf("wrong attribute %s, only userPassword is supported", c.Modification().Type_())
			res := ldapserver.NewModifyResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(diagMessage)
			w.Write(res)

			log.Errorf("client [%d]: modify error: %s", m.Client.Numero(), diagMessage)
			return
		}

		if len(c.Modification().Vals()) > 1 {
			diagMessage := "more than 1 value for userPassword is not supported"
			res := ldapserver.NewModifyResponse(ldapserver.LDAPResultUnwillingToPerform)
			res.SetDiagnosticMessage(diagMessage)
			w.Write(res)

			log.Errorf("client [%d]: modify error: %s", m.Client.Numero(), diagMessage)
			return
		}

		if err := doModify(modifyEntryName, string(c.Modification().Vals()[0])); err != nil {
			res := ldapserver.NewModifyResponse(ldapserver.LDAPResultOther)
			res.SetDiagnosticMessage(err.Error())
			w.Write(res)

			log.Errorf("client [%d]: modify error: %s", m.Client.Numero(), err)
			return
		}
	}

	res := ldapserver.NewModifyResponse(ldapserver.LDAPResultSuccess)
	w.Write(res)

	log.Infof("client [%d]: modify result=OK", m.Client.Numero())
}
