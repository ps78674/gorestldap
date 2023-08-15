package ldap

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
