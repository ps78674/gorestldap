package data

import "sync"

type Domain struct {
	ObjectClass     []string `json:"objectClass"`
	HasSubordinates string   `json:"hasSubordinates" ldap_operational:""`
}

type OU struct {
	ObjectClass     []string `json:"objectClass"`
	HasSubordinates string   `json:"hasSubordinates" ldap_operational:""`
	Name            string   `ldap_skip:""`
}

type User struct {
	LDAPAdmin       bool     `json:"ldapAdmin" ldap_skip:""`
	EntryUUID       string   `json:"entryUUID" ldap_operational:""`
	HasSubordinates string   `json:"hasSubordinates" ldap_operational:""`
	ObjectClass     []string `json:"objectClass"`
	CN              string   `json:"cn"`
	UIDNumber       uint     `json:"uidNumber"`
	UserPassword    string   `json:"userPassword" ldap_compare_cs:""`
	GIDNumber       uint     `json:"gidNumber"`
	UID             string   `json:"uid"`
	DisplayName     string   `json:"displayName"`
	GivenName       string   `json:"givenName"`
	SN              string   `json:"sn"`
	Mail            string   `json:"mail"`
	HomeDirectory   string   `json:"homeDirectory"`
	LoginShell      string   `json:"loginShell"`
	MemberOf        []string `json:"memberOf"`
}

type Group struct {
	EntryUUID       string   `json:"entryUUID" ldap_operational:""`
	HasSubordinates string   `json:"hasSubordinates" ldap_operational:""`
	ObjectClass     []string `json:"objectClass"`
	CN              string   `json:"cn"`
	GIDNumber       uint     `json:"gidNumber"`
	Description     string   `json:"description"`
	MemberUID       []string `json:"memberUid"`
}

type Entries struct {
	Domain Domain
	OUs    []OU
	Users  []User
	Groups []Group
	sync.RWMutex
}
