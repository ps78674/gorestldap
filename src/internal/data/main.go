package data

import "sync"

type Domain struct {
	ObjectClass     []string `json:"objectClass,omitempty"`
	HasSubordinates string   `json:"hasSubordinates,omitempty" ldap_operational:""`
	DC              string   `ldap_skip:""`
}

type OU struct {
	ObjectClass     []string `json:"objectClass,omitempty"`
	HasSubordinates string   `json:"hasSubordinates,omitempty" ldap_operational:""`
	OU              string   `ldap_skip:""`
}

type User struct {
	LDAPAdmin       bool     `json:"ldapAdmin,omitempty" ldap_skip:""`
	EntryUUID       string   `json:"entryUUID,omitempty" ldap_operational:""`
	HasSubordinates string   `json:"hasSubordinates,omitempty" ldap_operational:""`
	ObjectClass     []string `json:"objectClass,omitempty"`
	CN              string   `json:"cn,omitempty"`
	UIDNumber       uint     `json:"uidNumber,omitempty"`
	UserPassword    string   `json:"userPassword,omitempty" ldap_case_sensitive_value:""`
	GIDNumber       uint     `json:"gidNumber,omitempty"`
	UID             string   `json:"uid,omitempty"`
	DisplayName     string   `json:"displayName,omitempty"`
	GivenName       string   `json:"givenName,omitempty"`
	SN              string   `json:"sn,omitempty"`
	Mail            string   `json:"mail,omitempty"`
	HomeDirectory   string   `json:"homeDirectory,omitempty"`
	LoginShell      string   `json:"loginShell,omitempty"`
	MemberOf        []string `json:"memberOf,omitempty"`
}

type Group struct {
	EntryUUID       string   `json:"entryUUID,omitempty" ldap_operational:""`
	HasSubordinates string   `json:"hasSubordinates,omitempty" ldap_operational:""`
	ObjectClass     []string `json:"objectClass,omitempty"`
	CN              string   `json:"cn,omitempty"`
	GIDNumber       uint     `json:"gidNumber,omitempty"`
	Description     string   `json:"description,omitempty"`
	MemberUID       []string `json:"memberUid,omitempty"`
}

type Entries struct {
	Domain Domain
	OUs    []OU
	Users  []User
	Groups []Group
	sync.RWMutex
}
