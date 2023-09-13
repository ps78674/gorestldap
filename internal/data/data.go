package data

import "sync"

type DSE struct {
	ObjectClass          []string `json:"objectClass"`
	VendorVersion        string   `json:"vendorVersion"`
	SupportedLDAPVersion uint     `json:"supportedLDAPVersion"`
	SupportedControl     []string `json:"supportedControl"`
	NamingContexts       []string `json:"namingContexts"`
}

type Domain struct {
	EntryUUID       string   `json:"entryUUID,omitempty" ldap:"operational"`
	HasSubordinates string   `json:"hasSubordinates,omitempty" ldap:"operational"`
	ObjectClass     []string `json:"objectClass,omitempty"`
	DC              string   `ldap:"skip"`
}

type OU struct {
	EntryUUID       string   `json:"entryUUID,omitempty" ldap:"operational"`
	HasSubordinates string   `json:"hasSubordinates,omitempty" ldap:"operational"`
	ObjectClass     []string `json:"objectClass,omitempty"`
	OU              string   `ldap:"skip"`
}

type User struct {
	LDAPAdmin       bool     `json:"ldapAdmin,omitempty" ldap:"skip"`
	EntryUUID       string   `json:"entryUUID,omitempty" ldap:"operational"`
	HasSubordinates string   `json:"hasSubordinates,omitempty" ldap:"operational"`
	ObjectClass     []string `json:"objectClass,omitempty"`
	CN              string   `json:"cn,omitempty"`
	UIDNumber       uint     `json:"uidNumber,omitempty"`
	UserPassword    string   `json:"userPassword,omitempty" ldap:"case_sensitive_value"`
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
	EntryUUID       string   `json:"entryUUID,omitempty" ldap:"operational"`
	HasSubordinates string   `json:"hasSubordinates,omitempty" ldap:"operational"`
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
