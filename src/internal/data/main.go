package data

import "sync"

type Domain struct {
	ObjectClass     []string `json:"objectClass"`
	HasSubordinates string   `json:"hasSubordinates" hidden:""`
}

type User struct {
	LDAPAdmin       bool     `json:"ldapAdmin" skip:""`
	EntryUUID       string   `json:"entryUUID" hidden:""`
	HasSubordinates string   `json:"hasSubordinates" hidden:""`
	ObjectClass     []string `json:"objectClass" lower:""`
	CN              string   `json:"cn"`
	UIDNumber       uint     `json:"uidNumber"`
	UserPassword    string   `json:"userPassword"`
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
	EntryUUID       string   `json:"entryUUID" hidden:""`
	HasSubordinates string   `json:"hasSubordinates" hidden:""`
	ObjectClass     []string `json:"objectClass" lower:""`
	CN              string   `json:"cn"`
	GIDNumber       uint     `json:"gidNumber"`
	Description     string   `json:"description"`
	OU              []string `json:"ou"`
	MemberUID       []string `json:"memberUid"`
}

type Entries struct {
	Domain Domain
	Users  []User
	Groups []Group
	sync.RWMutex
}
