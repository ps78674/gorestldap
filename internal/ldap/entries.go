package ldap

import "github.com/ps78674/gorestldap/internal/data"

// GetEntries returns configured entries
func GetEntries(baseDN, usersOUName, groupsOUName string) *data.Entries {
	_, dc, _ := getEntryAttrValueSuffix(baseDN)
	var domain = data.Domain{
		EntryUUID:       newEntryUUID(dc),
		HasSubordinates: "TRUE",
		ObjectClass: []string{
			"top",
			"domain",
		},
		DC: dc,
	}

	var ous = []data.OU{
		{
			EntryUUID:       newEntryUUID(usersOUName),
			HasSubordinates: "TRUE",
			ObjectClass: []string{
				"top",
				"organizationalUnit",
			},
			OU: usersOUName,
		},
		{
			EntryUUID:       newEntryUUID(groupsOUName),
			HasSubordinates: "TRUE",
			ObjectClass: []string{
				"top",
				"organizationalUnit",
			},
			OU: groupsOUName,
		},
	}

	return &data.Entries{
		Domain: domain,
		OUs:    ous,
	}
}
