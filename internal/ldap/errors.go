package ldap

import (
	"errors"

	ldap "github.com/ps78674/goldap/message"
)

type LDAPError struct {
	ResultCode int
	error
}

var (
	errLDAPNoAttr error = LDAPError{
		ldap.ResultCodeUndefinedAttributeType,
		errors.New("target entry does not have requested attribute"),
	}

	errLDAPMultiValue error = LDAPError{
		ldap.ResultCodeInvalidAttributeSyntax,
		errors.New("attempt to set multiple values on single value attribute"),
	}
)
