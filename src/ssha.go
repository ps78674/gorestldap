package main

import (
	"crypto/sha1"
	"encoding/base64"
)

// validate password (string) with ldap ssha hash
func validatePassword(password string, hash string) bool {
	if len(hash) < 7 || string(hash[0:6]) != "{SSHA}" {
		return false
	}

	data, err := base64.StdEncoding.DecodeString(hash[6:])
	if len(data) < 21 || err != nil {
		return false
	}

	newhash := createHash(password, data[20:])
	hashedpw := base64.StdEncoding.EncodeToString(newhash)

	if hashedpw == hash[6:] {
		return true
	}

	return false
}

// standard algorythm for creating ssha-hashed passwords for ldap
func createHash(password string, salt []byte) []byte {
	pass := []byte(password)
	str := append(pass[:], salt[:]...)
	sum := sha1.Sum(str)
	result := append(sum[:], salt[:]...)
	return result
}
