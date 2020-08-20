package main

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
)

// validate password over SSHA hash
func validatePassword(password string, hash string) (bool, error) {
	if len(hash) < 7 {
		return false, fmt.Errorf("wrong hash length")
	}
	if string(hash[0:6]) != "{SSHA}" {
		return false, fmt.Errorf("hash must start with {SSHA} scheme")
	}

	data, err := base64.StdEncoding.DecodeString(hash[6:])
	if err != nil {
		return false, err
	}
	if len(data) < 21 {
		return false, fmt.Errorf("no salt in hash")
	}

	newhash := createHash(password, data[20:])
	hashedpw := base64.StdEncoding.EncodeToString(newhash)

	if hashedpw == hash[6:] {
		return true, nil
	}

	return false, nil
}

// create SSHA hashed password
func createHash(password string, salt []byte) []byte {
	pass := []byte(password)
	str := append(pass[:], salt[:]...)
	sum := sha1.Sum(str)
	result := append(sum[:], salt[:]...)
	return result
}
