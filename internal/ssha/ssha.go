package ssha

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
)

// ValidatePassword validates password over SSHA hash string
func ValidatePassword(password, hash string) (bool, error) {
	if len(hash) < 7 {
		return false, errors.New("wrong hash length")
	}
	if string(hash[0:6]) != "{SSHA}" {
		return false, errors.New("hash must start with {SSHA} scheme")
	}

	data, err := base64.StdEncoding.DecodeString(hash[6:])
	if err != nil {
		return false, err
	}
	if len(data) < 21 {
		return false, errors.New("no salt in hash")
	}

	newHashBytes := createSSHAHash(password, data[20:])
	if base64.StdEncoding.EncodeToString(newHashBytes) == hash[6:] {
		return true, nil
	}

	return false, nil
}

// createSSHAHash creates salted SSHA hash of a password
func createSSHAHash(password string, salt []byte) []byte {
	pass := []byte(password)
	str := append(pass[:], salt[:]...)
	sum := sha1.Sum(str)
	result := append(sum[:], salt[:]...)
	return result
}
