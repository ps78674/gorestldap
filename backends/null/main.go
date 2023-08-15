package main

import (
	"errors"

	"github.com/ps78674/gorestldap/internal/data"
)

type config struct{}

type backend struct {
	config *config
}

var Backend backend

func main() {}

func (b *backend) ReadConfig(in []byte) error {
	return nil
}

func (b *backend) GetData() ([]data.User, []data.Group, error) {
	return []data.User{}, []data.Group{}, nil
}

func (b *backend) UpdateData(old, new interface{}) error {
	return errors.New("updating data is not supported by this backend")
}
