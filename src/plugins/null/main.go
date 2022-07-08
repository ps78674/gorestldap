package main

import (
	"github.com/ps78674/gorestldap/src/internal/data"
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
