package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/ps78674/gorestldap/src/internal/data"
	"gopkg.in/yaml.v3"
)

type config struct {
	UsersPath  string `yaml:"users_path"`
	GroupsPath string `yaml:"groups_path"`
}

type backend struct {
	config *config
}

var Backend backend

func main() {}

func (b *backend) ReadConfig(in []byte) error {
	return yaml.Unmarshal(in, &b.config)
}

func (b *backend) GetData() ([]data.User, []data.Group, error) {
	users := []data.User{}
	if err := getData(b.config.UsersPath, &users); err != nil {
		return nil, nil, fmt.Errorf("error getting users data: %s", err)
	}

	groups := []data.Group{}
	if err := getData(b.config.GroupsPath, &groups); err != nil {
		return nil, nil, fmt.Errorf("error getting groups data: %s", err)
	}

	return users, groups, nil
}

func getData(path string, data interface{}) error {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("error opening file: %s", err)
	}

	if err := json.Unmarshal(contents, &data); err != nil {
		return fmt.Errorf("error unmarshalling file data: %s", err)
	}

	return nil
}
