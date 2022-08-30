package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"reflect"

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

func (b *backend) UpdateData(old, new interface{}) error {
	switch entry := new.(type) {
	case data.User:
		users := []data.User{}
		if err := getData(b.config.UsersPath, &users); err != nil {
			return fmt.Errorf("error getting users data: %s", err)
		}

		var found bool
		for i, user := range users {
			if !reflect.DeepEqual(old, user) {
				continue
			}
			users[i] = entry
			found = true
			break
		}

		if !found {
			return errors.New("error updating users data: user not found")
		}

		if err := updateData(b.config.UsersPath, &users); err != nil {
			return fmt.Errorf("error updating users data: %s", err)
		}
	case data.Group:
		groups := []data.Group{}
		if err := getData(b.config.GroupsPath, &groups); err != nil {
			return fmt.Errorf("error getting groups data: %s", err)
		}

		var found bool
		for i, group := range groups {
			if !reflect.DeepEqual(old, group) {
				continue
			}
			groups[i] = entry
			found = true
			break
		}

		if !found {
			return errors.New("error updating groups data: group not found")
		}

		if err := updateData(b.config.GroupsPath, &groups); err != nil {
			return fmt.Errorf("error updating groups data: %s", err)
		}
	}

	return nil
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

func updateData(path string, data interface{}) error {
	b, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return fmt.Errorf("error marshalling data: %s", err)
	}

	if err := ioutil.WriteFile(path, b, 0644); err != nil {
		return fmt.Errorf("error writing file: %s", err)
	}

	return nil
}
