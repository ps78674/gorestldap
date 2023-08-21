package backend

import (
	"errors"
	"fmt"
	"plugin"

	"github.com/ps78674/gorestldap/internal/data"
	"gopkg.in/yaml.v3"
)

type Backend interface {
	ReadConfig([]byte) error
	GetData() ([]data.User, []data.Group, error)
	UpdateData(interface{}, interface{}) error
}

// Open opens a backend.
func Open(path string, cfg interface{}) (Backend, error) {
	// open plugin
	p, err := plugin.Open(path)
	if err != nil {
		return nil, fmt.Errorf("error opening plugin: %s", err)
	}

	// lookup exported var
	symBackend, err := p.Lookup("Backend")
	if err != nil {
		return nil, fmt.Errorf("error loading backend: %s", err)
	}

	// assert type
	backend, ok := symBackend.(Backend)
	if !ok {
		return nil, errors.New("error loading backend: unexpected type")
	}

	// marshall backend config
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("error marshalling backend config: %s", err)
	}

	// set plugin config
	if err := backend.ReadConfig(b); err != nil {
		return nil, fmt.Errorf("error unmarshalling backend config: %s", err)
	}

	return backend, nil
}
