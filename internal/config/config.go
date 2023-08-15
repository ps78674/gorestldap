package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ps78674/docopt.go"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ConfigPath         string                 `docopt:"--config"`
	BackendName        string                 `docopt:"--backend"`
	BaseDN             string                 `docopt:"--basedn"`
	ListenAddr         string                 `docopt:"--listen"`
	UpdateInterval     time.Duration          `docopt:"--interval"`
	LogPath            string                 `docopt:"--log"`
	Debug              bool                   `docopt:"--debug"`
	LogTimestamp       bool                   `yaml:"log_timestamp"`
	LogCaller          bool                   `yaml:"log_caller"`
	BackendDir         string                 `yaml:"backend_dir"`
	Backends           map[string]interface{} `yaml:"backends"`
	RespectCritical    bool                   `yaml:"respect_control_criticality"`
	UsersOUName        string                 `yaml:"users_ou_name"`
	GroupsOUName       string                 `yaml:"groups_ou_name"`
	UseTLS             bool                   `yaml:"use_tls"`
	ServerCert         string                 `yaml:"server_cert"`
	ServerKey          string                 `yaml:"server_key"`
	CallbackListenAddr string                 `yaml:"callback_listen_addr"`
	CallbackAuthToken  string                 `yaml:"callback_auth_token"`
}

const (
	defaultUsersOUName  = "users"
	defaultGroupsOUName = "groups"
)

var (
	VersionString = "devel"
	ProgramName   = filepath.Base(os.Args[0])
)

var usage = fmt.Sprintf(`%[1]s: LDAP server with REST API & file backends

Usage:
  %[1]s [-b <BACKEND> -c <CONFIGPATH> -B <BASEDN> -L <LISTENADDR> -I <INTERVAL> -l <LOGPATH> -d]

Options:
  -c, --config <CONFIGPATH>  config file path [default: config.yaml, env: CONFIG_PATH]
  -b, --backend <BACKEND>    backend to use [default: rest, env: BACKEND]
  -B, --basedn <BASEDN>      server base dn [default: dc=example,dc=com, env: BASE_DN]
  -L, --listen <LISTENADDR>  listen addr for LDAP [default: 0.0.0.0:389, env: LDAP_LISTEN_ADDR]
  -I, --interval <INTERVAL>  data update interval [default: 300s, env: UPDATE_INTERVAL] 
  -l, --log <LOGPATH>        log file path
  -d, --debug                turn on debug logging [default: false] 

  -h, --help                 show this screen
  --version                  show version
`, ProgramName)

func (c *Config) Init() error {
	// parse cli options
	opts, err := docopt.ParseArgs(usage, nil, VersionString)
	if err != nil {
		return fmt.Errorf("error parsing options: %s", err)
	}

	// bind args to config struct
	if e := opts.Bind(&c); e != nil {
		return fmt.Errorf("error binding option values: %s", e)
	}

	// read config from file
	if len(c.ConfigPath) > 0 {
		f, err := os.Open(c.ConfigPath)
		if err != nil {
			return fmt.Errorf("error opening config file: %s", err)
		}
		defer f.Close()

		decoder := yaml.NewDecoder(f)
		if err = decoder.Decode(&c); err != nil {
			return fmt.Errorf("error parsing config file: %s", err)
		}
	}

	if len(c.UsersOUName) == 0 {
		c.UsersOUName = defaultUsersOUName
	}

	if len(c.GroupsOUName) == 0 {
		c.GroupsOUName = defaultGroupsOUName
	}

	// normalize baseDN
	// c.BaseDN = ldap.NormalizeEntry(c.BaseDN)

	c.UsersOUName = strings.ToLower(c.UsersOUName)
	c.GroupsOUName = strings.ToLower(c.GroupsOUName)

	return nil
}
