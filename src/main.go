package main

import (
	"fmt"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"plugin"
	"strings"
	"syscall"
	"time"

	"github.com/ps78674/docopt.go"
	"github.com/ps78674/gorestldap/src/internal/data"
	ldapserver "github.com/ps78674/ldapserver"
	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
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

type Backend interface {
	ReadConfig([]byte) error
	GetData() ([]data.User, []data.Group, error)
	UpdateData(interface{}, interface{}) error
}

const (
	defaultUsersOUName  = "users"
	defaultGroupsOUName = "groups"
)

var (
	versionString = "devel"
	programName   = filepath.Base(os.Args[0])
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
`, programName)

func (c *Config) init() error {
	// parse cli options
	opts, err := docopt.ParseArgs(usage, nil, versionString)
	if err != nil {
		return fmt.Errorf("error parsing options: %s\n", err)
	}

	// bind args to config struct
	if e := opts.Bind(&c); e != nil {
		return fmt.Errorf("error binding option values: %s\n", e)
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

	if len(cfg.UsersOUName) == 0 {
		cfg.UsersOUName = defaultUsersOUName
	}

	if len(cfg.GroupsOUName) == 0 {
		cfg.GroupsOUName = defaultGroupsOUName
	}

	// normalize baseDN
	c.BaseDN = normalizeEntry(c.BaseDN)

	c.UsersOUName = strings.ToLower(c.UsersOUName)
	c.GroupsOUName = strings.ToLower(c.GroupsOUName)

	return nil
}

var cfg Config

func main() {
	// init config
	// var cfg Config
	if err := cfg.init(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// set log output
	if len(cfg.LogPath) > 0 {
		f, err := os.OpenFile(cfg.LogPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			fmt.Printf("error opening logfile: %s\n", err)
			os.Exit(1)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	// setup debug logging
	if cfg.Debug {
		log.SetLevel(log.DebugLevel)
	}

	// setup log format
	var logFormatter log.TextFormatter
	logFormatter.FullTimestamp = true
	if !cfg.LogTimestamp {
		logFormatter.DisableTimestamp = true
	}
	log.SetFormatter(&logFormatter)

	// setup caller logging
	log.SetReportCaller(cfg.LogCaller)

	// open plugin
	backendPath := path.Join(cfg.BackendDir, cfg.BackendName+".so")

	log.Debugf("loading backend %s", backendPath)

	p, err := plugin.Open(backendPath)
	if err != nil {
		log.Fatal(err)
	}

	// lookup exported var
	symBackend, err := p.Lookup("Backend")
	if err != nil {
		log.Fatal(err)
	}

	// assert type
	backend, ok := symBackend.(Backend)
	if !ok {
		log.Fatal("error loading backend: unexpected type")
	}

	// marshall backend config
	b, err := yaml.Marshal(cfg.Backends[cfg.BackendName])
	if err != nil {
		log.Fatalf("error marshalling backend config: %s", err)
	}

	// set plugin config
	if err := backend.ReadConfig(b); err != nil {
		log.Fatalf("error unmarshalling backend config: %s", err)
	}

	// get initial data
	users, groups, err := backend.GetData()
	if err != nil {
		log.Fatalf("error getting data: %s", err)
	}

	// setup entries
	_, dc, _ := getEntryAttrNameSuffix(cfg.BaseDN)
	var domain = data.Domain{
		ObjectClass: []string{
			"top",
			"domain",
		},
		HasSubordinates: "TRUE",
		DC:              dc,
	}

	var ous = []data.OU{
		data.OU{
			ObjectClass: []string{
				"top",
				"organizationalUnit",
			},
			HasSubordinates: "TRUE",
			OU:              cfg.UsersOUName,
		},
		data.OU{
			ObjectClass: []string{
				"top",
				"organizationalUnit",
			},
			HasSubordinates: "TRUE",
			OU:              cfg.GroupsOUName,
		},
	}

	entries := data.Entries{
		Domain: domain,
		OUs:    ous,
		Users:  users,
		Groups: groups,
	}

	// create new LDAP Server
	ldapServer := ldapserver.NewServer()

	// create ticker
	ticker := time.NewTicker(cfg.UpdateInterval)
	defer ticker.Stop()

	// create route bindings
	routes := ldapserver.NewRouteMux()
	routes.Bind(func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		handleBind(w, m, &entries)
	})
	routes.Search(handleSearchDSE).BaseDn("").Scope(ldapserver.SearchRequestScopeBaseObject).Filter("(objectclass=*)")
	routes.Search(func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		handleSearch(w, m, &entries)
	})
	routes.Compare(func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		handleCompare(w, m, &entries)
	})
	routes.Modify(func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
		handleModify(w, m, &entries, backend, ticker)
	})

	// attach routes to server
	ldapServer.Handle(routes)

	// listen and serve
	chErr := make(chan error)
	if !cfg.UseTLS {
		log.Infof("starting ldap server on '%s'", cfg.ListenAddr)
		go ldapServer.ListenAndServe(cfg.ListenAddr, chErr)
	} else {
		log.Infof("starting ldaps server on '%s'", cfg.ListenAddr)
		go ldapServer.ListenAndServeTLS(cfg.ListenAddr, cfg.ServerCert, cfg.ServerKey, chErr)
	}

	if err := <-chErr; err != nil {
		log.Fatalf("error starting server: %s", err)
	}

	// http callback server
	var httpServer fasthttp.Server
	if len(cfg.CallbackListenAddr) > 0 {
		log.Infof("starting http server on '%s'", cfg.CallbackListenAddr)

		httpServer.Handler = func(ctx *fasthttp.RequestCtx) {
			handleCallback(ctx, ticker)
		}

		go func() {
			if err := httpServer.ListenAndServe(cfg.CallbackListenAddr); err != nil {
				log.Fatalf("http server error: %s", err)
			}
		}()
	}

	// update data every cfg.UpdateInterval
	go func() {
		for range ticker.C {
			func() {
				log.Info("updating entries data")

				entries.Lock()
				defer entries.Unlock()

				log.Debug("getting backend data")
				users, groups, err := backend.GetData()
				if err != nil {
					log.Errorf("error getting data: %s", err)
					return
				}

				entries.Users = users
				entries.Groups = groups

				log.Debug("entries updated")
			}()
		}
	}()

	// reset ticker / update data on SIGUSR1
	go func() {
		sigusr1 := make(chan os.Signal, 1)
		for {
			signal.Notify(sigusr1, syscall.SIGUSR1)
			<-sigusr1
			ticker.Reset(time.Millisecond)
			<-ticker.C
			ticker.Reset(cfg.UpdateInterval)
		}
	}()

	// graceful stop on CTRL+C / SIGINT / SIGTERM
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch

	httpServer.Shutdown()
	ldapServer.Stop()

	signal.Stop(ch)
	close(ch)
}
