package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ps78674/docopt.go"
	ldapserver "github.com/ps78674/ldapserver"
	"github.com/valyala/fasthttp"
)

const (
	mainClientID   int = -1
	signalClientID int = -2
)

var cmdOpts struct {
	URL             string `docopt:"--url"`
	ReqTimeout      int    `docopt:"--reqtimeout"`
	File            string `docopt:"--file"`
	BaseDN          string `docopt:"--basedn"`
	BindAddress     string `docopt:"--addr"`
	BindPort        int    `docopt:"--port"`
	HTTPPort        int    `docopt:"--httpport"`
	NoCallback      bool   `docopt:"--nocallback"`
	UseTLS          bool   `docopt:"--tls"`
	ServerCert      string `docopt:"--cert"`
	ServerKey       string `docopt:"--key"`
	LogFile         string `docopt:"--log"`
	AuthToken       string `docopt:"--token"`
	UpdateTimeout   int    `docopt:"--timeout"`
	RespectCritical bool   `docopt:"--criticality"`
}

var (
	versionString = "devel"
	programName   = filepath.Base(os.Args[0])
)

var usage = fmt.Sprintf(`%[1]s: simple LDAP emulator with HTTP REST backend, support bind / search / compare operations

Usage:
  %[1]s [-u <URL> -b <BASEDN> -a <ADDRESS> -p <PORT> (-P <PORT>|--nocallback) -t <TOKEN> -T <SECONDS> -C -l <FILENAME> --reqtimeout <SECONDS> --tls --cert <CERT> --key <KEY>]
  %[1]s [-f <FILE> -b <BASEDN> -a <ADDRESS> -p <PORT> -T <SECONDS> -C -l <FILENAME> --tls --cert <CERT> --key <KEY>]

Options:
  -u, --url <URL>          rest api url [default: http://localhost/api]
  -f, --file <FILE>        file with json data
  -b, --basedn <BASEDN>    server base dn [default: dc=example,dc=org]
  -a, --addr <ADDRESS>     server address [default: 0.0.0.0]
  -p, --port <PORT>        server port [default: 389]
  -P, --httpport <PORT>    http port (for callback) [default: 8080]
  -t, --token <TOKEN>      rest authentication token (env: REST_AUTH_TOKEN)
  -T, --timeout <SECONDS>  update REST data every <SECONDS>
  -C, --criticality        respect requested control criticality
  -l, --log <FILENAME>     log file path
  --reqtimeout <SECONDS>   http request timeout [default: 10]
  --nocallback             disable http callback [default: false]
  --tls                    use tls [default: false]
  --cert <CERT>            path to cert file / cert data (env: TLS_CERT)
  --key <KEY>              path to key file / key data (env: TLS_KEY)

  -h, --help               show this screen
  -v, --version            show version
`, programName)

func init() {
	opts, err := docopt.ParseArgs(usage, nil, versionString)
	if err != nil {
		fmt.Printf("error parsing options: %s\n", err)
		os.Exit(1)
	}

	if e := opts.Bind(&cmdOpts); e != nil {
		fmt.Printf("error parsing options: %s\n", e)
		os.Exit(1)
	}

	cmdOpts.URL = strings.ToLower(cmdOpts.URL)
	cmdOpts.BaseDN = trimSpacesAfterComma(strings.ToLower(cmdOpts.BaseDN))

	if cmdOpts.UseTLS {
		if len(cmdOpts.ServerCert) == 0 {
			cmdOpts.ServerCert = os.Getenv("TLS_CERT")
		}
		if len(cmdOpts.ServerKey) == 0 {
			cmdOpts.ServerKey = os.Getenv("TLS_KEY")
		}
	}

	if len(cmdOpts.AuthToken) == 0 {
		cmdOpts.AuthToken = os.Getenv("REST_AUTH_TOKEN")
	}
}

func main() {
	log.SetFlags(0)

	if len(cmdOpts.LogFile) > 0 {
		f, err := os.OpenFile(cmdOpts.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			fmt.Printf("error opening logfile: %s\n", err)
			os.Exit(1)
		}

		defer f.Close()
		log.SetOutput(f)
		log.SetFlags(log.LstdFlags)
	}

	entries := entriesData{Domain: dom}

	//Create a new LDAP Server
	ldapServer := ldapserver.NewServer()

	//Create routes bindings
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

	// modify supported only with url
	for _, a := range os.Args {
		switch a {
		case "-u", "--url":
			routes.Modify(func(w ldapserver.ResponseWriter, m *ldapserver.Message) {
				handleModify(w, m, &entries)
			})
		}
	}

	//Attach routes to server
	ldapServer.Handle(routes)

	// listen and serve
	chErr := make(chan error)
	listenOn := fmt.Sprintf("%s:%d", cmdOpts.BindAddress, cmdOpts.BindPort)
	if !cmdOpts.UseTLS {
		log.Printf("starting ldap server on '%s'", listenOn)
		go ldapServer.ListenAndServe(listenOn, chErr)
	} else {
		log.Printf("starting ldaps server on '%s'", listenOn)
		go ldapServer.ListenAndServeTLS(listenOn, cmdOpts.ServerCert, cmdOpts.ServerKey, chErr)
	}

	if err := <-chErr; err != nil {
		log.Fatalf("error starting server: %s", err)
	}

	if len(cmdOpts.File) > 0 {
		cmdOpts.NoCallback = true
	}

	// http callback server
	var httpServer fasthttp.Server
	if !cmdOpts.NoCallback {
		listenOn = fmt.Sprintf("%s:%d", cmdOpts.BindAddress, cmdOpts.HTTPPort)
		log.Printf("starting http server on '%s'", listenOn)

		httpServer.Handler = func(ctx *fasthttp.RequestCtx) {
			handleCallback(ctx, &entries)
		}

		go func() {
			if err := httpServer.ListenAndServe(listenOn); err != nil {
				log.Fatalf("http server error: %s", err)
			}
		}()
	}

	// update entries data
	go func() {
		// initial data load
		// if error occurs -> increment sleep timeout by 1
		// until sleep timeout == updateTimeout
		var dur int
		for {
			log.Printf("client [%d]: updating entries data\n", mainClientID)
			err := entries.update(callbackData{})
			if err != nil {
				log.Printf("client [%d]: error updating entries data: %s\n", mainClientID, err)
				dur += 1
				if dur == cmdOpts.UpdateTimeout {
					break
				}
				time.Sleep(time.Duration(dur) * time.Second)
			} else {
				break
			}
		}

		// update data by ticker
		// every N seconds
		for range time.Tick(time.Duration(cmdOpts.UpdateTimeout) * time.Second) {
			log.Printf("client [%d]: updating entries data\n", mainClientID)
			if err := entries.update(callbackData{}); err != nil {
				log.Printf("client [%d]: error updating entries data: %s\n", mainClientID, err)
			}
		}
	}()

	// update data on SIGUSR1
	go func() {
		chUsr := make(chan os.Signal, 1)
		for {
			signal.Notify(chUsr, syscall.SIGUSR1)
			<-chUsr
			log.Printf("client [%d]: updating entries data\n", signalClientID)
			if err := entries.update(callbackData{}); err != nil {
				log.Printf("client [%d]: error updating entries data: %s\n", signalClientID, err)
			}
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
