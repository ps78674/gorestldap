package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
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

var (
	restURL       string
	restFile      string
	baseDN        string
	bindAddress   string
	bindPort      string
	httpPort      string
	noCallback    bool
	useTLS        bool
	serverCert    string
	serverKey     string
	logFile       string
	authToken     string
	updateTimeout time.Duration
)

var (
	versionString = "devel"
	programName   = filepath.Base(os.Args[0])
)

var usage = fmt.Sprintf(`%[1]s: simple LDAP emulator with HTTP REST backend, support bind / search / compare operations

Usage:
  %[1]s [-u <URL> -b <BASEDN> -a <ADDRESS> -p <PORT> (-P <PORT>|--nocallback) (--tls --cert <CERTFILE> --key <KEYFILE>) -l <FILENAME> -t <TOKEN> -T <SECONDS>]
  %[1]s [-f <FILE> -b <BASEDN> -a <ADDRESS> -p <PORT> (--tls --cert <CERTFILE> --key <KEYFILE>) -l <FILENAME> -T <SECONDS>]

Options:
  -u, --url <URL>          rest api url [default: http://localhost/api]
  -f, --file <FILE>        file with json data
  -b, --basedn <BASEDN>    server base dn [default: dc=example,dc=org]
  -a, --addr <ADDRESS>     server address [default: 0.0.0.0]
  -p, --port <PORT>        server port [default: 389]
  -P, --httpport <PORT>    http port (for callback) [default: 8080]
  --nocallback             disable http callback [default: false]
  --tls                    use tls [default: false]
  --cert <CERTFILE>        path to certifcate [default: server.crt]
  --key <KEYFILE>          path to keyfile [default: server.key]
  -l, --log <FILENAME>     log file path
  -t, --token <TOKEN>      rest authentication token
  -T, --timeout <SECONDS>  update REST data every <SECONDS>
   
  -h, --help               show this screen
  -v, --version            show version
`, programName)

func init() {
	cmdOpts, err := docopt.Parse(usage, nil, true, versionString, false)
	if err != nil {
		fmt.Printf("error parsing options: %s\n", err)
		os.Exit(1)
	}

	restURL = strings.ToLower(cmdOpts["--url"].(string))
	baseDN = trimSpacesAfterComma(strings.ToLower(cmdOpts["--basedn"].(string)))
	bindAddress = cmdOpts["--addr"].(string)
	bindPort = cmdOpts["--port"].(string)
	httpPort = cmdOpts["--httpport"].(string)
	noCallback = cmdOpts["--nocallback"].(bool)
	useTLS = cmdOpts["--tls"].(bool)
	serverCert = cmdOpts["--cert"].(string)
	serverKey = cmdOpts["--key"].(string)

	if cmdOpts["--file"] != nil {
		restFile = cmdOpts["--file"].(string)
	}

	if cmdOpts["--log"] != nil {
		logFile = cmdOpts["--log"].(string)
	}

	if cmdOpts["--token"] != nil {
		authToken = cmdOpts["--token"].(string)
	} else if envToken := os.Getenv("REST_AUTH_TOKEN"); len(authToken) == 0 && len(envToken) > 0 {
		authToken = envToken
	}

	if cmdOpts["--timeout"] != nil {
		i, err := strconv.Atoi(cmdOpts["--timeout"].(string))
		if err != nil {
			fmt.Printf("error converting '--timeout' to int: %s\n", err)
			os.Exit(1)
		}

		updateTimeout = time.Duration(i)
	}
}

func main() {
	log.SetFlags(0)

	if len(logFile) > 0 {
		f, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			fmt.Printf("error opening logfile: %s\n", err)
			os.Exit(1)
		}

		defer f.Close()
		log.SetOutput(f)
		log.SetFlags(log.LstdFlags)
	}

	//Create a new LDAP Server
	ldapServer := ldapserver.NewServer()

	//Create routes bindings
	routes := ldapserver.NewRouteMux()
	routes.Bind(handleBind)
	routes.Search(handleSearchDSE).BaseDn("").Scope(ldapserver.SearchRequestScopeBaseObject).Filter("(objectclass=*)")
	routes.Search(handleSearch)
	routes.Compare(handleCompare)

	// modify supported only with url
	for _, a := range os.Args {
		switch a {
		case "-u", "--url":
			routes.Modify(handleModify)
			break
		}
	}

	//Attach routes to server
	ldapServer.Handle(routes)

	// listen and serve
	chErr := make(chan error)
	listenOn := fmt.Sprintf("%s:%s", bindAddress, bindPort)
	if !useTLS {
		log.Printf("starting ldap server on '%s'", listenOn)
		go ldapServer.ListenAndServe(listenOn, chErr)
	} else {
		log.Printf("starting ldaps server on '%s'", listenOn)
		go ldapServer.ListenAndServeTLS(listenOn, serverCert, serverKey, chErr)
	}

	if err := <-chErr; err != nil {
		log.Printf("error starting server: %s\n", err)
		os.Exit(1)
	}

	if len(restFile) > 0 {
		noCallback = true
	}

	// http callback server
	var httpServer fasthttp.Server
	if !noCallback {
		chErr := make(chan error)
		listenOn := fmt.Sprintf("%s:%s", bindAddress, httpPort)
		log.Printf("starting http server on '%s'", listenOn)

		go func() {
			if err := listenAndServeHTTP(&httpServer, listenOn, chErr); err != nil {
				log.Printf("http server error: %s\n", err)
			}
		}()

		if err := <-chErr; err != nil {
			log.Printf("error starting server: %s\n", err)
			os.Exit(1)
		}
	}

	// update entries data
	go func() {
		// initial data load
		// if error occurs -> increment sleep timeout by 1
		// until sleep timeout == updateTimeout
		var dur time.Duration
		for {
			log.Printf("client [%d]: updating entries data\n", mainClientID)
			err := entries.update(callbackData{})
			if err != nil {
				log.Printf("client [%d]: error updating entries data: %s\n", mainClientID, err)
				dur += 1
				if dur == updateTimeout {
					break
				}
				time.Sleep(dur * time.Second)
			} else {
				break
			}
		}

		// update data by ticker
		// every N seconds
		for range time.Tick(updateTimeout * time.Second) {
			log.Printf("client [%d]: updating entries data\n", mainClientID)
			if err := entries.update(callbackData{}); err != nil {
				log.Printf("client [%d]: error updating entries data: %s\n", mainClientID, err)
			}
		}
	}()

	// update data on SIGUSR1
	go func() {
		chUsr := make(chan os.Signal)
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
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch

	httpServer.Shutdown()
	ldapServer.Stop()

	signal.Stop(ch)
	close(ch)
}
