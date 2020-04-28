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

	"github.com/docopt/docopt-go"
	ldapserver "github.com/ps78674/ldapserver"
	"github.com/valyala/fasthttp"
)

const (
	mainClientID   int = -1
	signalClientID int = -2
)

var (
	restURL         string
	restFile        string
	baseDN          string
	bindAddress     string
	bindPort        string
	httpPort        string
	noCallback      bool
	useTLS          bool
	serverCert      string
	serverKey       string
	logFile         string
	authToken       string
	memStoreTimeout time.Duration
	restData        restAttrs
)

var (
	versionString = "devel"
	programName   = filepath.Base(os.Args[0])
)

var usage = fmt.Sprintf(`%[1]s: simple LDAP emulator with HTTP REST backend, support bind / search / compare operations

Usage:
  %[1]s [-u <URL> -b <BASEDN> -a <ADDRESS> -p <PORT> (-P <PORT>|--nocallback) (--tls --cert <CERTFILE> --key <KEYFILE>) -l <FILENAME> -t <TOKEN> -m <SECONDS>]
  %[1]s [-f <FILE> -b <BASEDN> -a <ADDRESS> -p <PORT> (--tls --cert <CERTFILE> --key <KEYFILE>) -l <FILENAME> -m <SECONDS>]

Options:
  -u, --url <URL>         rest api url [default: http://localhost/api]
  -f, --file <FILE>       file with json data
  -b, --basedn <BASEDN>   server base dn [default: dc=example,dc=org]
  -a, --addr <ADDRESS>    server address [default: 0.0.0.0]
  -p, --port <PORT>       server port [default: 389]
  -P, --httpport <PORT>   http port (for callback) [default: 8080]
  --nocallback            disable http callback [default: false]
  --tls                   use tls [default: false]
  --cert <CERTFILE>       path to certifcate [default: server.crt]
  --key <KEYFILE>         path to keyfile [default: server.key]
  -l, --log <FILENAME>    log file path
  -t, --token <TOKEN>     rest authentication token
  -m, --memory <SECONDS>  store REST data in memory and update every <SECONDS>
   
  -h, --help              show this screen
  -v, --version           show version
`, programName)

func init() {
	cmdOpts, err := docopt.Parse(usage, nil, true, versionString, false)
	if err != nil {
		fmt.Printf("error parsing options: %s\n", err)
		os.Exit(1)
	}

	restURL = strings.ToLower(cmdOpts["--url"].(string))
	baseDN = strings.ToLower(cmdOpts["--basedn"].(string))
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

	if cmdOpts["--memory"] != nil {
		i, err := strconv.Atoi(cmdOpts["--memory"].(string))
		if err != nil {
			fmt.Printf("error converting '--cache' to int: %s\n", err)
			os.Exit(1)
		}

		memStoreTimeout = time.Duration(i)
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
	routes.Search(handleSearch).BaseDn(baseDN)
	routes.Search(handleSearchOther)
	routes.Compare(handleCompare)

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

	if memStoreTimeout <= 0 && !noCallback {
		log.Println("disabling http callback, because in-memory mode not enabled")
		noCallback = true
	}

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

	// start in memory data updater
	if memStoreTimeout > 0 {
		go func() {
			for {
				restData.update(-1, "", "")
				time.Sleep(memStoreTimeout * time.Second)
			}
		}()

		go func() {
			chUsr := make(chan os.Signal)
			for {
				signal.Notify(chUsr, syscall.SIGUSR1)
				<-chUsr
				go restData.update(-3, "", "")
			}
		}()
	}

	// When CTRL+C, SIGINT and SIGTERM signal occurs
	// Then stop server gracefully
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	close(ch)

	httpServer.Shutdown()
	ldapServer.Stop()
}
