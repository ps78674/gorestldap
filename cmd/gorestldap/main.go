package main

import (
	"fmt"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/ps78674/gorestldap/internal/backend"
	"github.com/ps78674/gorestldap/internal/config"
	"github.com/ps78674/gorestldap/internal/http"
	"github.com/ps78674/gorestldap/internal/ldap"
	ldapserver "github.com/ps78674/ldapserver"
	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

func main() {
	// init config
	var cfg config.Config
	if err := cfg.Init(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// setup logging
	if len(cfg.LogPath) > 0 {
		f, err := os.OpenFile(cfg.LogPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			fmt.Printf("error opening logfile: %s\n", err)
			os.Exit(1)
		}
		defer f.Close()
		log.SetOutput(f)
	}
	if cfg.Debug {
		log.SetLevel(log.DebugLevel)
	}
	var logFormatter log.TextFormatter
	logFormatter.FullTimestamp = true
	if !cfg.LogTimestamp {
		logFormatter.DisableTimestamp = true
	}
	log.SetFormatter(&logFormatter)
	log.SetReportCaller(cfg.LogCaller)
	ldapserver.SetupLogger(log.StandardLogger())

	// open backend
	backendPath := path.Join(cfg.BackendDir, cfg.BackendName+".so")
	log.Debugf("loading backend %s", backendPath)
	backend, err := backend.Open(backendPath, cfg.Backends[cfg.BackendName])
	if err != nil {
		log.Fatalf("error opening backend: %s", err)
	}

	// get initial data
	users, groups, err := backend.GetData()
	if err != nil {
		log.Fatalf("error getting data: %s", err)
	}

	// get entries
	entries := ldap.GetEntries(cfg.BaseDN, cfg.UsersOUName, cfg.GroupsOUName)
	entries.Users = users
	entries.Groups = groups

	// create ticker
	ticker := time.NewTicker(cfg.UpdateInterval)
	defer ticker.Stop()

	// create new LDAP Server
	ldapServer, err := ldap.NewServer(entries, cfg.BaseDN, cfg.UsersOUName, cfg.GroupsOUName, cfg.RespectCritical, cfg.UpdateInterval, backend, ticker)
	if err != nil {
		log.Fatalf("error creating ldap server: %s", err)
	}

	// listen and serve
	switch cfg.UseTLS {
	case false:
		log.Infof("starting ldap server on '%s'", cfg.ListenAddr)
		go func() {
			if err := ldapServer.ListenAndServe(cfg.ListenAddr); err != nil {
				log.Fatalf("error starting server: %s\n", err)
			}
		}()
	case true:
		log.Infof("starting ldaps server on '%s'", cfg.ListenAddr)
		go func() {
			if err := ldapServer.ListenAndServeTLS(cfg.ListenAddr, cfg.ServerCert, cfg.ServerKey); err != nil {
				log.Fatalf("error starting server: %s\n", err)
			}
		}()
	}

	// create http server
	var httpServer *fasthttp.Server
	if len(cfg.CallbackListenAddr) > 0 {
		log.Infof("starting http server on '%s'", cfg.CallbackListenAddr)

		httpServer = http.NewServer(cfg.CallbackAuthToken, cfg.UpdateInterval, ticker)

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
		chReload := make(chan os.Signal, 1)
		for {
			signal.Notify(chReload, syscall.SIGUSR1)
			<-chReload
			ticker.Reset(time.Millisecond)
			<-ticker.C
			ticker.Reset(cfg.UpdateInterval)
		}
	}()

	// graceful stop on CTRL+C / SIGINT / SIGTERM
	chStop := make(chan os.Signal, 1)
	signal.Notify(chStop, syscall.SIGINT, syscall.SIGTERM)
	<-chStop

	httpServer.Shutdown()
	log.Info("gracefully closing client connections")
	ldapServer.Stop()
	log.Info("all client connections closed")

	signal.Stop(chStop)
	close(chStop)
}
