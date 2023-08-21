package main

import (
	"fmt"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/ps78674/gorestldap/internal/backend"
	"github.com/ps78674/gorestldap/internal/config"
	"github.com/ps78674/gorestldap/internal/http"
	"github.com/ps78674/gorestldap/internal/ldap"
	"github.com/ps78674/gorestldap/internal/logger"
	"github.com/ps78674/gorestldap/internal/ticker"
	"github.com/valyala/fasthttp"
)

func main() {
	// init config
	var cfg config.Config
	if err := cfg.Init(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// create logger
	logger, err := logger.NewLogger(cfg.LogPath, cfg.Debug, cfg.LogTimestamp, cfg.LogCaller)
	if err != nil {
		fmt.Printf("error creating logger: %s", err)
		os.Exit(1)
	}

	// open backend
	backendPath := path.Join(cfg.BackendDir, cfg.BackendName+".so")
	logger.Debugf("loading backend '%s'", backendPath)
	backend, err := backend.Open(backendPath, cfg.Backends[cfg.BackendName])
	if err != nil {
		logger.Fatalf("error opening backend: %s", err)
	}

	// get initial data
	users, groups, err := backend.GetData()
	if err != nil {
		logger.Fatalf("error getting data: %s", err)
	}

	// get entries
	entries := ldap.GetEntries(cfg.BaseDN, cfg.UsersOUName, cfg.GroupsOUName)
	entries.Users = users
	entries.Groups = groups

	// create ticker
	ticker := ticker.NewTicker(cfg.UpdateInterval)
	defer ticker.Stop()

	// create new LDAP Server
	ldapServer, err := ldap.NewServer(entries, cfg.BaseDN, cfg.UsersOUName, cfg.GroupsOUName, cfg.RespectCritical, backend, ticker, logger)
	if err != nil {
		logger.Fatalf("error creating ldap server: %s", err)
	}

	// listen and serve
	logger.Infof("starting ldap server on '%s'", cfg.ListenAddr)
	switch cfg.UseTLS {
	case false:
		go func() {
			if err := ldapServer.ListenAndServe(cfg.ListenAddr); err != nil {
				logger.Fatalf("error starting server: %s\n", err)
			}
		}()
	case true:
		go func() {
			if err := ldapServer.ListenAndServeTLS(cfg.ListenAddr, cfg.ServerCert, cfg.ServerKey); err != nil {
				logger.Fatalf("error starting server: %s\n", err)
			}
		}()
	}

	// create http server
	var httpServer *fasthttp.Server
	if len(cfg.CallbackListenAddr) > 0 {
		logger.Infof("starting http server on '%s'", cfg.CallbackListenAddr)
		httpServer = http.NewServer(cfg.CallbackAuthToken, ticker, logger)
		go func() {
			if err := httpServer.ListenAndServe(cfg.CallbackListenAddr); err != nil {
				logger.Fatalf("http server error: %s", err)
			}
		}()
	}

	// update data every cfg.UpdateInterval
	go func() {
		for range ticker.C {
			func() {
				logger.Info("updating entries data")

				entries.Lock()
				defer entries.Unlock()

				logger.Debug("getting backend data")
				users, groups, err := backend.GetData()
				if err != nil {
					logger.Errorf("error getting data: %s", err)
					return
				}

				entries.Users = users
				entries.Groups = groups

				logger.Debug("entries updated")
			}()
		}
	}()

	// reset ticker / update data on SIGUSR1
	chReload := make(chan os.Signal, 1)
	go func() {
		for {
			signal.Notify(chReload, syscall.SIGUSR1)
			<-chReload
			ticker.Reset()
		}
	}()

	// graceful stop on CTRL+C / SIGINT / SIGTERM
	chStop := make(chan os.Signal, 1)
	signal.Notify(chStop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(chStop)
	<-chStop

	signal.Stop(chReload)

	logger.Info("shutting down")
	httpServer.Shutdown()
	logger.Debug("gracefully closing client connections")
	ldapServer.Stop()
	logger.Debug("all client connections closed")
}
