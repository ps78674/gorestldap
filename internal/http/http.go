package http

import (
	"path"
	"strings"
	"time"

	"github.com/fasthttp/router"
	"github.com/ps78674/gorestldap/internal/ticker"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/pprofhandler"
)

const (
	callbackPath = "/callback"
	pprofPath    = "/debug/pprof"
)

// NewServer resturn new fasthttp server
func NewServer(callbackAuthToken string, ticker *ticker.Ticker, logger *logrus.Logger) *fasthttp.Server {
	return &fasthttp.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      newRouter(callbackAuthToken, ticker, logger).Handler,
	}
}

// newRouter creates new router for callback & pprof
func newRouter(callbackAuthToken string, ticker *ticker.Ticker, logger *logrus.Logger) *router.Router {
	r := router.New()
	r.MethodNotAllowed = func(ctx *fasthttp.RequestCtx) {
		ctx.Response.SetStatusCode(fasthttp.StatusMethodNotAllowed)
		logRequest(ctx, logger)
	}
	r.NotFound = func(ctx *fasthttp.RequestCtx) {
		ctx.Response.SetStatusCode(fasthttp.StatusNotFound)
		logRequest(ctx, logger)
	}
	r.HEAD(callbackPath, func(ctx *fasthttp.RequestCtx) {
		handleCallback(ctx, callbackAuthToken, ticker)
		logRequest(ctx, logger)
	})
	r.GET(path.Join(pprofPath, "{profile:*}"), func(ctx *fasthttp.RequestCtx) {
		pprofhandler.PprofHandler(ctx)
		logRequest(ctx, logger)
	})
	return r
}

func handleCallback(ctx *fasthttp.RequestCtx, callbackAuthToken string, ticker *ticker.Ticker) {
	if !ctx.IsHead() {
		ctx.Response.SetStatusCode(fasthttp.StatusBadRequest)
		return
	}

	hAuthBytes := ctx.Request.Header.Peek("Authorization")
	cbToken := strings.TrimPrefix(string(hAuthBytes), "Token ")
	if cbToken != callbackAuthToken {
		ctx.Response.SetStatusCode(fasthttp.StatusUnauthorized)
		return
	}

	ticker.Reset()

	ctx.Response.SetStatusCode(fasthttp.StatusOK)
}

// logRequest logs all incoming requests
func logRequest(ctx *fasthttp.RequestCtx, l *logrus.Logger) {
	l.Infof(
		"http request: method %s, uri %s, localaddr %s, remoteaddr %s, status %d",
		ctx.Method(),
		ctx.RequestURI(),
		ctx.LocalAddr().String(),
		ctx.RemoteAddr().String(),
		ctx.Response.StatusCode(),
	)
}
