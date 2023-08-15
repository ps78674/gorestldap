package http

import (
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

func NewServer(callbackAuthToken string, updateInterval time.Duration, ticker *time.Ticker) *fasthttp.Server {
	return &fasthttp.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler: func(ctx *fasthttp.RequestCtx) {
			handleCallback(ctx, callbackAuthToken, updateInterval, ticker)
		},
	}
}

func handleCallback(ctx *fasthttp.RequestCtx, callbackAuthToken string, updateInterval time.Duration, ticker *time.Ticker) {
	switch path := string(ctx.Path()); path {
	case "/callback":
		log.Debug("new callback request")

		if !ctx.IsHead() {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}

		hAuthBytes := ctx.Request.Header.Peek("Authorization")
		cbToken := strings.TrimPrefix(string(hAuthBytes), "Token ")
		if cbToken != callbackAuthToken {
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			return
		}

		ticker.Reset(time.Millisecond)
		<-ticker.C
		ticker.Reset(updateInterval)
	default:
		ctx.Redirect("/callback", fasthttp.StatusMovedPermanently)
	}
}
