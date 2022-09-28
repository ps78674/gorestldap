package main

import (
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

func handleCallback(ctx *fasthttp.RequestCtx, cfg *Config, ticker *time.Ticker) {
	switch path := string(ctx.Path()); path {
	case "/callback":
		log.Debug("new callback request")

		if !ctx.IsHead() {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			return
		}

		hAuthBytes := ctx.Request.Header.Peek("Authorization")
		cbToken := strings.TrimPrefix(string(hAuthBytes), "Token ")
		if cbToken != cfg.CallbackAuthToken {
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			return
		}

		ticker.Reset(time.Millisecond)
		<-ticker.C
		ticker.Reset(cfg.UpdateInterval)
	default:
		ctx.Redirect("/callback", fasthttp.StatusMovedPermanently)
	}
}
