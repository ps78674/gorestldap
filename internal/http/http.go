package http

import (
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

func NewServer(callbackAuthToken string, updateInterval time.Duration, ticker *time.Ticker, logger *logrus.Logger) *fasthttp.Server {
	return &fasthttp.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler: func(ctx *fasthttp.RequestCtx) {
			handleCallback(ctx, callbackAuthToken, updateInterval, ticker, logger)
		},
	}
}

func handleCallback(ctx *fasthttp.RequestCtx, callbackAuthToken string, updateInterval time.Duration, ticker *time.Ticker, logger *logrus.Logger) {
	switch path := string(ctx.Path()); path {
	case "/callback":
		logger.Debug("new callback request")

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
