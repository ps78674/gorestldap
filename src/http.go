package main

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/valyala/fasthttp"
)

type callbackData struct {
	CN   string
	Type string
}

func listenAndServeHTTP(s *fasthttp.Server, addr string, ch chan error) error {
	httpHandler := func(ctx *fasthttp.RequestCtx) {
		switch path := string(ctx.Path()); path {
		case "/callback":
			handleCallback(ctx)
		default:
			strErr := fmt.Sprintf("unsupported path '%s'\n", path)
			ctx.Error(strErr, fasthttp.StatusNotFound)
		}
	}

	l, err := net.Listen("tcp", addr)
	if err != nil {
		ch <- fmt.Errorf("error creating listener: %s", err)
		return nil
	}

	close(ch)

	s.Handler = httpHandler
	return s.Serve(l)
}

func handleCallback(ctx *fasthttp.RequestCtx) {
	if !ctx.IsPost() {
		strMsg := fmt.Sprintf("wrong http method '%s'\n", ctx.Method())
		ctx.Error(strMsg, fasthttp.StatusBadRequest)
		return
	}

	if string(ctx.Request.Header.ContentType()) != "application/json" {
		strMsg := fmt.Sprintf("wrong content type '%s'\n", ctx.Request.Header.ContentType())
		ctx.Error(strMsg, fasthttp.StatusBadRequest)
		return
	}

	var postData callbackData
	if err := json.Unmarshal(ctx.PostBody(), &postData); err != nil {
		strMsg := fmt.Sprintf("error unmarshalling post body: %s\n", ctx.PostBody())
		ctx.Error(strMsg, fasthttp.StatusBadRequest)
	}

	go restData.update(-2, postData.CN, postData.Type)
}
