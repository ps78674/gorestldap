package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/valyala/fasthttp"
)

type callbackData struct {
	Type       string
	ID         int
	RAWMessage string
}

const httpClientID int = -3

func handleCallback(ctx *fasthttp.RequestCtx, data *entriesData) {
	switch path := string(ctx.Path()); path {
	case "/callback":
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
		postBody := ctx.PostBody()
		if err := json.Unmarshal(postBody, &postData); err != nil {
			strMsg := fmt.Sprintf("wrong json %s\n", ctx.PostBody())
			ctx.Error(strMsg, fasthttp.StatusBadRequest)
			return
		}

		postData.RAWMessage = string(postBody)
		log.Printf("client [%d]: updating entries data\n", httpClientID)
		if err := data.update(postData); err != nil {
			log.Printf("client [%d]: error updating entries data: %s\n", httpClientID, err)
		}
	default:
		strErr := fmt.Sprintf("unsupported path '%s'\n", path)
		ctx.Error(strErr, fasthttp.StatusNotFound)
	}
}
