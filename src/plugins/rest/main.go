package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ps78674/gorestldap/src/internal/data"
	log "github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
	"gopkg.in/yaml.v3"
)

type config struct {
	URL            string        `yaml:"url"`
	UsersPath      string        `yaml:"users_path"`
	GroupsPath     string        `yaml:"groups_path"`
	AuthToken      string        `yaml:"auth_token"`
	HTTPReqTimeout time.Duration `yaml:"http_request_timeout"`
}

type backend struct {
	config *config
}

var Backend backend

func main() {}

func (b *backend) ReadConfig(in []byte) error {
	return yaml.Unmarshal(in, &b.config)
}

func (b *backend) GetData() ([]data.User, []data.Group, error) {
	client := fasthttp.Client{
		ReadTimeout:  b.config.HTTPReqTimeout,
		WriteTimeout: b.config.HTTPReqTimeout,
	}

	users := []data.User{}
	if err := getData(&client, b.config.URL+b.config.UsersPath, b.config.AuthToken, &users); err != nil {
		return nil, nil, fmt.Errorf("error getting users data: %s", err)
	}

	groups := []data.Group{}
	if err := getData(&client, b.config.URL+b.config.GroupsPath, b.config.AuthToken, &groups); err != nil {
		return nil, nil, fmt.Errorf("error getting groups data: %s", err)
	}

	return users, groups, nil
}

func getData(c *fasthttp.Client, url, token string, data interface{}) error {
	respData, err := doRequest(c, url, token)
	if err != nil {
		return fmt.Errorf("request error: %s", err)
	}

	if err = json.Unmarshal(respData, data); err != nil {
		// print raw response ??
		return fmt.Errorf("error unmarshalling data: %s", err)
	}

	return nil
}

func doRequest(c *fasthttp.Client, url, token string) ([]byte, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(url)

	log.Debug("adding Authorization header")
	req.Header.Add("Authorization", "Token "+token)

	log.Debugf("requesting URL %s", url)

	if err := c.Do(req, resp); err != nil {
		return nil, err
	}
	if resp.StatusCode() != fasthttp.StatusOK {
		return nil, fmt.Errorf("response code %d", resp.StatusCode())
	}

	log.Debugf("got response data with len=%d", len(resp.Body()))

	return resp.Body(), nil
}
