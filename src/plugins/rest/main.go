package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
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

func (b *backend) UpdateData(old, new interface{}) error {
	client := fasthttp.Client{
		ReadTimeout:  b.config.HTTPReqTimeout,
		WriteTimeout: b.config.HTTPReqTimeout,
	}

	tgt := reflect.New(reflect.TypeOf(old))
	for i := 0; i < reflect.ValueOf(old).NumField(); i++ {
		var eq bool
		switch {
		case reflect.ValueOf(old).Field(i).Kind() == reflect.Slice:
			eq = reflect.DeepEqual(reflect.ValueOf(old).Field(i).Interface(), reflect.ValueOf(new).Field(i).Interface())
		default:
			eq = reflect.ValueOf(old).Field(i).Interface() == reflect.ValueOf(new).Field(i).Interface()
		}
		if !eq {
			tgt.Elem().FieldByIndex([]int{i}).Set(reflect.ValueOf(new).Field(i))
		}
	}

	switch entry := old.(type) {
	case data.User:
		if err := updateData(&client, b.config.URL+b.config.UsersPath+"/"+entry.CN, b.config.AuthToken, tgt.Interface()); err != nil {
			return fmt.Errorf("error updating users data: %s", err)
		}
	case data.Group:
		if err := updateData(&client, b.config.URL+b.config.GroupsPath+"/"+entry.CN, b.config.AuthToken, tgt.Interface()); err != nil {
			return fmt.Errorf("error updating groups data: %s", err)
		}
	}

	return nil
}

func getData(c *fasthttp.Client, url, token string, data interface{}) error {
	respData, err := doRequest(c, url, token, nil)
	if err != nil {
		return fmt.Errorf("request error: %s", err)
	}

	if err = json.Unmarshal(respData, data); err != nil {
		// print raw response ??
		return fmt.Errorf("error unmarshalling data: %s", err)
	}

	return nil
}

func updateData(c *fasthttp.Client, url, token string, data interface{}) error {
	b, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("error marshalling data: %s", err)
	}

	respData, err := doRequest(c, url, token, b)
	if err != nil {
		errMsg := fmt.Sprintf("request error: %s", err)
		if respData != nil {
			errMsg += ": " + string(respData)
		}
		return errors.New(errMsg)

	}

	return nil
}

func doRequest(c *fasthttp.Client, url, token string, data []byte) ([]byte, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(url)
	req.Header.Add("Authorization", "Token "+token)

	if data != nil {
		req.Header.SetContentType("application/json")
		req.Header.SetMethod(fasthttp.MethodPut)
		req.SetBodyRaw(data)
	}

	log.Debugf("requesting URL %s", url)

	if err := c.Do(req, resp); err != nil {
		return resp.Body(), err
	}
	if resp.StatusCode() != fasthttp.StatusOK {
		return resp.Body(), fmt.Errorf("response code %d", resp.StatusCode())
	}

	log.Debugf("got response data with len=%d", len(resp.Body()))

	return resp.Body(), nil
}
