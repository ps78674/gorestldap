package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

const (
	urlLDAPUsers  = "/ldap/user"
	urlLDAPGroups = "/ldap/group"
)

type domain struct {
	ObjectClass     []string `json:"objectClass"`
	HasSubordinates string   `json:"hasSubordinates" hidden:""`
}

type user struct {
	LDAPAdmin       bool     `json:"ldapAdmin" skip:""`
	EntryUUID       string   `json:"entryUUID" hidden:""`
	HasSubordinates string   `json:"hasSubordinates" hidden:""`
	ObjectClass     []string `json:"objectClass" lower:""`
	CN              string   `json:"cn"`
	UIDNumber       string   `json:"uidNumber"`
	UserPassword    string   `json:"userPassword"`
	GIDNumber       string   `json:"gidNumber"`
	UID             string   `json:"uid"`
	DisplayName     string   `json:"displayName"`
	GivenName       string   `json:"givenName"`
	SN              string   `json:"sn"`
	Mail            string   `json:"mail"`
	HomeDirectory   string   `json:"homeDirectory"`
	LoginShell      string   `json:"loginShell"`
	MemberOf        []string `json:"memberOf"`
	SSHPublicKey    []string `json:"sshPublicKey"`
}

type group struct {
	EntryUUID       string   `json:"entryUUID" hidden:""`
	HasSubordinates string   `json:"hasSubordinates" hidden:""`
	ObjectClass     []string `json:"objectClass" lower:""`
	CN              string   `json:"cn"`
	GIDNumber       string   `json:"gidNumber"`
	Description     string   `json:"description"`
	OU              []string `json:"ou"`
	MemberUID       []string `json:"memberUid"`
}

type entriesData struct {
	Domain   domain
	Users    []user
	Groups   []group
	dataMu   sync.RWMutex // mutex for ldap handlers
	updateMu sync.Mutex   // mutex for update goroutines
}

var dom = domain{
	ObjectClass: []string{
		"top",
		"domain",
	},
	HasSubordinates: "TRUE",
}

func (data *entriesData) update(cb callbackData) error {
	var newUsers, newGroups interface{}

	data.updateMu.Lock()
	defer data.updateMu.Unlock()

	if len(cmdOpts.File) > 0 {
		fileContents, err := ioutil.ReadFile(cmdOpts.File)
		if err != nil {
			return fmt.Errorf("error opening file: %s", err)
		}

		newData := entriesData{}
		if err := json.Unmarshal(fileContents, &newData); err != nil {
			return fmt.Errorf("error unmarshalling file data: %s", err)
		}

		newUsers = newData.Users
		newGroups = newData.Groups
	}

	if len(cmdOpts.File) == 0 && len(cb.Type) == 0 {
		ret, err := getAPIData("user", 0)
		if err != nil {
			return fmt.Errorf("error getting users data: %s", err)
		} else {
			newUsers = ret
		}

		ret, err = getAPIData("group", 0)
		if err != nil {
			return fmt.Errorf("error getting groups data: %s", err)
		} else {
			newGroups = ret
		}
	}

	if len(cmdOpts.File) == 0 && len(cb.Type) > 0 {
		switch cb.Type {
		case "user":
			// type - user and not id specified == update all users
			if cb.ID == 0 {
				ret, err := getAPIData("user", 0)
				if err != nil {
					return fmt.Errorf("error getting users data: %s", err)
				}

				newUsers = ret
			} else {
				// update / append user by id
				ret, err := getAPIData("user", cb.ID)
				if err != nil {
					return fmt.Errorf("error getting user data: %s", err)
				}

				// id must be unique in API, if multiple objects returned -> stop
				if len(ret.([]user)) > 1 {
					return fmt.Errorf("multiple objects returned")
				}

				// if len(newData) == 0 -> none returned), stop
				if len(ret.([]user)) == 0 {
					return fmt.Errorf("user with id %d is not found", cb.ID)
				}

				newUsers = ret
			}
		case "group":
			// type - group and not id specified -> update all groupa
			if cb.ID == 0 {
				ret, err := getAPIData("group", 0)
				if err != nil {
					return fmt.Errorf("error getting groups data: %s", err)
				}

				newGroups = ret
			}

			// update / append group by id
			if cb.ID > 0 {
				ret, err := getAPIData("group", cb.ID)
				if err != nil {
					return fmt.Errorf("error getting group data: %s", err)
				}

				// id must be unique in API, if multiple objects returned -> stop
				if len(ret.([]group)) > 1 {
					return fmt.Errorf("multiple objects returned")
				}

				// if len(newData) == 0 -> none returned), stop
				if len(ret.([]group)) == 0 {
					return fmt.Errorf("group with id %d is not found", cb.ID)
				}

				newGroups = ret
			}
		default:
			return fmt.Errorf("got wrong callback data %s", cb.RAWMessage)
		}
	}

	data.dataMu.Lock()
	defer data.dataMu.Unlock()

	if newUsers != nil {
		if newUsers := newUsers.([]user); len(newUsers) == 1 {
			found := false
			for i := range data.Users {
				if data.Users[i].UIDNumber == newUsers[0].UIDNumber {
					data.Users[i] = newUsers[0]
					found = true
					break
				}
			}
			if !found {
				data.Users = append(data.Users, newUsers[0])
			}
		} else {
			data.Users = newUsers
		}
	}

	if newGroups != nil {
		if newGroups := newGroups.([]group); len(newGroups) == 1 {
			found := false
			for i := range data.Groups {
				if data.Groups[i].GIDNumber == newGroups[0].GIDNumber {
					data.Groups[i] = newGroups[0]
					found = true
					break
				}
			}
			if !found {
				data.Groups = append(data.Groups, newGroups[0])
			}
		} else {
			data.Groups = newGroups
		}
	}
	return nil
}

func doRequest(reqURL string, body []byte) ([]byte, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(reqURL)
	if len(cmdOpts.AuthToken) > 0 {
		req.Header.Add("Authorization", fmt.Sprintf("Token %s", cmdOpts.AuthToken))
	}

	if body != nil {
		req.Header.SetContentType("application/json")
		req.Header.SetMethod("PUT")
		req.SetBody(body)
	}

	httpClient := &fasthttp.Client{
		ReadTimeout:  time.Duration(cmdOpts.ReqTimeout) * time.Second,
		WriteTimeout: time.Duration(cmdOpts.ReqTimeout) * time.Second,
	}
	if err := httpClient.Do(req, resp); err != nil {
		return nil, err
	}
	if resp.StatusCode() != fasthttp.StatusOK {
		return nil, fmt.Errorf("got status code %d", resp.StatusCode())
	}

	return resp.Body(), nil
}

// get data from API
func getAPIData(reqType string, id int) (ret interface{}, err error) {
	switch reqType {
	case "user":
		reqURL := fmt.Sprintf("%s%s", cmdOpts.URL, urlLDAPUsers)
		if id > 0 {
			reqURL = fmt.Sprintf("%s?uidNumber=%d", reqURL, id)
		}

		respData, e := doRequest(reqURL, nil)
		if e != nil {
			err = fmt.Errorf("error getting response: %s", e)
			return
		}

		data := []user{}
		if e := json.Unmarshal(respData, &data); e != nil {
			err = fmt.Errorf("error unmarshalling data: %s", e)
			// print raw response ??
			return
		}
		ret = data
	case "group":
		reqURL := fmt.Sprintf("%s%s", cmdOpts.URL, urlLDAPGroups)
		if id > 0 {
			reqURL = fmt.Sprintf("%s?gidNumber=%d", reqURL, id)
		}

		respData, e := doRequest(reqURL, nil)
		if e != nil {
			err = fmt.Errorf("error getting response: %s", e)
			return
		}

		data := []group{}
		if e := json.Unmarshal(respData, &data); e != nil {
			err = fmt.Errorf("error unmarshalling data: %s", e)
			// print raw response ??
			return
		}
		ret = data
	}

	return
}
