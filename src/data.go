package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"sync"

	"github.com/valyala/fasthttp"
)

const (
	urlLDAPUsers  = "/ldap/user"
	urlLDAPGroups = "/ldap/group"
)

type domain struct {
	ObjectClass     []string `json:"objectClass"`
	HasSubordinates string   `json:"hasSubordinates" hidden:"yes"`
}

type user struct {
	LDAPAdmin       bool     `json:"ldapAdmin" skip:"yes"`
	EntryUUID       string   `json:"entryUUID" hidden:"yes"`
	HasSubordinates string   `json:"hasSubordinates" hidden:"yes"`
	ObjectClass     []string `json:"objectClass"`
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
	IPHostNumber    []string `json:"ipHostNumber"`
}

type group struct {
	EntryUUID       string   `json:"entryUUID" hidden:"yes"`
	HasSubordinates string   `json:"hasSubordinates" hidden:"yes"`
	ObjectClass     []string `json:"objectClass"`
	CN              string   `json:"cn"`
	GIDNumber       string   `json:"gidNumber"`
	Description     string   `json:"description"`
	OU              []string `json:"ou"`
	MemberUID       []string `json:"memberUid"`
}

type entriesData struct {
	Mutex  sync.RWMutex
	Domain domain
	Users  []user
	Groups []group
}

var entries entriesData

func (data *entriesData) update(cNum int, cb callbackData) {
	data.Mutex.Lock()
	defer data.Mutex.Unlock()

	data.Domain = domain{
		ObjectClass: []string{
			"top",
			"domain",
		},
		HasSubordinates: "TRUE",
	}

	if len(restFile) > 0 {
		log.Printf("client [%d]: getting data from file '%s'", cNum, restFile)

		fileContents, err := ioutil.ReadFile(restFile)
		if err != nil {
			log.Printf("client [%d]: error opening file: '%s'", cNum, err)
			return
		}

		fileData := entriesData{}
		if err := json.Unmarshal(fileContents, &fileData); err != nil {
			log.Printf("client [%d]: error unmarshalling file data: %s\n", cNum, err)
			return
		}

		data.Users = fileData.Users
		data.Groups = fileData.Groups

		return
	}

	if cNum == mainClientID || cNum == signalClientID {
		log.Printf("client [%d]: getting all users data\n", cNum)
		ret, err := getAPIData("user", 0)
		if err != nil {
			log.Printf("client [%d]: error getting users data: %s\n", cNum, err)
		} else {
			data.Users = ret.([]user)
		}

		log.Printf("client [%d]: getting all groups data\n", cNum)
		ret, err = getAPIData("group", 0)
		if err != nil {
			log.Printf("client [%d]: error getting groups data: %s\n", cNum, err)
		} else {
			data.Groups = ret.([]group)
		}

		return
	}

	if cNum == httpClientID {
		switch cb.Type {
		case "user":
			// type - user and not id specified == update all users
			if cb.ID == 0 {
				log.Printf("client [%d]: getting all users data\n", cNum)
				ret, err := getAPIData("user", 0)
				if err != nil {
					log.Printf("client [%d]: error getting users data: %s\n", cNum, err)
				} else {
					data.Users = ret.([]user)
				}

				return
			}

			// update / append user by id
			if cb.ID > 0 {
				log.Printf("client [%d]: getting user data for id %d\n", cNum, cb.ID)
				ret, err := getAPIData("user", cb.ID)
				if err != nil {
					log.Printf("client [%d]: error getting user data: %s\n", cNum, err)
					return
				}

				newData := ret.([]user)

				// id must be unique in API, if multiple objects returned -> stop
				// if len(newData) == 0 -> none returned), stop
				if len(newData) != 1 {
					log.Printf("client [%d]: returned slice length > 1\n", cNum)
					return
				}

				found := false
				for i := range data.Users {
					if data.Users[i].UIDNumber == newData[0].UIDNumber {
						data.Users[i] = newData[0]
						found = true
						break
					}
				}

				if !found {
					data.Users = append(data.Users, newData[0])
				}
			}
		case "group":
			// type - group and not id specified -> update all groupa
			if cb.ID == 0 {
				log.Printf("client [%d]: getting all groups data\n", cNum)
				ret, err := getAPIData("group", 0)
				if err != nil {
					log.Printf("client [%d]: error getting groups data: %s\n", cNum, err)
				} else {
					data.Groups = ret.([]group)
				}

				return
			}

			// update / append group by id
			if cb.ID > 0 {
				log.Printf("client [%d]: getting group data for id %d\n", cNum, cb.ID)
				ret, err := getAPIData("group", cb.ID)
				if err != nil {
					log.Printf("client [%d]: error getting group data: %s\n", cNum, err)
				}

				newData := ret.([]group)

				// id must be unique in API, if multiple objects returned -> stop
				// if len(newData) == 0 -> none returned), stop
				if len(newData) != 1 {
					log.Printf("client [%d]: returned slice length > 1\n", cNum)
					return
				}

				found := false
				for i := range data.Groups {
					if data.Groups[i].GIDNumber == newData[0].GIDNumber {
						data.Groups[i] = newData[0]
						found = true
						break
					}
				}

				if !found {
					data.Groups = append(data.Groups, newData[0])
				}
			}
		default:
			log.Printf("client [%d]: got wrong callback data %s", httpClientID, cb.RAWMessage)
			return
		}
	}
}

func doRequest(reqURL string, body []byte) ([]byte, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(reqURL)
	if len(authToken) > 0 {
		req.Header.Add("Authorization", fmt.Sprintf("Token %s", authToken))
	}

	if len(body) > 0 {
		req.Header.SetContentType("application/json")
		req.Header.SetMethod("PUT")
		req.SetBody(body)
	}

	httpClient := &fasthttp.Client{}
	if err := httpClient.Do(req, resp); err != nil {
		return nil, err
	}

	return resp.Body(), nil
}

// get data from API
func getAPIData(reqType string, id int) (ret interface{}, err error) {
	switch reqType {
	case "user":
		reqURL := fmt.Sprintf("%s%s", restURL, urlLDAPUsers)
		if id > 0 {
			reqURL = fmt.Sprintf("%s?uidNumber=%d", reqURL, id)
		}

		respData, e := doRequest(reqURL, []byte{})
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
		reqURL := fmt.Sprintf("%s%s", restURL, urlLDAPGroups)
		if id > 0 {
			reqURL = fmt.Sprintf("%s?gidNumber=%d", reqURL, id)
		}

		respData, e := doRequest(reqURL, []byte{})
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
