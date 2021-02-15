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
	Mutex  sync.Mutex
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
		data.Users = getUsersAPIData(cNum, 0)
		data.Groups = getGroupsAPIData(cNum, 0)
	}

	if cNum == httpClientID {
		// callback data must have type or id or both
		if (cb.Type == "" && cb.ID == 0) || (cb.Type != "" && cb.Type != "user" && cb.Type != "group") {
			log.Printf("client [%d]: got wrong callback data %s", httpClientID, cb.RAWMessage)
			return
		}

		// type - user and not id specified == update all users
		if cb.Type == "user" && cb.ID == 0 {
			data.Users = getUsersAPIData(cNum, 0)
		}

		// type - group and not id specified -> update all groupa
		if cb.Type == "group" && cb.ID == 0 {
			data.Groups = getGroupsAPIData(cNum, 0)
		}

		// update / append user by id
		if (cb.Type == "" || cb.Type == "user") && cb.ID > 0 {
			newData := getUsersAPIData(cNum, cb.ID)

			// id must be unique in API, if multiple objects returned -> stop
			// if len(newData) == 0 -> none returned), stop
			if len(newData) != 1 {
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

		// update / append group by id
		if (cb.Type == "" || cb.Type == "group") && cb.ID > 0 {
			newData := getGroupsAPIData(cNum, cb.ID)

			// id must be unique in API, if multiple objects returned -> stop
			// if len(newData) == 0 -> none returned), stop
			if len(newData) != 1 {
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

// get users data from rest
func getUsersAPIData(cNum int, userID int) (userData []user) {
	reqURL := fmt.Sprintf("%s%s", restURL, urlLDAPUsers)
	if userID > 0 {
		reqURL = fmt.Sprintf("%s?uidNumber=%d", reqURL, userID)
	}

	log.Printf("client [%d]: getting users data, url '%s'", cNum, reqURL)

	respData, err := doRequest(reqURL, []byte{})
	if err != nil {
		log.Printf("client [%d]: error getting response: %s\n", cNum, err)
	}

	if err := json.Unmarshal(respData, &userData); err != nil {
		log.Printf("client [%d]: error unmarshalling users data: %s\n", cNum, err)
		// if len(respData) > 0 {
		// 	log.Printf("client [%d]: raw http response data: %s\n", cNum, respData)
		// }
		return
	}

	if len(userData) == 0 {
		log.Printf("client [%d]: error getting users data from API: returned nil\n", cNum)
		return
	}

	return
}

// get groups data from rest
func getGroupsAPIData(cNum int, groupID int) (groupData []group) {
	reqURL := fmt.Sprintf("%s%s", restURL, urlLDAPGroups)
	if groupID > 0 {
		reqURL = fmt.Sprintf("%s?gidNumber=%d", reqURL, groupID)
	}

	log.Printf("client [%d]: getting groups data, url '%s'", cNum, reqURL)

	respData, err := doRequest(reqURL, []byte{})
	if err != nil {
		log.Printf("client [%d]: error getting http response: %s\n", cNum, err)
	}

	if err := json.Unmarshal(respData, &groupData); err != nil {
		log.Printf("client [%d]: error unmarshalling groups data: %s\n", cNum, err)
		// if len(respData) > 0 {
		// 	log.Printf("client [%d]: raw http response data: %s\n", cNum, respData)
		// }
		return
	}

	if len(groupData) == 0 {
		log.Printf("client [%d]: error getting groups data from API: returned nil\n", cNum)
		return
	}

	return
}
