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

type restUser struct {
	SSHPublicKey  []string
	UIDNumber     []string
	DisplayName   []string
	GivenName     []string
	Mail          []string
	GIDNumber     []string
	CN            []string
	SN            []string
	UserPassword  []string
	HomeDirectory []string
	UID           []string
	LoginShell    []string
	IPHostNumber  []string
}

type restGroup struct {
	Description []string
	OU          []string
	CN          []string
	GIDNumber   []string
	MemberUID   []string
}

type restObjects struct {
	Users  []restUser
	Groups []restGroup
}

var dataMutex sync.Mutex

func (data *restObjects) update(cNum int, cn string, oType string) {
	dataMutex.Lock()
	defer dataMutex.Unlock()

	if len(restFile) > 0 {
		log.Printf("client [%d]: getting data from file '%s'", cNum, restFile)

		fileContents, err := ioutil.ReadFile(restFile)
		if err != nil {
			log.Printf("client [%d]: error opening file: '%s'", cNum, err)
			return
		}

		fileData := restObjects{}
		if err := json.Unmarshal(fileContents, &fileData); err != nil {
			log.Printf("client [%d]: error unmarshalling file data: %s\n", cNum, err)
			return
		}

		data.Users = fileData.Users
		data.Groups = fileData.Groups

		return
	}

	if cNum == mainClientID || cNum == signalClientID {
		data.Users = getRESTUserData(cNum, "")
		data.Groups = getRESTGroupData(cNum, "")
	}

	if cNum == httpClientID {
		if oType == "" || oType == "user" {
			if cn == "" {
				data.Users = getRESTUserData(cNum, "")
				return
			}

			for _, newUser := range getRESTUserData(cNum, cn) {
				found := false

				for i, exUser := range data.Users {
					if newUser.CN[0] == exUser.CN[0] {
						data.Users[i] = newUser
						found = true
						break
					}
				}

				if !found {
					data.Users = append(data.Users, newUser)
				}
			}
		}
		if oType == "" || oType == "group" {
			if cn == "" {
				data.Groups = getRESTGroupData(cNum, "")
				return
			}

			for _, newGroup := range getRESTGroupData(cNum, cn) {
				found := false

				for i, exGroup := range data.Groups {
					if newGroup.CN[0] == exGroup.CN[0] {
						data.Groups[i] = newGroup
						found = true
						break
					}
				}

				if !found {
					data.Groups = append(data.Groups, newGroup)
				}
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
func getRESTUserData(cNum int, userName string) (userData []restUser) {
	reqURL := fmt.Sprintf("%s%s", restURL, urlLDAPUsers)
	if len(userName) > 0 {
		reqURL = fmt.Sprintf("%s?cn=%s", reqURL, userName)
	}

	log.Printf("client [%d]: getting users data, url '%s'", cNum, reqURL)

	respData, err := doRequest(reqURL, []byte{})
	if err != nil {
		log.Printf("client [%d]: error getting response: %s\n", cNum, err)
	}

	if err := json.Unmarshal(respData, &userData); err != nil {
		log.Printf("client [%d]: error unmarshalling users data: %s\n", cNum, err)
		if len(respData) > 0 {
			log.Printf("client [%d]: raw http response data: %s\n", cNum, respData)
		}
		return
	}

	if len(userData) == 0 {
		log.Printf("client [%d]: error getting users data from API: returned nil\n", cNum)
		return
	}

	return
}

// get groups data from rest
func getRESTGroupData(cNum int, groupName string) (groupData []restGroup) {
	reqURL := fmt.Sprintf("%s%s", restURL, urlLDAPGroups)
	if len(groupName) > 0 {
		reqURL = fmt.Sprintf("%s?name=%s", reqURL, groupName)
	}

	log.Printf("client [%d]: getting groups data, url '%s'", cNum, reqURL)

	respData, err := doRequest(reqURL, []byte{})
	if err != nil {
		log.Printf("client [%d]: error getting http response: %s\n", cNum, err)
	}

	if err := json.Unmarshal(respData, &groupData); err != nil {
		log.Printf("client [%d]: error unmarshalling groups data: %s\n", cNum, err)
		if len(respData) > 0 {
			log.Printf("client [%d]: raw http response data: %s\n", cNum, respData)
		}
		return
	}

	if len(groupData) == 0 {
		log.Printf("client [%d]: error getting groups data from API: returned nil\n", cNum)
		return
	}

	return
}
