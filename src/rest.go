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
	urlLDAPUsers  = "/ldap/user?CustomField=true"
	urlLDAPGroups = "/ldap/group"
)

type restUserAttrs struct {
	SSHPublicKey  []string `json:"sshPublicKey"`
	UIDNumber     []string `json:"uidNumber"`
	DisplayName   []string `json:"displayName"`
	GivenName     []string `json:"givenName"`
	Mail          []string `json:"mail"`
	GIDNumber     []string `json:"gidNumber"`
	CN            []string `json:"cn"`
	SN            []string `json:"sn"`
	UserPassword  []string `json:"userPassword"`
	HomeDirectory []string `json:"homeDirectory"`
	UID           []string `json:"uid"`
	LoginShell    []string `json:"loginShell"`
	IPHostNumber  []string `json:"ipHostNumber"`
}

type restGroupAttrs struct {
	Description []string `json:"description"`
	OU          []string `json:"ou"`
	CN          []string `json:"cn"`
	GIDNumber   []string `json:"gidNumber"`
	MemberUID   []string `json:"memberUid"`
}

type restAttrs struct {
	Users  []restUserAttrs
	Groups []restGroupAttrs
}

var m sync.Mutex

func (data *restAttrs) update(cNum int, cn string, oType string) {
	m.Lock()
	defer m.Unlock()

	if len(restFile) > 0 {
		log.Printf("client [%d]: getting data from file '%s'", cNum, restFile)

		fileContents, err := ioutil.ReadFile(restFile)
		if err != nil {
			log.Printf("client [%d]: error opening file: '%s'", cNum, err)
			return
		}

		fileData := []restAttrs{}
		if err := json.Unmarshal(fileContents, &fileData); err != nil {
			log.Printf("client [%d]: error unmarshalling file data: %s\n", cNum, err)
		}

		newData := restAttrs{}
		for _, d := range fileData {
			newData.Users = append(newData.Users, d.Users...)
			newData.Groups = append(newData.Groups, d.Groups...)
		}

		if len(newData.Users) > 0 {
			data.Users = newData.Users
		}

		if len(newData.Groups) > 0 {
			data.Groups = newData.Groups
		}

		return
	}

	if oType == "" || oType == "user" {
		if len(data.Users) == 0 {
			data.Users = getRESTUserData(cNum, cn)
		} else {
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
	}
	if oType == "" || oType == "group" {
		if len(data.Groups) == 0 {
			data.Groups = getRESTGroupData(cNum, cn)
		} else {
			for _, newGroup := range getRESTGroupData(cNum, cn) {
				found := false

				for i, exGroup := range data.Groups {
					if newGroup.CN[0] == exGroup.CN[0] && newGroup.OU[0] == exGroup.OU[0] {
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

func doRequest(reqURL string) ([]byte, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(reqURL)
	if len(authToken) > 0 {
		req.Header.Add("Authorization", fmt.Sprintf("Token %s", authToken))
	}

	httpClient := &fasthttp.Client{}
	if err := httpClient.Do(req, resp); err != nil {
		return nil, err
	}

	return resp.Body(), nil
}

// get users data from rest
func getRESTUserData(cNum int, userName string) (userData []restUserAttrs) {
	reqURL := fmt.Sprintf("%s%s", restURL, urlLDAPUsers)
	if len(userName) > 0 {
		reqURL = fmt.Sprintf("%s&username=%s", reqURL, userName)
	}

	log.Printf("client [%d]: getting users data, url '%s'", cNum, reqURL)

	respData, err := doRequest(reqURL)
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
func getRESTGroupData(cNum int, groupName string) (groupData []restGroupAttrs) {
	reqURL := fmt.Sprintf("%s%s", restURL, urlLDAPGroups)
	if len(groupName) > 0 {
		reqURL = fmt.Sprintf("%s?name=%s", reqURL, groupName)
	}

	log.Printf("client [%d]: getting groups data, url '%s'", cNum, reqURL)

	respData, err := doRequest(reqURL)
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
