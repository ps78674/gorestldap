package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/valyala/fasthttp"
)

const (
	urlLDAPUsers  = "/ldap/user"
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
	OU          []string `json:"ou"` // not used
	CN          []string `json:"cn"`
	GIDNumber   []string `json:"gidNumber"`
	MemberUID   []string `json:"memberUid"`
}

type restAttrs struct {
	Users  []restUserAttrs
	Groups []restGroupAttrs
}

func (data *restAttrs) update(cNum int) {
	data.Users = getRESTUserData(cNum, "")
	data.Groups = getRESTGroupData(cNum, "")
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
		reqURL = fmt.Sprintf("%s?username=%s", reqURL, userName)
	}

	log.Printf("client [%d]: getting users API data, url '%s'", cNum, reqURL)

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
		log.Printf("client [%d]: error getting users API data: returned nil\n", cNum)
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

	log.Printf("client [%d]: getting groups API data, url '%s'", cNum, reqURL)

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
		log.Printf("client [%d]: error getting groups API data: returned nil\n", cNum)
		return
	}

	return
}
