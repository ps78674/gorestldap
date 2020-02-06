package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

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

var prevUserSearchResult []restUserAttrs
var prevUserSearchTimestamp time.Time

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
func getRESTUserData(cNum int, userName string, uidNumber string, ipHostNumber string) (userData []restUserAttrs) {
	// check cached result
	// TODO imrove caching for more results (or drop it) ??
	if time.Since(prevUserSearchTimestamp) < cacheTimeout*time.Second && len(prevUserSearchResult) > 0 && userName == prevUserSearchResult[0].CN[0] {
		userData = prevUserSearchResult
		return
	}

	var urlParameters []string

	if len(userName) > 0 { // need to throw an error if len(username) == 0 ??
		urlParameters = append(urlParameters, fmt.Sprintf("username=%s", userName))
	}

	if len(uidNumber) > 0 {
		urlParameters = append(urlParameters, fmt.Sprintf("uid=%s", uidNumber))
	}

	if len(ipHostNumber) > 0 {
		urlParameters = append(urlParameters, fmt.Sprintf("ipHostNumber=%s", ipHostNumber))
	}

	reqURL := fmt.Sprintf("%s%s?%s", restURL, urlLDAPUsers, strings.Join(urlParameters, "&"))
	log.Printf("client [%d]: getting API data, url '%s'", cNum, reqURL)

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
		log.Printf("client [%d]: error getting API data for user '%s': returned nil\n", cNum, userName)
		return

	}

	// cache last result
	if len(userData) == 1 {
		prevUserSearchResult = userData
		prevUserSearchTimestamp = time.Now()
	}

	return
}

// get groups data from rest
func getRESTGroupData(cNum int, groupName string, gidNumber string, memberUID string) (groupData []restGroupAttrs) {
	var urlParameters []string

	if len(groupName) > 0 {
		urlParameters = append(urlParameters, fmt.Sprintf("name=%s", groupName))
	}

	if len(gidNumber) > 0 {
		urlParameters = append(urlParameters, fmt.Sprintf("gid=%s", gidNumber))
	}

	if len(memberUID) > 0 {
		urlParameters = append(urlParameters, fmt.Sprintf("memberUid=%s", memberUID))
	}

	reqURL := fmt.Sprintf("%s%s?%s", restURL, urlLDAPGroups, strings.Join(urlParameters, "&"))
	log.Printf("client [%d]: getting API data, url '%s'", cNum, reqURL)

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
		log.Printf("client [%d]: error getting API data for group '%s': returned nil\n", cNum, groupName)
		return
	}

	return
}
