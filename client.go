package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/JackOfMostTrades/spiffe-user-demo/common"
	"io/ioutil"
	"net/http"
)

type UserClient interface {
	GetUserX509(req *common.GetUserX509Request) (*common.GetUserX509Response, error)
	GetUserJwt(req *common.GetUserJwtRequest) (*common.GetUserJwtResponse, error)
	GetJwks() (*common.GetJwksResponse, error)
}

type UserClientImpl struct {
	AuthToken string
	Hostname  string
}

func (c *UserClientImpl) GetUserX509(req *common.GetUserX509Request) (*common.GetUserX509Response, error) {
	req.AuthToken = c.AuthToken
	resp := new(common.GetUserX509Response)
	err := c.doRequest(req, resp, "/x509")
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *UserClientImpl) GetUserJwt(req *common.GetUserJwtRequest) (*common.GetUserJwtResponse, error) {
	req.AuthToken = c.AuthToken
	resp := new(common.GetUserJwtResponse)
	err := c.doRequest(req, resp, "/jwt")
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *UserClientImpl) doRequest(req interface{}, resp interface{}, path string) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	res, err := http.Post(fmt.Sprintf("%s%s", c.Hostname, path), "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	if res.Body != nil {
		defer res.Body.Close()
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		debugData, _ := ioutil.ReadAll(res.Body)
		return fmt.Errorf("non 2xx status code: %d: %s", res.StatusCode, string(debugData))
	}
	err = json.NewDecoder(res.Body).Decode(resp)
	if err != nil {
		return err
	}
	return nil
}

func (c *UserClientImpl) GetJwks() (*common.GetJwksResponse, error) {
	res, err := http.Get(fmt.Sprintf("%s/jwks", c.Hostname))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	resp := new(common.GetJwksResponse)
	err = json.NewDecoder(res.Body).Decode(resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
