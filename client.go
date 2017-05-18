package main

import (
	"net/http"

	"github.com/docker/engine-api/client"
	"github.com/docker/go-connections/sockets"
	"github.com/docker/go-connections/tlsconfig"
	"github.com/hyperhq/loadbalancer/pkg/wsclient"
)

const UserAgent = "hyper-loadbalancer"

func newHyperClient(apiServer, apiVersion, accessKey, secretKey string) (*client.Client, error) {
	proto, addr, _, err := client.ParseHost(apiServer)
	if err != nil {
		return nil, err
	}

	config, err := tlsconfig.Client(tlsconfig.Options{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		TLSClientConfig: config,
	}
	sockets.ConfigureTransport(tr, proto, addr)

	headers := map[string]string{
		"User-Agent": UserAgent,
	}
	client, err := client.NewClient(apiServer, apiVersion, &http.Client{Transport: tr}, headers, accessKey, secretKey)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func newHyperWSClient(apiServer, apiVersion, accessKey, secretKey string) (*wsclient.HyperWSClient, error) {
	_, addr, _, err := client.ParseHost(apiServer)
	if err != nil {
		return nil, err
	}

	headers := map[string]string{
		"User-Agent": UserAgent,
	}
	c, err := wsclient.NewHyperWSClient("wss", addr, apiVersion, accessKey, secretKey, headers)
	if err != nil {
		return nil, err
	}

	return c, nil
}
