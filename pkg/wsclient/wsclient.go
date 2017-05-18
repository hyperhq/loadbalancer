package wsclient

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/hyperhq/loadbalancer/pkg/signature"
)

var validSchemes = map[string]bool{
	"wss": true,
}

type HyperWSClient struct {
	AccessKey   string
	SecretKey   string
	Scheme      string
	Host        string
	APIVersion  string
	HttpHeaders map[string]string
}

type CancelFunc func()

func NewHyperWSClient(scheme, host, version, access, secret string, headers map[string]string) (*HyperWSClient, error) {
	if !validSchemes[scheme] {
		return nil, fmt.Errorf("%s is not a valid scheme for Hyper.sh Websocket client. Availables: %v", scheme, validSchemes)
	}

	if version != "" && version[0] != '/' {
		version = strings.Join([]string{"/v", strings.TrimPrefix(version, "v")}, "")
	}

	return &HyperWSClient{
		AccessKey:   access,
		SecretKey:   secret,
		Scheme:      scheme,
		Host:        host,
		APIVersion:  version,
		HttpHeaders: headers,
	}, nil
}

func (c *HyperWSClient) request(path, query string) (*http.Request, error) {
	u := &url.URL{Scheme: c.Scheme, Host: c.Host, Path: strings.Join([]string{c.APIVersion, path}, ""), RawQuery: query}

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	for k, v := range c.HttpHeaders {
		req.Header.Set(k, v)
	}
	req.URL = u
	req = signature.Sign4(c.AccessKey, c.SecretKey, req)

	return req, nil
}

func (c *HyperWSClient) ws(req *http.Request) (*websocket.Conn, *http.Response, error) {
	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	dialer := websocket.Dialer{
		TLSClientConfig: config,
	}

	ws, resp, err := dialer.Dial(req.URL.String(), req.Header)

	if resp.StatusCode != http.StatusSwitchingProtocols && err == nil {
		err = fmt.Errorf("status %v shows the connection is failed but no error", resp.StatusCode)
	}

	return ws, resp, err
}

func newCancelFunc(ws *websocket.Conn) CancelFunc {
	return func() { ws.Close() }
}

func getResponseContent(resp *http.Response) []byte {
	var data []byte
	if resp != nil && resp.ContentLength > 0 {
		data, _ = ioutil.ReadAll(resp.Body)
	}
	return data
}
