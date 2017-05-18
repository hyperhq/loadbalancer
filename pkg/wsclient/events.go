package wsclient

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hyperhq/loadbalancer/pkg/types"
)

var validEventFilters = map[string]bool{
	"container": true,
	"image":     true,
	"event":     true,
	"label":     true,
}

func (c *HyperWSClient) Events(filters ...string) (chan *types.EventResponse, chan error, CancelFunc, error) {
	var queryParam string = ""
	if len(filters) > 0 {
		qs, err := parseFilters(filters)
		if err != nil {
			return nil, nil, nil, err
		}
		queryParam = fmt.Sprintf("filters=%s", qs)
	}

	req, err := c.request("/events/ws", queryParam)
	if err != nil {
		return nil, nil, nil, err
	}

	ws, resp, err := c.ws(req)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		if ws != nil {
			ws.Close()
		}
		return nil, nil, nil, err
	}

	cf := newCancelFunc(ws)
	var (
		evch = make(chan *types.EventResponse, 128)
		ech  = make(chan error, 4)
	)

	go func() {
		defer ws.Close()
		for {
			var event types.EventResponse
			_, message, err := ws.ReadMessage()
			if err != nil {
				ech <- err
				break
			}
			err = json.Unmarshal(message, &event)
			if err != nil {
				ech <- err
				break
			}
			evch <- &event
		}
		close(ech)
		close(evch)
	}()

	return evch, ech, cf, nil
}

func parseFilters(filters []string) (string, error) {
	result := map[string]map[string]bool{}
	for _, v := range filters {
		item := strings.SplitN(v, "=", 2)
		if !validEventFilters[item[0]] {
			return "", fmt.Errorf("%q is not a valid filter, only %v is allowed", item[0], validEventFilters)
		}
		if len(item) < 2 {
			return "", fmt.Errorf("Invalid filter: %q", v)
		}
		mm, ok := result[item[0]]
		if !ok {
			mm = make(map[string]bool)
			result[item[0]] = mm
		}
		mm[item[1]] = true
	}
	b, err := json.Marshal(result)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
