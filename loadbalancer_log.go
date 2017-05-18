package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/golang/glog"
	"github.com/ziutek/syslog"
)

type handler struct {
	*syslog.BaseHandler
}

type syslogServer struct {
	*syslog.Server
}

// newSyslogServer start a syslog server using a unix socket to listen for connections
func newSyslogServer(path string) (*syslogServer, error) {
	glog.Infof("Starting syslog server for haproxy using %v as socket", path)
	// remove the socket file if exists
	os.Remove(path)

	server := &syslogServer{syslog.NewServer()}
	server.AddHandler(newHandler())
	err := server.Listen(path)
	if err != nil {
		return nil, err
	}

	return server, nil
}

func newHandler() *handler {
	h := handler{syslog.NewBaseHandler(1000, nil, false)}
	go h.mainLoop()
	return &h
}

func (h *handler) mainLoop() {
	for {
		message := h.Get()
		if message == nil {
			break
		}

		fmt.Printf("servicelb [%s] %s%s\n", strings.ToUpper(message.Severity.String()), message.Tag, message.Content)
	}

	h.End()
}
