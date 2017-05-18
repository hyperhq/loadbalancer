package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"text/template"
	"time"

	"github.com/docker/engine-api/client"
	"github.com/docker/engine-api/types"
	dfilters "github.com/docker/engine-api/types/filters"
	"github.com/golang/glog"
	htypes "github.com/hyperhq/loadbalancer/pkg/types"
	"github.com/hyperhq/loadbalancer/pkg/wsclient"
	"golang.org/x/net/context"
)

// LBProtocol is the protocol for load balance service
type LBProtocol string

const (
	defaultHyperAPIVersion = "1.23"
	defaultHyperAPIServer  = "tcp://us-west-1.hyper.sh:443"

	resyncPeriod = 5 * time.Second

	// LBProtocolHTTP http
	LBProtocolHTTP LBProtocol = "http"
	// LBProtocolHTTPS https
	LBProtocolHTTPS LBProtocol = "https"
	// LBProtocolTCP tcp
	LBProtocolTCP LBProtocol = "tcp"
	// LBProtocolHTTPSTERM httpsTerm
	LBProtocolHTTPSTERM LBProtocol = "httpsTerm"

	defaultErrorPage   = "file:///etc/haproxy/errors/404.http"
	defaultSSLCertFile = "/etc/haproxy/cert.crt"
)

var (
	server     = flag.String("server", defaultHyperAPIServer, "The API server of Hyper_ Cloud.")
	apiVersion = flag.String("server-version", defaultHyperAPIVersion, "The API version of of Hyper_ Cloud.")

	// See https://cbonte.github.io/haproxy-dconv/configuration-1.5.html#4.2-balance
	// In brief:
	//  * roundrobin: backend with the highest weight (how is this set?) receives new connection
	//  * leastconn: backend with least connections receives new connection
	//  * first: first server sorted by server id, with an available slot receives connection
	//  * source: connection given to backend based on hash of source ip
	supportedAlgorithms = []string{"roundrobin", "leastconn", "first", "source"}
	supportedProtocols  = []LBProtocol{LBProtocolHTTP, LBProtocolTCP, LBProtocolHTTPS, LBProtocolHTTPSTERM}

	labels = flag.String("labels", "", `Comma separated list of labels for filtering
         pods to haproxy backends, e.g. 'app=nginx,role=frontend'.`)

	servicePort   = flag.Int("service-port", -1, `Port to expose this service.`)
	containerPort = flag.Int("container-port", -1, `Port of containers. Default
        same with servicePort.`)
	healthCheckPort = flag.Int("health-check-port", 30000, `Port to listen '/healthz' for
        health checking the service container.`)
	statsPort = flag.Int("stats-port", 30001, `Port for loadbalancer stats,
                Used in the loadbalancer liveness probe.`)
	protocol = flag.String("protocol", "http", "Protocol of this service.")

	healthCheckInterval = flag.Int("health-check-interval", 5, `Interval in seconds for
        health checking the service backends`)
	healthCheckRise = flag.Int("health-check-rise", 2, `number of consecutive valid
        health checks before considering the server as UP`)
	healthCheckFall = flag.Int("health-check-fall", 3, `number of consecutive invalid
        health checks before considering the server as DOWN`)

	sessionAffinity = flag.Bool("session-affinity", false, `SessionAffinity
        indicates if the service must use sticky sessions.`)
	cookieStickySession = flag.Bool("cookie-sticky-session", false, `CookieStickySession
         use a cookie to enable sticky sessions.`)

	startSyslog = flag.Bool("syslog", false, `if set, it will start a syslog server
                that will forward haproxy logs to stdout.`)

	sslCert   = flag.String("ssl-cert", "", `if set, it will load the certificate.`)
	errorPage = flag.String("error-page", "", `if set, it will try to load the content
                as a web page and use the content as error page. Is required that the URL returns
                200 as a status code`)

	defaultReturnCode = flag.Int("default-return-code", 404, `if set, this HTTP code is written
        out for requests that don't match other rules.`)

	algorithm = flag.String("algorithm", "roundrobin", `if set, it allows a custom
                default balance algorithm.`)
)

// loadBalancerConfig represents loadbalancer specific configuration.
type loadBalancerConfig struct {
	Name      string
	ReloadCmd string
	Config    string
	Template  string
	Algorithm string
	Protocol  LBProtocol

	Labels        map[string]string
	ServicePort   int
	ContainerPort int

	cookieStickySession bool
	sessionAffinity     bool
	startSyslog         bool

	// health check params
	interval int
	fall     int
	rise     int

	// Only for https termination
	sslCert string
}

// reload reloads the loadbalancer using the reload cmd specified in the json manifest.
func (cfg *loadBalancerConfig) reload() error {
	output, err := exec.Command("sh", "-c", cfg.ReloadCmd).CombinedOutput()
	msg := fmt.Sprintf("%v -- %v", cfg.Name, string(output))
	if err != nil {
		return fmt.Errorf("error restarting %v: %v", msg, err)
	}
	glog.Infof(msg)
	return nil
}

// write writes the configuration file
func (cfg *loadBalancerConfig) write(services map[string][]service) (err error) {
	var w io.Writer
	w, err = os.Create(cfg.Config)
	if err != nil {
		return
	}

	var t *template.Template
	t, err = template.ParseFiles(cfg.Template)
	if err != nil {
		return
	}

	conf := make(map[string]interface{})
	conf["startSyslog"] = strconv.FormatBool(cfg.startSyslog)
	conf["services"] = services

	var sslConfig string
	if cfg.sslCert != "" {
		err = ioutil.WriteFile(defaultSSLCertFile, []byte(cfg.sslCert), 0644)
		if err != nil {
			return
		}
		sslConfig = "crt " + defaultSSLCertFile
	}
	conf["sslCert"] = sslConfig
	conf["defLbAlgorithm"] = cfg.Algorithm

	err = t.Execute(w, conf)
	return
}

// service encapsulates a single backend entry in the load balancer config.
// The Ep field contains the ips of the pods that make up a service.
type service struct {
	Name string
	Ep   []string

	// Backend container port. The application must serve a 200 page on this port.
	BackendPort int

	// FrontendPort is the port that the loadbalancer listens on for traffic
	// for this service. For http, it's always :80, for each tcp service it
	// is the service port of any service matching a name in the tcpServices set.
	FrontendPort int

	// if true, terminate ssl using the loadbalancers certificates.
	SslTerm bool

	// if set use this to match the path rule
	AclMatch string

	// Algorithm
	Algorithm string

	// Health check
	Interval int
	Fall     int
	Rise     int

	// If SessionAffinity is set and without CookieStickySession, requests are routed to
	// a backend based on client ip. If both SessionAffinity and CookieStickSession are
	// set, a SERVERID cookie is inserted by the loadbalancer and used to route subsequent
	// requests. If neither is set, requests are routed based on the algorithm.

	// Indicates if the service must use sticky sessions
	// http://cbonte.github.io/haproxy-dconv/configuration-1.5.html#stick-table
	// Enabled using the attribute service.spec.sessionAffinity
	SessionAffinity bool

	// CookieStickySession use a cookie to enable sticky sessions.
	// The name of the cookie is SERVERID
	// This only can be used in http services
	CookieStickySession bool
}

// loadBalancerController watches the Hyper_ api and adds/removes services
// from the loadbalancer, via loadBalancerConfig.
type loadBalancerController struct {
	client    *client.Client
	wsclient  *wsclient.HyperWSClient
	cfg       *loadBalancerConfig
	endpoints []string
}

// newLoadBalancerController creates a new controller from the given config.
func newLoadBalancerController(apiServer, apiVersion, accessKey, secretKey string, cfg *loadBalancerConfig) (*loadBalancerController, error) {
	hyperClient, err := newHyperClient(apiServer, apiVersion, accessKey, secretKey)
	if err != nil {
		glog.Errorf("Create hyper client failed: %v", err)
		return nil, err
	}
	wsc, err := newHyperWSClient(apiServer, apiVersion, accessKey, secretKey)
	if err != nil {
		glog.Errorf("Create hyper events client failed: %v", err)
		return nil, err
	}

	lbc := loadBalancerController{
		cfg:       cfg,
		client:    hyperClient,
		wsclient:  wsc,
		endpoints: []string{},
	}

	return &lbc, nil
}

// sync all services with the loadbalancer.
func (lbc *loadBalancerController) sync() error {
	hasNewEndpoints := lbc.checkNewEndpoints()
	if !hasNewEndpoints {
		return nil
	}

	httpSvc, httpsSvc, httpsTermSvc, tcpSvc := lbc.getServices()
	if err := lbc.cfg.write(
		map[string][]service{
			"http":      httpSvc,
			"https":     httpsSvc,
			"httpsTerm": httpsTermSvc,
			"tcp":       tcpSvc,
		}); err != nil {
		return err
	}
	return lbc.cfg.reload()
}

func (lbc *loadBalancerController) updateEndpoints(ev *htypes.EventResponse) error {
	c, err := lbc.client.ContainerInspect(context.Background(), ev.Id)
	if err != nil {
		glog.Warningf("cannot inspect container %s: %v", ev.Id, err)
		return lbc.sync()
	}

	for _, n := range c.NetworkSettings.Networks {
		if n == nil || n.IPAddress == "" {
			continue
		}
		var (
			i    int
			addr string
		)
		for i, addr = range lbc.endpoints {
			if addr == n.IPAddress {
				break
			}
		}
		if c.State.Running && i == len(lbc.endpoints) { //running but not in list
			glog.Infof("add ip of container %s %s", ev.Id, n.IPAddress)
			lbc.endpoints = append(lbc.endpoints, n.IPAddress)
		} else if !c.State.Running && i < len(lbc.endpoints) { //stopped but in list
			glog.Infof("remove ip of container %s %s", ev.Id, n.IPAddress)
			lbc.endpoints = append(lbc.endpoints[:i], lbc.endpoints[i+1:]...)
		}
	}
	return nil
}

func (lbc *loadBalancerController) checkNewEndpoints() bool {
	endpoints := []string{}

	filters := dfilters.NewArgs()
	for k, v := range lbc.cfg.Labels {
		filters.Add("label", fmt.Sprintf("%s=%s", k, v))
	}
	containers, err := lbc.client.ContainerList(context.Background(), types.ContainerListOptions{
		Filter: filters,
	})
	if err != nil {
		glog.Errorf("Get container list failed: %v", err)
		return false
	}

	for _, c := range containers {
		if c.NetworkSettings != nil {
			for _, v := range c.NetworkSettings.Networks {
				if v != nil && v.IPAddress != "" {
					endpoints = append(endpoints, v.IPAddress)
					break
				}
			}
		}
	}

	sort.Sort(sort.StringSlice(endpoints))
	glog.Infof("list all endpoints: %v", endpoints)
	if reflect.DeepEqual(endpoints, lbc.endpoints) {
		glog.V(3).Infof("No new endpoints")
		return false
	}

	lbc.endpoints = endpoints
	return true
}

// getServices returns a list of services and their endpoints.
func (lbc *loadBalancerController) getServices() (httpSvc []service, httpsSvc []service, httpsTermSvc []service, tcpSvc []service) {
	glog.Infof("GetServices got endpoints %q", lbc.endpoints)
	newService := service{
		Name:                lbc.cfg.Name,
		Algorithm:           lbc.cfg.Algorithm,
		FrontendPort:        lbc.cfg.ServicePort,
		BackendPort:         lbc.cfg.ContainerPort,
		SessionAffinity:     lbc.cfg.sessionAffinity,
		CookieStickySession: lbc.cfg.cookieStickySession,
		Interval:            lbc.cfg.interval,
		Fall:                lbc.cfg.fall,
		Rise:                lbc.cfg.rise,
		Ep:                  lbc.endpoints,
	}

	switch lbc.cfg.Protocol {
	case LBProtocolHTTPS:
		// httpsSvc = append(httpsSvc, newService)
		tcpSvc = append(tcpSvc, newService)
	case LBProtocolHTTP:
		httpSvc = append(httpSvc, newService)
	case LBProtocolHTTPSTERM:
		httpsTermSvc = append(httpsTermSvc, newService)
	default:
		tcpSvc = append(tcpSvc, newService)
	}

	return
}

// worker handles the work queue.
func (lbc *loadBalancerController) worker() {
	var (
		cancelFunc wsclient.CancelFunc
		events     chan *htypes.EventResponse
		errCh      chan error
		err        error
	)
	defer func() {
		if cancelFunc != nil {
			cancelFunc()
		}
	}()

	for {
		filters := []string{}
		for k, v := range lbc.cfg.Labels {
			filters = append(filters, fmt.Sprintf("%s=%s", k, v))
		}
		events, errCh, cancelFunc, err = lbc.wsclient.Events(filters...)
		if err != nil {
			glog.Errorf("failed to get events from server: %v", err)
			return
		}

		if err := lbc.sync(); err != nil {
			glog.Warningf("Sync service endpoints error: %v", err)
			cancelFunc()
			time.Sleep(resyncPeriod)
			continue
		}

		glog.Info("connected to server events channel")
		connected := true
		for connected {
			select {
			case ev, ok := <-events:
				if !ok {
					//should have error message here
					select {
					case err, ok = <-errCh:
					case <-time.After(1 * time.Second):
						glog.Errorf("events channel closed, but no error messages")
					}
					glog.Warningf("event connection closed: %v", err)
					connected = false
					break
				}
				if err = lbc.updateEndpoints(ev); err != nil {
					glog.Errorf("failed to update events %#v: %v", ev, err)
					connected = false
					cancelFunc()
				}
			case e, ok := <-errCh:
				if !ok {
					glog.Errorf("events error channel unexpected closed")
					connected = false
					break
				}
				glog.Warningf("events watching closed: %v", e)
			}
		}
	}
}

type staticPageHandler struct {
	pagePath     string
	pageContents []byte
	returnCode   int
	c            *http.Client
}

// newStaticPageHandler returns a staticPageHandles with the contents of pagePath loaded and ready to serve
// page is a url to the page to load.
// defaultPage is the page to load if page is unreachable.
// returnCode is the HTTP code to write along with the page/defaultPage.
func newStaticPageHandler(page string, defaultPage string, returnCode int) *staticPageHandler {
	t := &http.Transport{}
	t.RegisterProtocol("file", http.NewFileTransport(http.Dir("/")))
	c := &http.Client{Transport: t}
	s := &staticPageHandler{c: c}
	if err := s.loadURL(page); err != nil {
		s.loadURL(defaultPage)
	}
	s.returnCode = returnCode
	return s
}

func (s *staticPageHandler) loadURL(url string) error {
	res, err := s.c.Get(url)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		glog.Errorf("%v", err)
		return err
	}
	glog.V(2).Infof("Error page:\n%v", string(body))
	s.pagePath = url
	s.pageContents = body

	return nil
}

// Get serves the error page
func (s *staticPageHandler) Getfunc(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(s.returnCode)
	w.Write(s.pageContents)
}

// registerHandlers  services liveness probes.
func registerHandlers(s *staticPageHandler) {
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		// Delegate a check to the haproxy stats service.
		response, err := http.Get(fmt.Sprintf("http://localhost:%v", *statsPort))
		if err != nil {
			glog.Infof("Error %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				contents, err := ioutil.ReadAll(response.Body)
				if err != nil {
					glog.Infof("Error reading resonse on receiving status %v: %v",
						response.StatusCode, err)
				}
				glog.Infof("%v\n", string(contents))
				w.WriteHeader(response.StatusCode)
			} else {
				w.WriteHeader(200)
				w.Write([]byte("ok"))
			}
		}
	})

	// handler for not matched traffic
	http.HandleFunc("/", s.Getfunc)

	glog.Fatal(http.ListenAndServe(fmt.Sprintf(":%v", *healthCheckPort), nil))
}

func main() {
	flag.Set("v", "3")
	flag.Set("logtostderr", "true")
	flag.Parse()

	accessKey := os.Getenv("HYPER_ACCESS_KEY")
	secretKey := os.Getenv("HYPER_SECRET_KEY")
	if accessKey == "" || secretKey == "" {
		glog.Fatalf("Must set accessKey and secretKey by env HYPER_ACCESS_KEY and HYPER_SECRET_KEY")
	}

	cfg := &loadBalancerConfig{
		Name:                "haproxy",
		ReloadCmd:           "./haproxy_reload",
		Config:              "/etc/haproxy/haproxy.cfg",
		Template:            "template.cfg",
		sslCert:             *sslCert,
		sessionAffinity:     *sessionAffinity,
		cookieStickySession: *cookieStickySession,
		interval:            *healthCheckInterval,
		fall:                *healthCheckFall,
		rise:                *healthCheckRise,
	}

	// check algorithm
	algorithmSupported := false
	for _, algo := range supportedAlgorithms {
		if *algorithm != algo {
			algorithmSupported = true
			break
		}
	}
	if !algorithmSupported {
		glog.Fatalf("Algorithm %s not supported, only %q are supported.", *algorithm, supportedAlgorithms)
	}
	cfg.Algorithm = *algorithm

	// check protocol
	protocolSupported := false
	for _, p := range supportedProtocols {
		if *protocol != string(p) {
			protocolSupported = true
			break
		}
	}
	if !protocolSupported {
		glog.Fatalf("Protocol %q not supported, only %q are supported.", *protocol, supportedProtocols)
	}
	cfg.Protocol = LBProtocol(*protocol)

	// check service port
	if *servicePort <= 0 {
		glog.Fatalf("Service port %d is illegal", *servicePort)
	}
	cfg.ServicePort = *servicePort

	// check container port (default same with service port)
	cfg.ContainerPort = *containerPort
	if cfg.ContainerPort <= 0 {
		cfg.ContainerPort = cfg.ServicePort
	}

	// check labels
	serviceLabels, err := parseLabels(*labels)
	if err != nil {
		glog.Fatalf("Labels errored: %v", err)
	}
	cfg.Labels = serviceLabels

	defErrorPage := newStaticPageHandler(*errorPage, defaultErrorPage, *defaultReturnCode)
	if defErrorPage == nil {
		glog.Fatalf("Failed to load the default error page")
	}

	// serve /healthz for health checking
	go registerHandlers(defErrorPage)

	if *startSyslog {
		cfg.startSyslog = true
		_, err := newSyslogServer("/var/run/haproxy.log.socket")
		if err != nil {
			glog.Fatalf("Failed to start syslog server: %v", err)
		}
	}

	lbc, err := newLoadBalancerController(*server, *apiVersion, accessKey, secretKey, cfg)
	if err != nil {
		glog.Fatalf("unexpected error: %v", err)
	}

	lbc.cfg.reload()
	lbc.worker()
}
