FROM gcr.io/google_containers/haproxy:0.3
MAINTAINER Hyper Dev Team <dev@hyper.sh>

RUN mkdir -p /etc/haproxy/errors /var/state/haproxy
RUN for ERROR_CODE in 400 403 404 408 500 502 503 504;do curl -sSL -o /etc/haproxy/errors/$ERROR_CODE.http \
    https://raw.githubusercontent.com/haproxy/haproxy-1.5/master/examples/errorfiles/$ERROR_CODE.http;done
ADD . /gopath/src/github.com/hyperhq/loadbalancer
RUN apt-get update && apt-get install -y gcc make && \
  curl -sL https://storage.googleapis.com/golang/go1.8.1.linux-amd64.tar.gz | tar -C /usr/local -zxf - && \
  cd /gopath/src/github.com/hyperhq/loadbalancer && \
  GOPATH=/gopath PATH=$PATH:$GOPATH/bin:/usr/local/bin:/usr/local/go/bin/ go build -a -installsuffix cgo -ldflags '-w' -o loadbalancer *.go && \
  cp loadbalancer /loadbalancer && rm -rf /gopath && \
  apt-get clean && rm -rf /var/lib/apt/lists/* /var/tmp/* /tmp/*

CMD ["dumb-init", "/loadbalancer"]

ADD dumb-init /sbin/dumb-init
ADD haproxy.cfg /etc/haproxy/haproxy.cfg
ADD template.cfg template.cfg
ADD haproxy_reload haproxy_reload

RUN touch /var/run/haproxy.pid
