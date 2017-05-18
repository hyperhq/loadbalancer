all: push

TAG ?= latest
PREFIX ?= hyperhq/labeled-loadbalancer
SRC = loadbalancer.go loadbalancer_log.go utils.go client.go

loadbalancer: $(SRC)
	GOPATH=$(GOPATH) CGO_ENABLED=0 GOOS=linux godep go build -a -installsuffix cgo -ldflags '-w' -o $@ $(SRC)

container: loadbalancer
	docker build -t $(PREFIX):$(TAG) .

push: container
	docker push $(PREFIX):$(TAG)

clean:
	docker rmi -f $(PREFIX):$(TAG) || true
	rm -f loadbalancer

.PHONY: container push
