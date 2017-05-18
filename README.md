# labeled-loadbalancer

Load balance on hyper.sh cloud.

HTTP example:

```sh
hyper run -itd -p 80 nginx
hyper run -itd -p 80 httpd
hyper run -e HYPER_ACCESS_KEY=ak -e HYPER_SECRET_KEY=sk -itd -p 80:80 hyperhq/labeled-loadbalancer dumb-init /service-loadbalancer --server=tcp://us-west-1.hyper.sh:443 --service-port=80 --container-port=80 --algorithm=roundrobin --health-check-fall=3 --health-check-interval=5 --health-check-rise=2 --protocol=http --server-version=1.23 --session-affinity=true  --labels='app=nginx'
```

HTTPS Termination:

```sh
hyper run -e HYPER_ACCESS_KEY=ak -e HYPER_SECRET_KEY=sk -itd -p 443 hyperhq/labeled-loadbalancer dumb-init /service-loadbalancer --server=tcp://us-west-1.hyper.sh:443 --service-port=443 --container-port=80 --algorithm=roundrobin --health-check-fall=3 --health-check-interval=5 --health-check-rise=2 --protocol=httpsTerm --server-version=1.23 --session-affinity=true --ssl-cert="xxxx" --labels='app=nginx'
```

## Features

- Run haproxy as a container to do load babalancing
- Select backend containers by labels
- Custum haproxy settings
- Support http/https/tcp/httpsTerm protocol
- Custum enabling haproxy stats
- Use Hyper.sh events websocket API for container status update

