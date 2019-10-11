# go-mutual-tcp-tls

tcp with mutual tls


[中文介绍](https://blog.laisky.com/p/go-mutual-tls-tcp/)

## Run

```sh
# start server
go run server/server.go

# start client
go run client/client.go
```

## Prepare certs

* <https://medium.com/rahasak/tls-mutual-authentication-with-golang-and-nginx-937f0da22a0e>

Use same CA for client and server.

![tls](./mutual-tls.jpg)

```sh
# 1. generate CA
openssl genrsa -des3 -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt

# 2. generate server key & csr & crt
openssl genrsa -des3 -out server.key 1024
openssl rsa -in server.key -out server.key.text  # decrypt server key
# CN(common name) shoule be: localhost
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt

# 3. generate client key & csr & crt
openssl genrsa -des3 -out client.key 1024
openssl rsa -in client.key -out client.key.text  # decrypt client key
openssl req -new -key client.key -out client.csr
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out client.crt
```

## docker

build:

```sh
docker build . -f server.Dockerfile -t ppcelery/go-mutual-tcp-tls:server-b2a863f
docker build . -f client.Dockerfile -t ppcelery/go-mutual-tcp-tls:client-b2a863f

docker-compose -f docker-compose.yml up -d --remove-orphans --force-recreate
```

Metrics:

* Prometheus metrics: <http://localhost:8080/metrics>
* pprof: <http://localhost:8080/pprof>

```sh
docker logs go-mutual-tcp-tls_server_1 -f | grep heart

{"level":"info","ts":"2019-10-11T08:24:12.555Z","caller":"server/server.go:87","message":"heartbeat","conn":0}
{"level":"info","ts":"2019-10-11T08:24:17.557Z","caller":"server/server.go:87","message":"heartbeat","conn":12349}
{"level":"info","ts":"2019-10-11T08:24:22.566Z","caller":"server/server.go:87","message":"heartbeat","conn":18572}
{"level":"info","ts":"2019-10-11T08:24:27.566Z","caller":"server/server.go:87","message":"heartbeat","conn":18572}
{"level":"info","ts":"2019-10-11T08:24:32.568Z","caller":"server/server.go:87","message":"heartbeat","conn":27273}
{"level":"info","ts":"2019-10-11T08:24:37.570Z","caller":"server/server.go:87","message":"heartbeat","conn":55291}
{"level":"info","ts":"2019-10-11T08:24:42.570Z","caller":"server/server.go:87","message":"heartbeat","conn":70846}
{"level":"info","ts":"2019-10-11T08:24:47.572Z","caller":"server/server.go:87","message":"heartbeat","conn":76812}
{"level":"info","ts":"2019-10-11T08:24:52.573Z","caller":"server/server.go:87","message":"heartbeat","conn":85090}
{"level":"info","ts":"2019-10-11T08:24:57.575Z","caller":"server/server.go:87","message":"heartbeat","conn":85090}
{"level":"info","ts":"2019-10-11T08:25:02.612Z","caller":"server/server.go:87","message":"heartbeat","conn":85157}
{"level":"info","ts":"2019-10-11T08:25:07.612Z","caller":"server/server.go:87","message":"heartbeat","conn":90541}
{"level":"info","ts":"2019-10-11T08:25:12.688Z","caller":"server/server.go:87","message":"heartbeat","conn":90541}
{"level":"info","ts":"2019-10-11T08:25:17.692Z","caller":"server/server.go:87","message":"heartbeat","conn":90541}
{"level":"info","ts":"2019-10-11T08:25:22.847Z","caller":"server/server.go:87","message":"heartbeat","conn":90541}
{"level":"info","ts":"2019-10-11T08:25:27.851Z","caller":"server/server.go:87","message":"heartbeat","conn":90541}
{"level":"info","ts":"2019-10-11T08:25:32.852Z","caller":"server/server.go:87","message":"heartbeat","conn":90541}
{"level":"info","ts":"2019-10-11T08:25:38.022Z","caller":"server/server.go:87","message":"heartbeat","conn":95346}
{"level":"info","ts":"2019-10-11T08:25:43.026Z","caller":"server/server.go:87","message":"heartbeat","conn":95346}
{"level":"info","ts":"2019-10-11T08:25:48.030Z","caller":"server/server.go:87","message":"heartbeat","conn":95346}
{"level":"info","ts":"2019-10-11T08:25:53.031Z","caller":"server/server.go:87","message":"heartbeat","conn":95346}
{"level":"info","ts":"2019-10-11T08:25:58.032Z","caller":"server/server.go:87","message":"heartbeat","conn":95346}
```
