build:
	go build -a --ldflags '-extldflags "-static"' -o server server/server.go
	go build -a --ldflags '-extldflags "-static"' -o client client/client.go
