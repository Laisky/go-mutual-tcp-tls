FROM ppcelery/gobase:1.13.0-alpine3.10 AS gobuild

ENV GO111MODULE=on
WORKDIR /app
COPY go.mod .
COPY go.sum .
RUN go mod download

# static build
ADD . .
RUN go build -a --ldflags '-extldflags "-static"' client/client.go


# copy executable file and certs to a pure container
FROM alpine:3.10
COPY --from=gobuild /app/ca.crt .
COPY --from=gobuild /app/client.crt .
COPY --from=gobuild /app/client.key.text .
COPY --from=gobuild /app/client/command-line-arguments app

ENTRYPOINT  ["./app"]
