# syntax = docker/dockerfile:1.2

FROM golang:1.18

WORKDIR /usr/src/app
COPY . .
RUN go mod tidy
RUN go build -tags netgo -ldflags '-s -w' -o api ./...
CMD [ "./api/api", "-wallet=/etc/secrets/wallet.json", "-password=password"]