.PHONY: build docker-build down up

all: build docker-build down up

build:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" ../../plugins/output

docker-build:
	docker build -t ncode/cni-output:dev .

up:
	docker compose up

down:
	docker compose down
