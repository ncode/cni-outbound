.PHONY: build docker-build down up

all: build docker-build down up

build:
	GOOS=linux GOARCH=arm64 go build -o outbound -ldflags="-s -w" ../../

docker-build:
	docker build -t ncode/cni-output:dev .

up:
	docker compose up

down:
	docker compose down
