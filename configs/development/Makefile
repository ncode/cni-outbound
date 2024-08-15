.PHONY: build docker-build down up

all: build docker-build down up

build:
	GOOS=linux go build -o outbound -ldflags="-s -w" ../../

docker-build:
	cp -f ../my-network.conflist .
	docker build -t ncode/cni-output:dev .

up:
	docker compose up

down:
	docker compose down
