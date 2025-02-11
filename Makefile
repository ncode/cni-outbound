# Extract the Go version directly from go.mod (e.g., "1.23")
GO_VERSION = $(shell awk '/^toolchain / {sub(/go/,"",$$2) ; print $$2}' go.mod)

DOCKER_IMAGE = cni-outbound-test

.PHONY: test
test:
	# Build the Docker image, passing GO_VERSION to the Docker build
	docker build \
		--build-arg GO_VERSION=$(GO_VERSION) \
		-f Dockerfile.test \
		-t $(DOCKER_IMAGE) .
	# Run the container, which by default executes "go test -v ./..."
	docker run --rm $(DOCKER_IMAGE)

.PHONY: clean
clean:
	docker rmi $(DOCKER_IMAGE) || true
